// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	stdcontext "context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// These tests pin down the behavior of Context.Run and Subcontext.Run on the
// paths that other tests do not reach: guard order, the hand-off of the input
// pinner to the WAF, and the checks made under the evaluation lock.
//
// Rule and input used by every test: the Arachni test rule (see
// newArachniTestRule) listens on the address "my.input" and matches the value
// "Arachni". A run with runPathsMatchingData therefore creates an event when it
// is evaluated by the WAF.

const (
	runPathsWaitTimeout = 5 * time.Second
	runPathsTimerKey    = timer.Key("k")
)

// runPathsMatchingData returns input that matches the rule of the fixture.
func runPathsMatchingData() map[string]any {
	return map[string]any{"my.input": "Arachni"}
}

// runPathsTarget gives the tests uniform access to a Context or a Subcontext.
type runPathsTarget struct {
	name string
	run  Runner
	// evalMu is the lock that Run takes before the checks that are made under
	// the evaluation lock.
	evalMu *sync.Mutex
	// hint is the closed hint of the runner itself.
	hint *atomic.Bool
	// parentHint is the closed hint of the parent Context. It is nil for a
	// Context.
	parentHint *atomic.Bool
	timer      timer.NodeTimer
	// pinnerState reads, under pinnersMu, how many pinners the runner keeps
	// and if they were released by Close.
	pinnerState func() (kept int, released bool)
	close       func()
}

// runPathsFixture is a Context with one Subcontext. Cleanup closes both.
type runPathsFixture struct {
	ctx *Context
	sub *Subcontext
}

// newRunPathsFixture creates the fixture. The default timer has an unlimited
// budget. The timer options of the Context can be replaced with opts.
func newRunPathsFixture(t *testing.T, opts ...timer.Option) *runPathsFixture {
	t.Helper()

	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(waf.Close)

	if len(opts) == 0 {
		opts = []timer.Option{timer.WithUnlimitedBudget(), timer.WithComponents(runPathsTimerKey)}
	}
	ctx, err := waf.NewContext(stdcontext.Background(), opts...)
	require.NoError(t, err)
	sub, err := ctx.NewSubcontext(stdcontext.Background())
	require.NoError(t, err)

	t.Cleanup(func() { closeWithin(t, func() { sub.Close(); ctx.Close() }) })
	return &runPathsFixture{ctx: ctx, sub: sub}
}

// targets returns the Context and the Subcontext of the fixture.
func (fx *runPathsFixture) targets() []runPathsTarget {
	ctx, sub := fx.ctx, fx.sub
	return []runPathsTarget{
		{
			name:   "Context",
			run:    ctx,
			evalMu: &ctx.mu,
			hint:   &ctx.closedHint,
			timer:  ctx.Timer,
			pinnerState: func() (int, bool) {
				ctx.pinnersMu.Lock()
				defer ctx.pinnersMu.Unlock()
				return len(ctx.pinners), ctx.pinnersReleased
			},
			close: ctx.Close,
		},
		{
			name:       "Subcontext",
			run:        sub,
			evalMu:     &sub.mu,
			hint:       &sub.closedHint,
			parentHint: &ctx.closedHint,
			timer:      sub.Timer,
			pinnerState: func() (int, bool) {
				sub.pinnersMu.Lock()
				defer sub.pinnersMu.Unlock()
				return len(sub.pinners), sub.pinnersReleased
			},
			close: sub.Close,
		},
	}
}

// pinnersKept returns how many input pinners the target keeps.
func (tg runPathsTarget) pinnersKept() int {
	kept, _ := tg.pinnerState()
	return kept
}

// closeWithin calls closeFn and fails the test if it does not return in time.
// A Close that waits for an evaluation that never ends would otherwise hang
// the whole test binary.
func closeWithin(t *testing.T, closeFn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		closeFn()
	}()
	select {
	case <-done:
	case <-time.After(runPathsWaitTimeout):
		t.Fatal("Close did not return in time")
	}
}

// forceClosedHint sets hint to true. It returns a restore function that sets
// hint back to false the first time that it is called and does nothing after
// that. The restore function is also registered with t.Cleanup, so the hint is
// restored before the fixture closes, even if an assertion fails. A second
// write would reopen a runner that was closed in the meantime, and the
// fixture would then release the reference to the Handle a second time.
func forceClosedHint(t *testing.T, hint *atomic.Bool) (restore func()) {
	t.Helper()

	var once sync.Once
	restore = func() { once.Do(func() { hint.Store(false) }) }
	hint.Store(true)
	t.Cleanup(restore)
	return restore
}

// errGateCtx blocks its first Err call until the test releases it.
type errGateCtx struct {
	stdcontext.Context
	calls   atomic.Int32
	reached chan struct{} // closed by the first Err call
	release chan struct{} // closed by the test
}

func newErrGateCtx() (*errGateCtx, stdcontext.CancelFunc) {
	inner, cancel := stdcontext.WithCancel(stdcontext.Background())
	return &errGateCtx{
		Context: inner,
		reached: make(chan struct{}),
		release: make(chan struct{}),
	}, cancel
}

func (g *errGateCtx) Err() error {
	if g.calls.Add(1) != 1 {
		return g.Context.Err()
	}
	err := g.Context.Err() // nil: the test changes the state only after reached
	close(g.reached)
	<-g.release
	return err
}

// assertRunsKeepPinnersUntilClose checks that every successful run hands its
// input pinner to the runner and that Close releases all of them.
func assertRunsKeepPinnersUntilClose(t *testing.T, tg runPathsTarget) {
	t.Helper()

	for i := range 2 {
		res, err := tg.run.Run(stdcontext.Background(), RunAddressData{Data: runPathsMatchingData()})
		require.NoError(t, err)
		// The WAF reports a rule only once per context: only the first run has events.
		require.Equal(t, i == 0, res.HasEvents(), "the fixture input must match the rule once")
	}
	assert.Equal(t, 2, tg.pinnersKept(), "each run must hand its pinner to the runner")

	closeWithin(t, tg.close)
	kept, released := tg.pinnerState()
	assert.Zero(t, kept, "Close must release the pinners")
	assert.True(t, released, "Close must mark the pinners as released")
}

func TestContextRunKeepsPinnerUntilClose(t *testing.T) {
	assertRunsKeepPinnersUntilClose(t, newRunPathsFixture(t).targets()[0])
}

func TestSubcontextRunKeepsPinnerUntilClose(t *testing.T) {
	assertRunsKeepPinnersUntilClose(t, newRunPathsFixture(t).targets()[1])
}

// TestSubcontextRunParentClosedBeforeEval checks that the rejection of a run
// because the parent Context is closed does not leave an outstanding
// evaluation: Close would wait for it forever.
func TestSubcontextRunParentClosedBeforeEval(t *testing.T) {
	fx := newRunPathsFixture(t)
	restore := forceClosedHint(t, &fx.ctx.closedHint)

	res, err := fx.sub.Run(stdcontext.Background(), RunAddressData{Data: runPathsMatchingData()})
	require.ErrorIs(t, err, waferrors.ErrContextClosed)
	assert.Zero(t, fx.targets()[1].pinnersKept())
	assert.NotEmpty(t, res.TimerStats)

	// The restore must happen before Close, and only once: see forceClosedHint.
	restore()
	closeWithin(t, func() { fx.sub.Close(); fx.ctx.Close() })
}

// TestRunChecksUnderEvalLock checks the closed hint and ctx.Err checks that
// Run makes after it took the evaluation lock. The test holds that lock. It
// changes the state only after Run passed all the earlier checks, so nothing
// but the checks under the lock can return the error.
func TestRunChecksUnderEvalLock(t *testing.T) {
	cases := []struct {
		name   string
		target int
		closed bool // true: set the closed hint, false: cancel the context
		want   error
	}{
		{"Context/cancel", 0, false, stdcontext.Canceled},
		{"Context/closed", 0, true, waferrors.ErrContextClosed},
		{"Subcontext/cancel", 1, false, stdcontext.Canceled},
		{"Subcontext/closed", 1, true, waferrors.ErrContextClosed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tg := newRunPathsFixture(t).targets()[tc.target]
			res, err := runWithStateChangedUnderLock(t, tg, tc.closed)
			assert.ErrorIs(t, err, tc.want)
			assert.False(t, res.HasEvents(), "the WAF must not evaluate the input")
			assert.Zero(t, tg.pinnersKept(), "the input pinner must not be kept")
		})
	}
}

// runWithStateChangedUnderLock runs the target while the test holds its
// evaluation lock. Once Run is inside its first ctx.Err call, the test either
// cancels the context or sets the closed hint of the target, and then lets Run
// continue.
func runWithStateChangedUnderLock(t *testing.T, tg runPathsTarget, closed bool) (Result, error) {
	t.Helper()

	gate, cancel := newErrGateCtx()
	tg.evalMu.Lock()
	var releaseOnce, unlockOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	unlock := func() { unlockOnce.Do(tg.evalMu.Unlock) }
	// Registered before anything can fail, so a timeout does not leave Run
	// blocked on the gate or on the lock. This runs before the fixture Close.
	t.Cleanup(func() { cancel(); release(); unlock() })

	type outcome struct {
		res Result
		err error
	}
	outcomes := make(chan outcome, 1)
	go func() {
		res, err := tg.run.Run(gate, RunAddressData{Data: runPathsMatchingData()})
		outcomes <- outcome{res, err}
	}()

	select {
	case <-gate.reached:
	case <-time.After(runPathsWaitTimeout):
		t.Fatal("Run did not reach its first ctx.Err call")
	}

	if closed {
		forceClosedHint(t, tg.hint)
	} else {
		cancel()
	}
	release()
	unlock()

	select {
	case o := <-outcomes:
		return o.res, o.err
	case <-time.After(runPathsWaitTimeout):
		t.Fatal("Run did not return")
		return Result{}, nil
	}
}

// TestRunGuardOrder checks the order of the guards at the start of Run: nil
// context, empty data, closed, exhausted timer, canceled context.
func TestRunGuardOrder(t *testing.T) {
	cases := []struct {
		name         string
		nilCtx       bool
		empty        bool
		canceled     bool
		closed       bool
		parentClosed bool
		exhausted    bool
		want         error
		wantMsg      string
	}{
		{name: "nil context comes first", nilCtx: true, empty: true, closed: true, want: waferrors.ErrNilContext, wantMsg: ".Run: "},
		{name: "empty comes before ctx.Err", empty: true, canceled: true},
		{name: "empty and closed", empty: true, canceled: true, closed: true, want: waferrors.ErrContextClosed},
		{name: "empty and parent closed", empty: true, parentClosed: true, want: waferrors.ErrContextClosed},
		{name: "closed comes before timer", closed: true, exhausted: true, canceled: true, want: waferrors.ErrContextClosed},
		{name: "timer comes before ctx.Err", exhausted: true, canceled: true, want: waferrors.ErrTimeout},
	}

	for index, name := range []string{"Context", "Subcontext"} {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				fx := newRunPathsFixture(t, timer.WithBudget(time.Millisecond), timer.WithComponents(runPathsTimerKey))
				tg := fx.targets()[index]
				if tc.parentClosed && tg.parentHint == nil {
					t.Skip("a Context has no parent")
				}
				ctx := stdcontext.Background()
				if tc.nilCtx {
					ctx = nil //nolint:staticcheck // SA1012: the nil check is what this case is about
				}
				if tc.canceled {
					var cancel stdcontext.CancelFunc
					ctx, cancel = stdcontext.WithCancel(ctx)
					cancel()
				}
				if tc.exhausted {
					tg.timer.AddTime(runPathsTimerKey, 2*time.Millisecond)
				}
				if tc.closed {
					forceClosedHint(t, tg.hint)
				}
				if tc.parentClosed {
					forceClosedHint(t, tg.parentHint)
				}

				data := runPathsMatchingData()
				if tc.empty {
					data = nil
				}
				res, err := tg.run.Run(ctx, RunAddressData{Data: data})
				assert.ErrorIs(t, err, tc.want) // a nil want checks that err is nil
				if tc.wantMsg != "" {
					assert.ErrorContains(t, err, tg.name+tc.wantMsg)
				}
				assert.False(t, res.HasEvents())
			})
		}
	}
}

// TestRunUnknownTimerKeyKeepsNoPinner checks that a run fails without keeping
// an input pinner when its timer key is not a component of the parent timer.
func TestRunUnknownTimerKeyKeepsNoPinner(t *testing.T) {
	for _, tg := range newRunPathsFixture(t).targets() {
		t.Run(tg.name, func(t *testing.T) {
			_, err := tg.run.Run(stdcontext.Background(), RunAddressData{
				Data:     runPathsMatchingData(),
				TimerKey: "no-such-key",
			})
			require.ErrorContains(t, err, "component no-such-key not found")
			assert.Zero(t, tg.pinnersKept())
		})
	}
}
