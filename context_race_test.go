// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"runtime"
	"sync"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContextRunCloseRace_LeaksPinnedPointer is a standalone, self-contained
// proof that go-libddwaf has a concurrent lifecycle race on Context.pinner
// that leaks pinned pointers and eventually blows up in the runtime.Pinner
// finalizer with the exact signature reported in issue #211:
//
//	panic: runtime error: runtime.Pinner: found leaking pinned pointer;
//	       forgot to call Unpin()?
//
// Why this differs from the reproducer in #211. The reproducer in the issue
// is sequential: ctx.Close() followed by ctx.Run(...). dd-trace-go never
// does that — it atomically swaps the Context pointer to nil before calling
// Close, and every Run call loads from that atomic and returns early if the
// load returns nil. The sequential "Run-after-Close" path is therefore not
// reachable through dd-trace-go, and the fix proposed in the issue (a
// "closed" flag on ConcurrentPinner) is only demonstrated against that
// unreachable path.
//
// The race that is reachable through dd-trace-go is concurrent, not
// sequential. Context.Run pins persistent address data into context.pinner
// via encodeOneAddressType *before* it acquires context.mutex and checks
// cContext == 0 (context.go:121 vs context.go:139). Context.Close takes
// context.mutex, then calls context.pinner.Unpin() and zeroes cContext
// (context.go:324-331). If Close runs concurrently with a Run that already
// entered the encoder, the encoder keeps calling Pin() on context.pinner
// after Close's Unpin() has cleared it. Those post-Unpin pins never get
// unpinned — Close only runs once — so they are leaked onto the pinner
// embedded in the Context. When the Context is later collected, the
// runtime.Pinner finalizer sees the leftover entries and panics.
//
// Why this is flaky, not deterministic. Whether any given iteration
// actually lands a Pin call *between* Close's mutex acquisition and the
// Run encoder's completion depends on goroutine scheduling, the size of
// the persistent payload, and GC timing. Some iterations race, some
// don't. Running the test a few times in a row reliably crashes the
// process with the finalizer panic. A race-free implementation would
// pass every time.
//
// How to exercise:
//
//	go test -run TestContextRunCloseRace_LeaksPinnedPointer -count=10 ./...
//
// Under the current v4.9.x code this aborts with the finalizer panic
// well before 10 runs complete. With a fix that serializes Pin against
// Close (e.g., holding context.mutex across encode, or making
// ConcurrentPinner terminal-state-aware *and* routing the encoder's
// Pins through that gate) the test passes every run.
func TestContextRunCloseRace_LeaksPinnedPointer(t *testing.T) {
	waf, _, err := newDefaultHandle(testArachniRule)
	require.NoError(t, err)
	require.NotNil(t, waf)
	defer waf.Close()

	// A persistent payload with several scalar leaves. Every leaf becomes
	// a separate Pin() call on context.pinner during encoding, which widens
	// the window where Close's Unpin() can slot in between two Pin()s.
	persistent := map[string]any{
		"server.request.headers.no_cookies": map[string][]string{
			"user-agent":      {"Arachni/v1", "curl/8.0"},
			"accept":          {"application/json", "text/html", "*/*"},
			"accept-encoding": {"gzip", "deflate", "br"},
			"x-forwarded-for": {"1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"},
			"x-custom":        {"a", "b", "c", "d", "e", "f", "g", "h"},
		},
	}

	// Run many independent contexts to amortize scheduling variance. Each
	// context gets exactly one concurrent Run+Close pair. We do not keep a
	// slice of the contexts — once the WaitGroup returns the only root is
	// the pair of goroutine stacks, which are already done. The contexts
	// become collectable and their pinner finalizers will fire during GC
	// below. If any one of them leaked a Pin past Close.Unpin(), that
	// finalizer panics and takes the test process with it.
	const iterations = 4000
	for i := 0; i < iterations; i++ {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-start
			// Enter the encoder. encodeOneAddressType pins the string and
			// slice backing memory of `persistent` into context.pinner,
			// one Pin() call at a time, without holding context.mutex.
			_, _ = ctx.Run(RunAddressData{Persistent: persistent})
		}()

		go func() {
			defer wg.Done()
			<-start
			// Acquires context.mutex, zeros cContext, and calls
			// context.pinner.Unpin(). If the Run goroutine is mid-encode
			// at this moment, all its Pin() calls that happen after this
			// Unpin() are orphans.
			ctx.Close()
		}()

		close(start)
		wg.Wait()

		// Help the race land: yield between iterations so the scheduler
		// actually interleaves the two goroutines rather than running them
		// back-to-back on the same P. This is cheap and materially
		// improves how often the race window is entered.
		runtime.Gosched()
	}

	// Force the finalizer goroutine to run. If any iteration left pins on
	// a closed context.pinner, the runtime.Pinner finalizer panics here.
	runtime.GC()
	runtime.GC()
	runtime.GC()
}

// TestContextRunAfterCloseReturnsErr is the sequential reproducer from
// issue #211. dd-trace-go never reaches this ordering (it atomic-swaps the
// Context pointer to nil before Close), but this test pins the contract
// anyway: after Close, Run must return ErrContextClosed and must not leak
// pinned pointers onto the now-terminal context.pinner.
func TestContextRunAfterCloseReturnsErr(t *testing.T) {
	waf, _, err := newDefaultHandle(testArachniRule)
	require.NoError(t, err)
	require.NotNil(t, waf)
	defer waf.Close()

	ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, ctx)

	ctx.Close()

	// Encoder runs, hits the terminal pinner, all Pin calls no-op, the
	// mutex-gated cContext == 0 check returns ErrContextClosed.
	_, err = ctx.Run(RunAddressData{
		Persistent: map[string]any{
			"server.request.headers.no_cookies": map[string][]string{
				"user-agent": {"Arachni/v1"},
			},
		},
	})
	assert.ErrorIs(t, err, waferrors.ErrContextClosed)

	// No pins should have survived Close. A regression here would panic
	// inside runtime.runFinalizers.
	ctx = nil
	runtime.GC()
	runtime.GC()
}

// TestContextDoubleCloseSafe covers the defensive cContext != 0 guard in
// Context.Close. Two concurrent Close calls on the same Context must not
// double-destroy the underlying ddwaf_context and must not double-decrement
// the handle refcount. The terminal pinner also makes pinner.Close
// idempotent.
func TestContextDoubleCloseSafe(t *testing.T) {
	waf, _, err := newDefaultHandle(testArachniRule)
	require.NoError(t, err)
	require.NotNil(t, waf)
	defer waf.Close()

	ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, ctx)

	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})

	go func() {
		defer wg.Done()
		<-start
		ctx.Close()
	}()
	go func() {
		defer wg.Done()
		<-start
		ctx.Close()
	}()

	close(start)
	wg.Wait()

	// Sequential third close must also be a no-op.
	ctx.Close()
}
