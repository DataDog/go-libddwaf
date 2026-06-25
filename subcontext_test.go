// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.28 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/timer"
)

func TestSiblingSubcontextParallelismTarget(t *testing.T) {
	require.True(t, meetsSiblingSubcontextSpeedupTarget(0.8))
	require.True(t, meetsSiblingSubcontextSpeedupTarget(1.2))
	require.True(t, meetsSiblingSubcontextSpeedupTarget(2.0))
	require.False(t, meetsSiblingSubcontextSpeedupTarget(0.79))
	require.False(t, meetsSiblingSubcontextSpeedupTarget(0.5))
}

// meetsSiblingSubcontextSpeedupTarget reports whether the measured
// serialized/parallel runtime ratio is acceptable. The floor is deliberately
// permissive: shared/throttled CI runners (notably older 3-core macOS hosts)
// routinely show no parallel speedup for these microsecond-scale work units and
// were observed producing ratios as low as ~0.75x. The 0.8x floor keeps the
// test stable on such hardware while still catching catastrophic serialization
// regressions (e.g. a global lock making parallel several times slower).
func meetsSiblingSubcontextSpeedupTarget(ratio float64) bool {
	return ratio >= 0.8
}

func TestSubcontextTruncations(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { subCtx.Close() })

	require.True(t, subCtx.Truncations().IsEmpty())

	oversized := strings.Repeat("a", int(bindings.MaxStringLength)*2)
	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": oversized}})

	tr := subCtx.Truncations()
	require.NotEmpty(t, tr.StringTooLong)
	require.Equal(t, len(oversized), tr.StringTooLong[0])
}

func TestSubcontextCloseRollsUpIntoParent(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents("waf"))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)

	oversized := strings.Repeat("a", int(bindings.MaxStringLength)*2)
	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": oversized}, TimerKey: "waf"})
	subCtx.Close()

	require.Greater(t, ctx.Timer.Stats()["waf"], time.Duration(0))
	require.False(t, ctx.Truncations().IsEmpty())
}

func TestContextCloseCascadeRollsUpSubcontext(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents("waf"))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)
	// subCtx intentionally NOT closed before ctx — Context.Close cascade path under test.

	oversized := strings.Repeat("a", int(bindings.MaxStringLength)*2)
	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": oversized}, TimerKey: "waf"})

	ctx.Close()

	// Context.Timer and truncations remain readable after Close (pure Go fields).
	require.Greater(t, ctx.Timer.Stats()["waf"], time.Duration(0))
	require.False(t, ctx.Truncations().IsEmpty())
}

func TestSubcontextRollupPerScopeAttribution(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents("waf", "rasp"))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)

	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": "benign"}, TimerKey: "waf"})
	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": "benign"}, TimerKey: "rasp"})
	subCtx.Close()

	require.Greater(t, ctx.Timer.Stats()["waf"], time.Duration(0))
	require.Greater(t, ctx.Timer.Stats()["rasp"], time.Duration(0))
}

func TestSubcontextEmptyTimerKeyDoesNotRollUp(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents("waf"))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)

	// Empty TimerKey uses a standalone tree timer not attached to s.Timer, so
	// s.Timer["waf"] stays zero and nothing rolls up into the parent.
	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": "benign"}})
	subCtx.Close()

	require.Equal(t, time.Duration(0), ctx.Timer.Stats()["waf"])
}

func TestSubcontextRollupNoComponentParentNoOp(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)

	_, _ = subCtx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": "benign"}, TimerKey: DurationTimeKey})
	require.Greater(t, subCtx.Timer.Stats()[DurationTimeKey], time.Duration(0))
	subCtx.Close()

	require.Empty(t, ctx.Timer.Stats())
}

func TestSiblingSubcontextParallelismSpeedup(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)

	n := min(runtime.NumCPU(), 8)
	if n < 2 {
		t.Skip("speedup test requires at least 2 CPUs")
	}
	if raceDetectorEnabled {
		t.Skip("speedup test unreliable under -race due to instrumentation overhead")
	}

	subCtxs := make([]*Subcontext, n)
	for i := range n {
		subCtxs[i], err = ctx.NewSubcontext(context.Background())
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		for _, s := range subCtxs {
			s.Close()
		}
		ctx.Close()
	})

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string][]string{
			"user-agent":      {"Arachni/test", "curl/8.0"},
			"accept":          {"application/json", "text/html", "*/*"},
			"accept-encoding": {"gzip", "deflate", "br"},
			"x-forwarded-for": {"1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"},
			"x-custom":        {"a", "b", "c", "d", "e", "f", "g", "h"},
		},
	}}

	const (
		warmupIterations = 100
		iterations       = 2000
		attempts         = 5
	)

	for _, subCtx := range subCtxs {
		for range warmupIterations {
			_, _ = subCtx.Run(context.Background(), data)
		}
	}

	bestRatio := 0.0
	var bestSerializedTime, bestParallelTime time.Duration

	for attempt := range attempts {
		serializedStart := time.Now()
		for _, subCtx := range subCtxs {
			for range iterations {
				_, _ = subCtx.Run(context.Background(), data)
			}
		}
		serializedTime := time.Since(serializedStart)

		var wg sync.WaitGroup
		parallelStart := time.Now()
		for _, subCtx := range subCtxs {
			wg.Add(1)
			go func(s *Subcontext) {
				defer wg.Done()
				for range iterations {
					_, _ = s.Run(context.Background(), data)
				}
			}(subCtx)
		}
		wg.Wait()
		parallelTime := time.Since(parallelStart)

		ratio := float64(serializedTime) / float64(parallelTime)
		t.Logf("attempt=%d/%d n=%d iterations=%d serialized=%v parallel=%v ratio=%.2fx", attempt+1, attempts, n, iterations, serializedTime, parallelTime, ratio)

		if ratio > bestRatio {
			bestRatio = ratio
			bestSerializedTime = serializedTime
			bestParallelTime = parallelTime
		}

		if meetsSiblingSubcontextSpeedupTarget(ratio) {
			return
		}
	}

	require.True(t, meetsSiblingSubcontextSpeedupTarget(bestRatio),
		"expected ≥0.8x parallel/serial ratio in at least one of %d attempts (best ratio=%.2f): serialized=%v parallel=%v", attempts, bestRatio, bestSerializedTime, bestParallelTime)
}
