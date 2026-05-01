// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/stretchr/testify/require"
)

func TestSiblingSubcontextParallelismTarget(t *testing.T) {
	require.True(t, meetsSiblingSubcontextSpeedupTarget(1.2))
	require.True(t, meetsSiblingSubcontextSpeedupTarget(2.0))
	require.False(t, meetsSiblingSubcontextSpeedupTarget(1.19))
	require.False(t, meetsSiblingSubcontextSpeedupTarget(1.0))
}

func meetsSiblingSubcontextSpeedupTarget(ratio float64) bool {
	return ratio >= 1.2
}

func TestSiblingSubcontextParallelismSpeedup(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)

	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
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
		attempts         = 3
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
		"expected ≥1.2x speedup in at least one of %d attempts (best ratio=%.2f): serialized=%v parallel=%v", attempts, bestRatio, bestSerializedTime, bestParallelTime)
}

func TestNewSubcontext_StackPath_DDTraceGo(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents("waf", "rasp"))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { subCtx.Close() })

	require.ElementsMatch(t,
		[]timer.Key{"waf", "rasp", EncodeTimeKey, DurationTimeKey, DecodeTimeKey},
		subCtx.Timer.ComponentKeys(),
	)
}

func TestNewSubcontext_HeapFallback(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(
		context.Background(),
		timer.WithBudget(timer.UnlimitedBudget),
		timer.WithComponents("waf", "rasp", "appsec", "gateway"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { subCtx.Close() })

	require.ElementsMatch(t,
		[]timer.Key{"waf", "rasp", "appsec", "gateway", EncodeTimeKey, DurationTimeKey, DecodeTimeKey},
		subCtx.Timer.ComponentKeys(),
	)
}
