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
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	const iterations = 200

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
	t.Logf("n=%d iterations=%d serialized=%v parallel=%v ratio=%.2fx", n, iterations, serializedTime, parallelTime, ratio)

	require.LessOrEqual(t, int64(parallelTime), int64(serializedTime)*10/14,
		"expected ≥1.4x speedup (ratio=%.2f): serialized=%v parallel=%v", ratio, serializedTime, parallelTime)
}
