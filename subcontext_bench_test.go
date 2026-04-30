// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/DataDog/go-libddwaf/v5/timer"
)

func BenchmarkSiblingSubcontextParallelism(b *testing.B) {
	waf, _, err := newDefaultHandle(b, newArachniTestRule(b, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ctx.Close() })

	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}

	subCtxs := make([]*Subcontext, n)
	for i := range n {
		subCtxs[i], err = ctx.NewSubcontext(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
	b.Cleanup(func() {
		for _, s := range subCtxs {
			s.Close()
		}
	})

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	var goroutineIdx atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := int(goroutineIdx.Add(1)-1) % n
		subCtx := subCtxs[i]
		for pb.Next() {
			_, _ = subCtx.Run(context.Background(), data)
		}
	})
}

func BenchmarkSiblingSubcontextSerialized(b *testing.B) {
	waf, _, err := newDefaultHandle(b, newArachniTestRule(b, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ctx.Close() })

	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}

	subCtxs := make([]*Subcontext, n)
	for i := range n {
		subCtxs[i], err = ctx.NewSubcontext(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
	b.Cleanup(func() {
		for _, s := range subCtxs {
			s.Close()
		}
	})

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	b.ResetTimer()
	for i := range b.N {
		_, _ = subCtxs[i%n].Run(context.Background(), data)
	}
}

func BenchmarkContextRun(b *testing.B) {
	waf, _, err := newDefaultHandle(b, newArachniTestRule(b, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ctx.Close() })

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	b.ResetTimer()
	for range b.N {
		_, _ = ctx.Run(context.Background(), data)
	}
}

func BenchmarkSubcontextRun(b *testing.B) {
	waf, _, err := newDefaultHandle(b, newArachniTestRule(b, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { subCtx.Close() })

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	b.ResetTimer()
	for range b.N {
		_, _ = subCtx.Run(context.Background(), data)
	}
}
