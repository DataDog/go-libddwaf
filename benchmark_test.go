// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	stdcontext "context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/stretchr/testify/require"
)

const benchWAFTimerKey timer.Key = "waf"

func benchRecommendedHandle(b *testing.B) *Handle {
	b.Helper()
	builder, err := NewBuilder()
	require.NoError(b, err)
	b.Cleanup(func() { builder.Close() })

	_, err = builder.AddDefaultRecommendedRuleset()
	require.NoError(b, err)

	handle, err := builder.Build()
	require.NoError(b, err)
	b.Cleanup(func() { handle.Close() })
	return handle
}

func benchSmallRuleHandle(b *testing.B) *Handle {
	b.Helper()
	builder, err := NewBuilder()
	require.NoError(b, err)
	b.Cleanup(func() { builder.Close() })

	rule := newArachniTestRule(b, []ruleInput{
		{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}},
	}, nil)
	_, err = builder.AddOrUpdateConfig("/default", rule)
	require.NoError(b, err)

	handle, err := builder.Build()
	require.NoError(b, err)
	b.Cleanup(func() { handle.Close() })
	return handle
}

func benchBenignRequest() map[string]any {
	return map[string]any{
		"http.client_ip":         "192.168.1.1",
		"server.request.method":  "GET",
		"server.request.uri.raw": "/api/v1/users?page=1&limit=20",
		"server.request.headers.no_cookies": map[string][]string{
			"host":            {"example.com"},
			"content-length":  {"0"},
			"accept":          {"application/json"},
			"user-agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
			"accept-encoding": {"gzip, deflate"},
			"connection":      {"keep-alive"},
		},
		"server.request.cookies": map[string][]string{
			"session_id": {"abc123def456"},
		},
		"server.request.query": map[string][]string{
			"page":  {"1"},
			"limit": {"20"},
		},
		"server.request.path_params": map[string]string{
			"version": "v1",
		},
	}
}

func benchAttackRequest() map[string]any {
	return map[string]any{
		"http.client_ip":         "1.2.3.4",
		"server.request.method":  "POST",
		"server.request.uri.raw": "/api/v1/users?id=' OR 1=1--",
		"server.request.headers.no_cookies": map[string][]string{
			"host":            {"example.com"},
			"content-length":  {"42"},
			"accept":          {"application/json"},
			"user-agent":      {"Arachni/v1.6.1.1"},
			"accept-encoding": {"gzip, deflate"},
			"connection":      {"keep-alive"},
		},
		"server.request.cookies": map[string][]string{
			"session_id": {"abc123def456"},
		},
		"server.request.query": map[string][]string{
			"id": {"' OR 1=1--"},
		},
		"server.request.path_params": map[string]string{
			"version": "v1",
		},
	}
}

func benchResponseData() map[string]any {
	return map[string]any{
		"server.response.headers.no_cookies": map[string][]string{
			"content-type":   {"application/json"},
			"content-length": {"256"},
			"connection":     {"keep-alive"},
		},
		"server.response.status": 200,
	}
}

func benchMinimalRequest() map[string]any {
	return map[string]any{
		"server.request.uri.raw": "/",
	}
}

func benchHeavyRequest() map[string]any {
	headers := make(map[string][]string, 50)
	for i := range 50 {
		headers[fmt.Sprintf("x-custom-%d", i)] = []string{strings.Repeat("value", 20)}
	}
	headers["user-agent"] = []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
	headers["host"] = []string{"example.com"}

	query := make(map[string][]string, 30)
	for i := range 30 {
		query[fmt.Sprintf("param%d", i)] = []string{strings.Repeat("x", 100)}
	}

	cookies := make(map[string][]string, 20)
	for i := range 20 {
		cookies[fmt.Sprintf("cookie%d", i)] = []string{strings.Repeat("v", 50)}
	}

	pathParams := make(map[string]string, 10)
	for i := range 10 {
		pathParams[fmt.Sprintf("param%d", i)] = strings.Repeat("p", 50)
	}

	return map[string]any{
		"http.client_ip":                    "10.0.0.1",
		"server.request.method":             "POST",
		"server.request.uri.raw":            "/api/v2/data?" + strings.Repeat("key=value&", 50),
		"server.request.headers.no_cookies": headers,
		"server.request.cookies":            cookies,
		"server.request.query":              query,
		"server.request.path_params":        pathParams,
		"server.request.body":               strings.Repeat("body content ", 100),
	}
}

// BenchmarkWAF benchmarks WAF operations across multiple dimensions.
// The RequestResponse sub-benchmark is migrated from dd-trace-go/internal/appsec.BenchmarkSampleWAFContext
// and adapted to the v5 API.
func BenchmarkWAF(b *testing.B) {

	b.Run("RequestResponse", func(b *testing.B) {
		handle := benchRecommendedHandle(b)
		requestData := benchBenignRequest()
		responseData := benchResponseData()

		b.ReportAllocs()
		for b.Loop() {
			ctx, err := handle.NewContext(stdcontext.Background(), timer.WithBudget(time.Second))
			if err != nil {
				b.Fatal(err)
			}

			_, err = ctx.Run(stdcontext.Background(), RunAddressData{Data: requestData})
			if err != nil {
				b.Fatalf("request run: %v", err)
			}

			_, err = ctx.Run(stdcontext.Background(), RunAddressData{Data: responseData})
			if err != nil {
				b.Fatalf("response run: %v", err)
			}

			ctx.Close()
		}
	})

	b.Run("Run", func(b *testing.B) {
		type rulesetCase struct {
			name   string
			handle func(b *testing.B) *Handle
		}
		type attackCase struct {
			name string
			data map[string]any
		}

		rulesets := []rulesetCase{
			{"SmallRuleset", benchSmallRuleHandle},
			{"RecommendedRuleset", benchRecommendedHandle},
		}
		attacks := []attackCase{
			{"NoAttack", benchBenignRequest()},
			{"Attack", benchAttackRequest()},
		}

		for _, rs := range rulesets {
			b.Run(rs.name, func(b *testing.B) {
				handle := rs.handle(b)
				for _, atk := range attacks {
					b.Run(atk.name, func(b *testing.B) {
						// Sanity-check that attack payloads actually trigger events.
						if atk.name == "Attack" {
							verifyCtx, err := handle.NewContext(stdcontext.Background(), timer.WithUnlimitedBudget())
							require.NoError(b, err)
							res, err := verifyCtx.Run(stdcontext.Background(), RunAddressData{Data: atk.data})
							require.NoError(b, err)
							require.True(b, res.HasEvents(), "attack payload should trigger WAF events")
							verifyCtx.Close()
						}

						b.ReportAllocs()
						for b.Loop() {
							ctx, err := handle.NewContext(stdcontext.Background(),
								timer.WithBudget(time.Second),
								timer.WithComponents(benchWAFTimerKey))
							if err != nil {
								b.Fatal(err)
							}
							_, err = ctx.Run(stdcontext.Background(), RunAddressData{
								Data:     atk.data,
								TimerKey: benchWAFTimerKey,
							})
							if err != nil {
								b.Fatal(err)
							}
							ctx.Close()
						}
					})
				}
			})
		}
	})

	b.Run("ContextLifecycle", func(b *testing.B) {
		handle := benchRecommendedHandle(b)

		b.ReportAllocs()
		for b.Loop() {
			ctx, err := handle.NewContext(stdcontext.Background(), timer.WithBudget(time.Second))
			if err != nil {
				b.Fatal(err)
			}
			ctx.Close()
		}
	})

	b.Run("DataComplexity", func(b *testing.B) {
		handle := benchRecommendedHandle(b)
		cases := []struct {
			name string
			data map[string]any
		}{
			{"Minimal", benchMinimalRequest()},
			{"Realistic", benchBenignRequest()},
			{"Heavy", benchHeavyRequest()},
		}

		for _, tc := range cases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					ctx, err := handle.NewContext(stdcontext.Background(),
						timer.WithBudget(time.Second),
						timer.WithComponents(benchWAFTimerKey))
					if err != nil {
						b.Fatal(err)
					}
					_, err = ctx.Run(stdcontext.Background(), RunAddressData{
						Data:     tc.data,
						TimerKey: benchWAFTimerKey,
					})
					if err != nil {
						b.Fatal(err)
					}
					ctx.Close()
				}
			})
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		handle := benchRecommendedHandle(b)
		data := benchBenignRequest()

		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ctx, err := handle.NewContext(stdcontext.Background(),
					timer.WithBudget(time.Second),
					timer.WithComponents(benchWAFTimerKey))
				if err != nil {
					b.Fatal(err)
				}
				_, err = ctx.Run(stdcontext.Background(), RunAddressData{
					Data:     data,
					TimerKey: benchWAFTimerKey,
				})
				if err != nil {
					b.Fatal(err)
				}
				ctx.Close()
			}
		})
	})

	b.Run("Subcontext", func(b *testing.B) {
		handle := benchRecommendedHandle(b)
		persistentData := benchBenignRequest()
		ephemeralData := map[string]any{
			"server.request.body": "some ephemeral body content to evaluate",
		}

		wafCtx, err := handle.NewContext(stdcontext.Background(), timer.WithUnlimitedBudget())
		require.NoError(b, err)
		b.Cleanup(func() { wafCtx.Close() })

		_, err = wafCtx.Run(stdcontext.Background(), RunAddressData{Data: persistentData})
		require.NoError(b, err)

		b.ReportAllocs()
		for b.Loop() {
			subCtx, err := wafCtx.NewSubcontext(stdcontext.Background())
			if err != nil {
				b.Fatal(err)
			}
			_, err = subCtx.Run(stdcontext.Background(), RunAddressData{Data: ephemeralData})
			if err != nil {
				b.Fatal(err)
			}
			subCtx.Close()
		}
	})
}

// BenchmarkNewContextOnly measures Handle.NewContext in isolation.
// Close is excluded from the timed region via StopTimer/StartTimer.
func BenchmarkNewContextOnly(b *testing.B) {
	handle := benchRecommendedHandle(b)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ctx, err := handle.NewContext(stdcontext.Background(), timer.WithBudget(time.Second))
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		ctx.Close()
		b.StartTimer()
	}
}

// BenchmarkContextCloseOnly measures Context.Close in isolation.
// NewContext is excluded from the timed region.
func BenchmarkContextCloseOnly(b *testing.B) {
	handle := benchRecommendedHandle(b)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		ctx, err := handle.NewContext(stdcontext.Background(), timer.WithBudget(time.Second))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		ctx.Close()
	}
}

// BenchmarkRunOnly measures Context.Run in isolation with the recommended
// ruleset and benign request data. The context is created once and reused
// across iterations to isolate Run's cost from NewContext/Close overhead.
func BenchmarkRunOnly(b *testing.B) {
	handle := benchRecommendedHandle(b)
	data := benchBenignRequest()

	ctx, err := handle.NewContext(stdcontext.Background(),
		timer.WithUnlimitedBudget())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ctx.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err = ctx.Run(stdcontext.Background(), RunAddressData{
			Data: data,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSubcontextRunOnly measures Subcontext.Run in isolation.
// Parent context and subcontext are created once and reused.
func BenchmarkSubcontextRunOnly(b *testing.B) {
	handle := benchRecommendedHandle(b)
	persistentData := benchBenignRequest()
	ephemeralData := map[string]any{
		"server.request.body": "some ephemeral body content to evaluate",
	}

	ctx, err := handle.NewContext(stdcontext.Background(), timer.WithUnlimitedBudget())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ctx.Close() })

	_, err = ctx.Run(stdcontext.Background(), RunAddressData{Data: persistentData})
	if err != nil {
		b.Fatal(err)
	}

	subCtx, err := ctx.NewSubcontext(stdcontext.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { subCtx.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err = subCtx.Run(stdcontext.Background(), RunAddressData{Data: ephemeralData})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkColdStart forces a GC before each iteration to drain sync.Pool.
// This validates that optimizations are robust under GC pressure and measures
// the worst-case allocation path when pools are empty.
func BenchmarkColdStart(b *testing.B) {
	handle := benchRecommendedHandle(b)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runtime.GC()
		ctx, err := handle.NewContext(stdcontext.Background(), timer.WithBudget(time.Second))
		if err != nil {
			b.Fatal(err)
		}
		ctx.Close()
	}
}

// BenchmarkNewContextParallel measures NewContext+Close under parallel
// goroutine pressure. Run with -cpu=1,4,8,16 to assess per-core scaling.
func BenchmarkNewContextParallel(b *testing.B) {
	handle := benchRecommendedHandle(b)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx, err := handle.NewContext(stdcontext.Background(), timer.WithBudget(time.Second))
			if err != nil {
				b.Fatal(err)
			}
			ctx.Close()
		}
	})
}
