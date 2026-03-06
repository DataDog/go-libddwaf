// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/stretchr/testify/require"
)

var ctxOpts = []timer.Option{timer.WithBudget(timer.UnlimitedBudget)}

// TestHandleCloseConcurrentWithNewContext exercises the TOCTOU race between
// Handle.Close (which calls ddwaf_destroy on the C handle) and Handle.NewContext
// (which calls ddwaf_context_init with the same C handle). The race window is
// between handle.retain() succeeding at handle.go:54 and the C call at
// handle.go:58 — during which another goroutine can destroy the C handle.
//
// With the race detector enabled (-race), this test should report a data race
// on Handle.cHandle if the bug is present, because cHandle is read (NewContext)
// and written (Close sets it to 0) without synchronization.
//
// Without the race detector, this test may SIGSEGV — which is exactly the
// production crash we're investigating (IR-50594).
func TestHandleCloseConcurrentWithNewContext(t *testing.T) {
	builder, err := NewBuilder("", "")
	require.NoError(t, err)
	defer builder.Close()

	_, err = builder.AddDefaultRecommendedRuleset()
	require.NoError(t, err)

	const iterations = 1000

	for i := 0; i < iterations; i++ {
		handle := builder.Build()
		if handle == nil {
			t.Fatal("builder.Build() returned nil")
		}

		// Create one context first so the handle's refcount is 2 (handle + 1 context).
		// This ensures Handle.Close won't immediately destroy on decrement (goes 2→1),
		// but the context's Close will (goes 1→0). This is the production scenario:
		// RC calls Handle.Close while contexts still exist and are being created.
		ctx, err := handle.NewContext(ctxOpts...)
		if err != nil {
			t.Fatalf("initial NewContext failed: %v", err)
		}

		var wg sync.WaitGroup

		// Goroutine 1: close the handle (simulates Remote Config swap)
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle.Close()
		}()

		// Goroutine 2: try to create new contexts concurrently (simulates request handlers)
		wg.Add(1)
		go func() {
			defer wg.Done()
			newCtx, err := handle.NewContext(ctxOpts...)
			if err == nil && newCtx != nil {
				// Successfully created a context — close it
				newCtx.Close()
			}
			// err != nil is fine — means retain() correctly detected the handle was released
		}()

		wg.Wait()

		// Close the initial context, which may trigger the actual Destroy
		ctx.Close()
	}
}

// TestHandleCloseConcurrentWithContextRun exercises the race between
// Handle.Close and Context.Run. In production, the RC goroutine calls
// Handle.Close → ddwaf_destroy while request goroutines are calling
// Context.Run → ddwaf_run on contexts derived from the same handle.
//
// Even though Context.Run doesn't directly read handle.cHandle, the C
// library's ddwaf_run accesses the underlying WAF instance which is freed
// by ddwaf_destroy. This test verifies that refcounting properly prevents
// Destroy from running while contexts are still active.
func TestHandleCloseConcurrentWithContextRun(t *testing.T) {
	builder, err := NewBuilder("", "")
	require.NoError(t, err)
	defer builder.Close()

	_, err = builder.AddDefaultRecommendedRuleset()
	require.NoError(t, err)

	const iterations = 500

	for i := 0; i < iterations; i++ {
		handle := builder.Build()
		if handle == nil {
			t.Fatal("builder.Build() returned nil")
		}

		ctx, err := handle.NewContext(ctxOpts...)
		if err != nil {
			t.Fatalf("NewContext failed: %v", err)
		}

		var wg sync.WaitGroup

		// Goroutine 1: close the handle (simulates RC swap)
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle.Close()
		}()

		// Goroutine 2: run the WAF (simulates request handler)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Run with some data — if Destroy races, this will SIGSEGV
			_, _ = ctx.Run(RunAddressData{
				Persistent: map[string]any{
					"server.request.uri.raw": "/test",
				},
			})
		}()

		wg.Wait()
		ctx.Close()
	}
}

// TestHandleCloseConcurrentWithContextClose exercises the race between
// Handle.Close and Context.Close running concurrently. Both decrement
// the refcount — if the C handle is destroyed by one while the other
// is still calling ddwaf_context_destroy, we get a use-after-free.
func TestHandleCloseConcurrentWithContextClose(t *testing.T) {
	builder, err := NewBuilder("", "")
	require.NoError(t, err)
	defer builder.Close()

	_, err = builder.AddDefaultRecommendedRuleset()
	require.NoError(t, err)

	const iterations = 1000

	for i := 0; i < iterations; i++ {
		handle := builder.Build()
		if handle == nil {
			t.Fatal("builder.Build() returned nil")
		}

		ctx, err := handle.NewContext(ctxOpts...)
		if err != nil {
			t.Fatalf("NewContext failed: %v", err)
		}

		var wg sync.WaitGroup

		// Goroutine 1: close the handle (RC swap)
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle.Close()
		}()

		// Goroutine 2: close the context (request finishing)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx.Close()
		}()

		wg.Wait()
	}
}

// TestContextDoubleClose verifies that closing a Context twice doesn't
// double-decrement the Handle refcount, which would cause premature
// Handle destruction.
func TestContextDoubleClose(t *testing.T) {
	builder, err := NewBuilder("", "")
	require.NoError(t, err)
	defer builder.Close()

	_, err = builder.AddDefaultRecommendedRuleset()
	require.NoError(t, err)

	handle := builder.Build()
	require.NotNil(t, handle)

	// Create two contexts so handle refcount = 3 (handle + 2 contexts)
	ctx1, err := handle.NewContext(ctxOpts...)
	require.NoError(t, err)

	ctx2, err := handle.NewContext(ctxOpts...)
	require.NoError(t, err)

	// Double-close ctx1 — this should NOT double-decrement the refcount
	ctx1.Close()
	ctx1.Close() // Second close — if buggy, refcount goes 2→1→0 and Destroy runs

	// ctx2 should still be usable — if double-close caused premature Destroy, this will SIGSEGV
	_, err = ctx2.Run(RunAddressData{
		Persistent: map[string]any{
			"server.request.uri.raw": "/test",
		},
	})
	// We don't care about the result, just that it doesn't crash
	_ = err

	ctx2.Close()
	handle.Close()
}

// TestMassiveConcurrentNewContextAndClose is a stress test that simulates
// the production scenario: many goroutines creating and closing contexts
// while the handle is being closed by another goroutine (RC swap).
func TestMassiveConcurrentNewContextAndClose(t *testing.T) {
	builder, err := NewBuilder("", "")
	require.NoError(t, err)
	defer builder.Close()

	_, err = builder.AddDefaultRecommendedRuleset()
	require.NoError(t, err)

	const (
		iterations = 100
		workers    = 20
	)

	for i := 0; i < iterations; i++ {
		handle := builder.Build()
		if handle == nil {
			t.Fatal("builder.Build() returned nil")
		}

		var (
			wg             sync.WaitGroup
			contextsOpened atomic.Int32
		)

		// Spawn many workers trying to create and use contexts
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, err := handle.NewContext(ctxOpts...)
				if err != nil {
					return // Handle was already closed, that's fine
				}
				contextsOpened.Add(1)

				// Do a WAF run
				_, _ = ctx.Run(RunAddressData{
					Persistent: map[string]any{
						"server.request.uri.raw": "/test",
					},
				})

				ctx.Close()
			}()
		}

		// Close the handle while workers are still running (RC swap)
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle.Close()
		}()

		wg.Wait()
	}
}
