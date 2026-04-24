// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

// Package testhelpers provides shared test utilities for go-libddwaf tests.
// It is placed under internal/ to prevent external packages from depending on it.
//
// The helpers here exist to eliminate repeated boilerplate patterns found
// throughout the test suite, particularly the concurrent goroutine barrier
// pattern and common error assertion helpers.
package testhelpers

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ConcurrentRunner executes iter on numGoroutines goroutines, gating start
// with a shared barrier. It captures the first non-nil error returned and
// calls t.Fatal with it. Each test that exercises concurrent behavior should
// use this helper to avoid reinventing the barrier pattern.
func ConcurrentRunner(t testing.TB, numGoroutines int, iter func(goroutineIdx int) error) {
	t.Helper()
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier // wait for all goroutines to be ready
			if err := iter(idx); err != nil {
				errCh <- err
			}
		}(i)
	}

	close(barrier) // release all goroutines simultaneously
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// RequireErrorIs asserts that errors.Is(err, target) is true, failing the
// test with a descriptive message if not. Prefer this over require.Equal for
// error matching to be future-proof against error wrapping.
func RequireErrorIs(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("expected errors.Is(%v, %v) to be true, but it was false\nerr type: %T\ntarget type: %T", err, target, err, target)
	}
}

// RequireNoError asserts that err is nil, failing the test with a descriptive
// message if not.
func RequireNoError(t testing.TB, err error, msgAndArgs ...any) {
	t.Helper()
	if err != nil {
		if len(msgAndArgs) > 0 {
			t.Fatalf("unexpected error: %v\ncontext: %v", err, fmt.Sprint(msgAndArgs...))
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}
