// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package testhelpers_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/go-libddwaf/v5/internal/testhelpers"
)

// mockTB wraps *testing.T and overrides Fatal/Fatalf to record failure without
// calling runtime.Goexit(), allowing callers to assert that failure was reported.
type mockTB struct {
	*testing.T
	mu     sync.Mutex
	failed bool
}

func (m *mockTB) Helper() { m.T.Helper() }

func (m *mockTB) Fatal(args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
}

func (m *mockTB) Fatalf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
}

func (m *mockTB) isFailed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failed
}

func TestConcurrentRunner_RunsNGoroutines(t *testing.T) {
	const n = 50
	var count atomic.Int64

	testhelpers.ConcurrentRunner(t, n, func(_ int) error {
		count.Add(1)
		return nil
	})

	if got := count.Load(); got != n {
		t.Fatalf("expected %d goroutines to run, got %d", n, got)
	}
}

func TestConcurrentRunner_CapturesError(t *testing.T) {
	sentinel := errors.New("sentinel error")
	mock := &mockTB{T: t}

	testhelpers.ConcurrentRunner(mock, 5, func(idx int) error {
		if idx == 2 {
			return sentinel
		}
		return nil
	})

	if !mock.isFailed() {
		t.Fatal("expected ConcurrentRunner to report error via t.Fatal")
	}
}

func TestConcurrentRunner_NoErrorOnSuccess(t *testing.T) {
	testhelpers.ConcurrentRunner(t, 10, func(_ int) error {
		return nil
	})
}

func TestRequireErrorIs_PassesOnMatch(t *testing.T) {
	target := errors.New("base")
	wrapped := fmt.Errorf("wrapped: %w", target)
	mock := &mockTB{T: t}

	testhelpers.RequireErrorIs(mock, wrapped, target)

	if mock.isFailed() {
		t.Fatal("expected RequireErrorIs to pass when errors.Is matches")
	}
}

func TestRequireErrorIs_FailsOnMismatch(t *testing.T) {
	a := errors.New("a")
	b := errors.New("b")
	mock := &mockTB{T: t}

	testhelpers.RequireErrorIs(mock, a, b)

	if !mock.isFailed() {
		t.Fatal("expected RequireErrorIs to fail when errors.Is does not match")
	}
}

func TestRequireNoError_PassesOnNil(t *testing.T) {
	mock := &mockTB{T: t}
	testhelpers.RequireNoError(mock, nil)

	if mock.isFailed() {
		t.Fatal("expected RequireNoError to pass on nil error")
	}
}

func TestRequireNoError_FailsOnNonNil(t *testing.T) {
	mock := &mockTB{T: t}
	testhelpers.RequireNoError(mock, errors.New("boom"))

	if !mock.isFailed() {
		t.Fatal("expected RequireNoError to fail on non-nil error")
	}
}

func TestRequireNoError_IncludesContext(t *testing.T) {
	mock := &mockTB{T: t}
	testhelpers.RequireNoError(mock, errors.New("fail"), "during setup")

	if !mock.isFailed() {
		t.Fatal("expected RequireNoError with context to fail on non-nil error")
	}
}
