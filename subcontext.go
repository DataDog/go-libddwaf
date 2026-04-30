// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"fmt"
	"maps"
	"runtime"
	"sync"
	"sync/atomic"

	wafBindings "github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// Lock order: Subcontext.mu MUST be acquired before parent.Context.mu. Never reverse.

// Subcontext is a derived ephemeral evaluation scope. Spawned via [Context.NewSubcontext].
// Data passed to a Subcontext's Run persists for the Subcontext's lifetime and is
// released when the Subcontext is closed.
//
// # Concurrency
//
// Subcontext.Run may be called concurrently across different Subcontexts of
// the same parent; same-Subcontext Run calls serialize internally.
//
// Subcontext.Close should be called before its parent Context.Close for clean
// teardown; if the parent is already closed, Subcontext.Close is still safe
// (it skips the underlying destroy).
type Subcontext struct {
	Timer         timer.NodeTimer
	parent        *Context
	closedHint    atomic.Bool
	mu            sync.Mutex
	cSub          wafBindings.WAFSubcontext
	truncationsMu sync.RWMutex
	truncations   map[TruncationReason][]int
	pinner        pin.ConcurrentPinner
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
func (s *Subcontext) Run(ctx context.Context, addressData RunAddressData) (res Result, err error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("Subcontext.Run: %w", waferrors.ErrNilContext)
	}

	if addressData.isEmpty() {
		if s.closedHint.Load() || s.parent.closedHint.Load() {
			return Result{}, waferrors.ErrContextClosed
		}
		return Result{}, nil
	}

	if s.closedHint.Load() {
		return Result{}, waferrors.ErrContextClosed
	}

	if s.Timer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}

	runTimer, err := newRunTimer(s.Timer, addressData.TimerKey)
	if err != nil {
		return Result{}, err
	}
	defer func() { res.TimerStats = runTimer.Stats() }()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closedHint.Load() {
		return Result{}, waferrors.ErrContextClosed
	}

	s.parent.mu.Lock()
	if s.parent.closedHint.Load() {
		s.parent.mu.Unlock()
		return Result{}, waferrors.ErrContextClosed
	}
	s.parent.evalsInFlight.Add(1)
	s.parent.mu.Unlock()
	defer s.parent.evalsInFlight.Done()

	runTimer.Start()
	defer runTimer.Stop()

	wafEncodeTimer := runTimer.MustLeaf(EncodeTimeKey)
	wafEncodeTimer.Start()
	data, truncations, err := encodeAddressData(&s.pinner, addressData.Data, wafEncodeTimer)
	wafEncodeTimer.Stop()
	if err != nil {
		return Result{}, err
	}
	if len(truncations) > 0 {
		s.truncationsMu.Lock()
		s.truncations = merge(s.truncations, truncations)
		s.truncationsMu.Unlock()
	}

	if runTimer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}
	timeout := effectiveTimeoutMicros(ctx, runTimer)

	var pinner runtime.Pinner
	defer pinner.Unpin()
	result := newWAFObject()
	pinner.Pin(result.raw())
	defer wafBindings.Lib.ObjectDestroy(result.raw(), wafBindings.Lib.DefaultAllocator())

	ret := wafBindings.Lib.SubcontextEval(s.cSub, data.raw(), 0, result.raw(), timeout)

	return decodeWafResult(ctx, ret, &result, runTimer)
}

// Close disposes of the underlying subcontext.
func (s *Subcontext) Close() {
	if !s.closedHint.CompareAndSwap(false, true) {
		return
	}

	s.mu.Lock()
	s.mu.Unlock() //nolint:staticcheck // SA2001: intentional barrier — synchronize with Run before pinner close

	s.parent.mu.Lock()
	if !s.parent.closedHint.Load() && s.cSub != 0 {
		wafBindings.Lib.SubcontextDestroy(s.cSub)
	}
	s.parent.mu.Unlock()
	s.cSub = 0

	s.pinner.Close()

	s.parent.handle.Close()
}

// Truncations returns the truncations that occurred while encoding address data for WAF execution.
func (s *Subcontext) Truncations() map[TruncationReason][]int {
	s.truncationsMu.RLock()
	defer s.truncationsMu.RUnlock()
	return maps.Clone(s.truncations)
}
