// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"fmt"
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
	truncations   Truncations
	pinner        pin.ConcurrentPinner
}

type pooledSubcontexts struct{ sync.Pool }

func (pool *pooledSubcontexts) Get() any {
	return pool.Pool.Get().(*Subcontext)
}

func (pool *pooledSubcontexts) Put(x any) {
	_ = x.(*Subcontext)
	subCtx := &Subcontext{}
	subCtx.reset()
	pool.Pool.Put(subCtx)
}

var subcontextPool = pooledSubcontexts{Pool: sync.Pool{
	New: func() any {
		return &Subcontext{}
	},
}}

func (s *Subcontext) reset() {
	s.parent = nil
	s.cSub = 0
	s.closedHint.Store(false)
	s.mu = sync.Mutex{}
	s.truncationsMu = sync.RWMutex{}

	if cap(s.truncations.StringTooLong) > 32 {
		s.truncations.StringTooLong = nil
	} else {
		clear(s.truncations.StringTooLong)
		s.truncations.StringTooLong = s.truncations.StringTooLong[:0]
	}
	if cap(s.truncations.ContainerTooLarge) > 32 {
		s.truncations.ContainerTooLarge = nil
	} else {
		clear(s.truncations.ContainerTooLarge)
		s.truncations.ContainerTooLarge = s.truncations.ContainerTooLarge[:0]
	}
	if cap(s.truncations.ObjectTooDeep) > 32 {
		s.truncations.ObjectTooDeep = nil
	} else {
		clear(s.truncations.ObjectTooDeep)
		s.truncations.ObjectTooDeep = s.truncations.ObjectTooDeep[:0]
	}

	s.pinner = pin.ConcurrentPinner{}
	s.Timer = nil
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
func (s *Subcontext) Run(ctx context.Context, addressData RunAddressData) (res Result, err error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("Subcontext.Run: %w", waferrors.ErrNilContext)
	}
	if s.parent == nil {
		return Result{}, waferrors.ErrContextClosed
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
	if s.parent.closedHint.Load() {
		return Result{}, waferrors.ErrContextClosed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
	defer timer.PutNodeTimer(runTimer)
	defer func() { res.TimerStats = runTimer.Stats() }()

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
	if pooled, ok := wafEncodeTimer.(interface{ ReleaseToPool() }); ok {
		// Safe after Stop(): childStopped only does an atomic add into the parent's component lookup and retains no leaf reference.
		pooled.ReleaseToPool()
	}
	if err != nil {
		return Result{}, err
	}
	if !truncations.IsEmpty() {
		s.truncationsMu.Lock()
		s.truncations.Merge(truncations)
		s.truncationsMu.Unlock()
	}

	if runTimer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}
	timeout := effectiveTimeoutMicros(ctx, runTimer)

	var pinner runtime.Pinner
	defer pinner.Unpin()
	var result WAFObject
	pinner.Pin(&result)
	defer wafBindings.Lib.ObjectDestroy(&result, wafBindings.Lib.DefaultAllocator())

	ret := wafBindings.Lib.SubcontextEval(s.cSub, data, 0, &result, timeout)

	return decodeWafResult(ctx, ret, &result, runTimer)
}

// Close disposes of the underlying subcontext.
func (s *Subcontext) Close() {
	if s.parent == nil {
		return
	}
	if !s.closedHint.CompareAndSwap(false, true) {
		return
	}
	parent := s.parent

	s.mu.Lock()
	_ = s.cSub
	s.mu.Unlock()

	parent.mu.Lock()
	// Skip SubcontextDestroy when the parent Context is already closed:
	// ddwaf_context_destroy transitively destroys all associated subcontexts.
	if !parent.closedHint.Load() && s.cSub != 0 {
		wafBindings.Lib.SubcontextDestroy(s.cSub)
	}
	parent.mu.Unlock()
	s.cSub = 0

	s.pinner.Close()
	timer.PutNodeTimer(s.Timer)
	s.Timer = nil

	parent.handle.Close()
	subcontextPool.Put(s)
}

// Truncations returns the truncations that occurred while encoding address data for WAF execution.
func (s *Subcontext) Truncations() Truncations {
	s.truncationsMu.RLock()
	defer s.truncationsMu.RUnlock()
	return Truncations{
		StringTooLong:     append([]int(nil), s.truncations.StringTooLong...),
		ContainerTooLarge: append([]int(nil), s.truncations.ContainerTooLarge...),
		ObjectTooDeep:     append([]int(nil), s.truncations.ObjectTooDeep...),
	}
}
