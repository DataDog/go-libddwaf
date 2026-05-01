// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	wafBindings "github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

const (
	// EncodeTimeKey is the key used to track the time spent encoding the address data reported in [Result.TimerStats].
	EncodeTimeKey timer.Key = "encode"
	// DurationTimeKey is the key used to track the time spent in libddwaf ddwaf_run C function reported in [Result.TimerStats].
	DurationTimeKey timer.Key = "duration"
	// DecodeTimeKey is the key used to track the time spent decoding the address data reported in [Result.TimerStats].
	DecodeTimeKey timer.Key = "decode"
)

// Context is a WAF execution context. It allows running the WAF incrementally when calling it
// multiple times to run its rules every time new addresses become available. Each request must have
// its own [Context]. New [Context] instances can be created by calling
// [Handle.NewContext].
//
// Subcontexts can be created via [Context.NewSubcontext]. Data passed to a subcontext is stored
// and persists across multiple calls to Run on that subcontext, until the subcontext is closed.
//
// # Concurrency
//
// Context.Run may be called concurrently; same-Context Run calls serialize
// internally via a per-instance mutex. Context.Run may run concurrently with
// Subcontext.Run calls under the same Context.
//
// Context.Close waits for all in-flight Run and NewSubcontext operations to
// complete before destroying the underlying ddwaf_context.
type Context struct {
	// Timer registers the time spent in the WAF and go-libddwaf. It is created alongside the Context using the options
	// passed in to NewContext. Once its time budget is exhausted, each new call to Context.Run will return a timeout error.
	Timer timer.NodeTimer

	handle *Handle // Instance of the WAF

	closedHint    atomic.Bool
	evalsInFlight sync.WaitGroup
	mu            sync.Mutex
	cContext      wafBindings.WAFContext

	// truncationsMu protects reads and writes to truncations independently of
	// the run mutex, so that Truncations() does not block on long Run() calls.
	truncationsMu sync.RWMutex

	truncations Truncations

	// pinner is used to retain Go data that is being passed to the WAF as part of
	// [RunAddressData.Data] until the [Context.Close] method results in the context being
	// destroyed.
	pinner pin.ConcurrentPinner
}

// NewSubcontext creates a subcontext derived from this context.
// The provided ctx only scopes the construction call itself and is not retained
// after NewSubcontext returns; per-run deadlines and cancellation must be supplied
// to [Context.Run] via its own ctx argument.
// Data passed to the subcontext's Run() is stored and persists across multiple calls
// to Run on that subcontext, but does not persist in the parent context.
// When the subcontext is closed, its data is released.
//
// A subcontext gets its own timer whose initial budget is snapshotted from the
// caller's remaining budget when the subcontext is created.
//
// Usage:
//
//	subCtx, err := ctx.NewSubcontext(context.Background())
//	if err != nil {
//	    return err
//	}
//	defer subCtx.Close()
//	result, err := subCtx.Run(context.Background(), RunAddressData{Data: data})
func (context *Context) NewSubcontext(ctx context.Context) (*Subcontext, error) {
	if err := validateConstructionContext("Context.NewSubcontext", ctx); err != nil {
		return nil, err
	}

	if !context.handle.retain() {
		if context.closedHint.Load() {
			return nil, waferrors.ErrContextClosed
		}
		return nil, waferrors.ErrHandleReleased
	}
	success := false
	defer func() {
		if !success {
			context.handle.Close()
		}
	}()

	context.mu.Lock()
	defer context.mu.Unlock()

	if context.closedHint.Load() || context.cContext == 0 {
		return nil, waferrors.ErrContextClosed
	}

	cSubcontext := wafBindings.Lib.SubcontextInit(context.cContext)
	if cSubcontext == 0 {
		return nil, errors.New("failed to create subcontext: ddwaf_subcontext_init returned null")
	}

	parentKeys := context.Timer.ComponentKeys()
	var staging [5]timer.Key
	var components []timer.Key
	if len(parentKeys)+3 <= cap(staging) {
		components = staging[:0]
		components = append(components, parentKeys...)
		for _, key := range [...]timer.Key{EncodeTimeKey, DurationTimeKey, DecodeTimeKey} {
			if !slices.Contains(components, key) {
				if len(components) >= cap(staging) {
					components = nil
					break
				}
				components = append(components, key)
			}
		}
	}
	if components == nil {
		seen := make(map[timer.Key]struct{}, len(parentKeys)+3)
		components = make([]timer.Key, 0, len(parentKeys)+3)
		components = append(components, parentKeys...)
		for _, key := range parentKeys {
			seen[key] = struct{}{}
		}
		for _, key := range []timer.Key{EncodeTimeKey, DurationTimeKey, DecodeTimeKey} {
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				components = append(components, key)
			}
		}
	}
	subTimer, err := timer.NewTreeTimer(
		timer.WithComponents(components...),
		timer.WithBudget(context.Timer.SumRemaining()),
	)
	if err != nil {
		wafBindings.Lib.SubcontextDestroy(cSubcontext)
		return nil, fmt.Errorf("failed to create subcontext timer: %w", err)
	}

	success = true
	return &Subcontext{
		Timer:  timer.WrapOwnedNodeTimer(subTimer),
		parent: context,
		cSub:   cSubcontext,
	}, nil
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
// Callers must check the returned [Result] object even when an error is returned, as the WAF might
// have been able to match some rules and generate events or actions before the error was reached.
//
// Deadline precedence is the minimum of ctx's deadline and the remaining [Context.Timer] budget.
// If ctx fires first, Run returns ctx.Err(). If the timer budget fires first, Run returns
// [waferrors.ErrTimeout].
func (context *Context) Run(ctx context.Context, addressData RunAddressData) (res Result, err error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("Context.Run: %w", waferrors.ErrNilContext)
	}

	if addressData.isEmpty() {
		if context.closedHint.Load() {
			return Result{}, waferrors.ErrContextClosed
		}
		return Result{}, nil
	}

	if context.closedHint.Load() {
		return Result{}, waferrors.ErrContextClosed
	}

	context.mu.Lock()
	defer context.mu.Unlock()

	if context.closedHint.Load() {
		return Result{}, waferrors.ErrContextClosed
	}

	if context.Timer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}

	runTimer, err := newRunTimer(context.Timer, addressData.TimerKey)
	if err != nil {
		return Result{}, err
	}
	defer timer.PutNodeTimer(runTimer)
	defer func() { res.TimerStats = runTimer.Stats() }()

	context.evalsInFlight.Add(1)
	defer context.evalsInFlight.Done()

	runTimer.Start()
	defer runTimer.Stop()

	wafEncodeTimer := runTimer.MustLeaf(EncodeTimeKey)
	wafEncodeTimer.Start()
	data, truncations, err := encodeAddressData(&context.pinner, addressData.Data, wafEncodeTimer)
	wafEncodeTimer.Stop()
	if pooled, ok := wafEncodeTimer.(interface{ ReleaseToPool() }); ok {
		// Safe after Stop(): childStopped only does an atomic add into the parent's component lookup and retains no leaf reference.
		pooled.ReleaseToPool()
	}
	if err != nil {
		return Result{}, err
	}
	if !truncations.IsEmpty() {
		context.truncationsMu.Lock()
		context.truncations.Merge(truncations)
		context.truncationsMu.Unlock()
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

	cContext := context.cContext
	ret := wafBindings.Lib.ContextEval(cContext, data, 0, &result, timeout)

	return decodeWafResult(ctx, ret, &result, runTimer)
}

// Close disposes of the underlying context or subcontext.
// It destroys the context, releases associated data, and decreases
// the reference count of the [Handle] created for this [Context].
func (context *Context) Close() {
	if !context.closedHint.CompareAndSwap(false, true) {
		return
	}

	context.mu.Lock()
	context.mu.Unlock() //nolint:staticcheck // SA2001: intentional barrier — synchronize with Run/NewSubcontext before waiting for in-flight evals

	context.evalsInFlight.Wait()
	context.mu.Lock()
	defer context.mu.Unlock()

	if context.cContext != 0 {
		wafBindings.Lib.ContextDestroy(context.cContext)
		context.cContext = 0
	}

	context.pinner.Close()
	timer.PutNodeTimer(context.Timer)
	context.Timer = nil

	context.handle.Close()
}

// Truncations returns the truncations that occurred while encoding address
// data for WAF execution. The returned value is a snapshot; subsequent Run
// calls may accumulate more truncations.
func (context *Context) Truncations() Truncations {
	context.truncationsMu.RLock()
	defer context.truncationsMu.RUnlock()
	return Truncations{
		StringTooLong:     append([]int(nil), context.truncations.StringTooLong...),
		ContainerTooLarge: append([]int(nil), context.truncations.ContainerTooLarge...),
		ObjectTooDeep:     append([]int(nil), context.truncations.ObjectTooDeep...),
	}
}
