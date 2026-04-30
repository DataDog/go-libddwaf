// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"errors"
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

// numTruncationReasons is the number of known [TruncationReason]s; sized so
// the truncations map allocated in NewContext/NewSubcontext rarely grows.
const numTruncationReasons = 3

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
type Context struct {
	// Timer registers the time spent in the WAF and go-libddwaf. It is created alongside the Context using the options
	// passed in to NewContext. Once its time budget is exhausted, each new call to Context.Run will return a timeout error.
	Timer timer.NodeTimer

	handle *Handle // Instance of the WAF

	root        *contextRoot              // Shared root state for the C ddwaf_context pointer
	isSubCtx    bool                      // Whether this Context represents a subcontext
	closed      atomic.Bool               // Whether this Context or subcontext has been closed
	cSubcontext wafBindings.WAFSubcontext // The C ddwaf_subcontext pointer (nil for root context)

	closedHint    atomic.Bool
	evalsInFlight sync.WaitGroup
	mu            sync.Mutex

	// mutex protecting local fields such as pinner and cSubcontext.
	mutex sync.Mutex

	// truncationsMu protects reads and writes to truncations independently of
	// the run mutex, so that Truncations() does not block on long Run() calls.
	truncationsMu sync.RWMutex

	// truncations provides details about truncations that occurred while encoding address data for the WAF execution.
	truncations map[TruncationReason][]int

	// pinner is used to retain Go data that is being passed to the WAF as part of
	// [RunAddressData.Data] until the [Context.Close] method results in the context being
	// destroyed.
	pinner pin.ConcurrentPinner
}

type contextRoot struct {
	mu         sync.Mutex
	cContext   wafBindings.WAFContext
	closed     atomic.Bool
	activeRuns atomic.Int64
}

// RunAddressData provides address data to the [Context.Run] method.
// When encoding Go structs to the WAF-compatible format, fields with the `ddwaf:"ignore"` tag are
// ignored and will not be visible to the WAF.
//
// Data passed to Run is stored and persists for the lifetime of the context or subcontext.
// Use NewSubcontext() to scope data to a shorter lifetime.
type RunAddressData struct {
	// Data is the address data to pass to the WAF. Data is stored and persists across multiple
	// calls to Run until the context or subcontext is closed.
	Data map[string]any

	// TimerKey is the key used to track the time spent in the WAF for this run.
	// If left empty, a new timer with unlimited budget is started.
	TimerKey timer.Key
}

func (d RunAddressData) isEmpty() bool {
	return len(d.Data) == 0
}

// newTimer creates a new timer for this run. If the TimerKey is empty, a new timer without taking the parent into account is created.
func (d RunAddressData) newTimer(parent timer.NodeTimer) (timer.NodeTimer, error) {
	return newRunTimer(parent, d.TimerKey)
}

func (context *Context) isSubcontext() bool {
	return context.isSubCtx
}

// isClosedAssumingBothLocked reports whether this context (or subcontext) is no
// longer usable because either itself or its underlying C context has been
// released.
//
// The caller MUST hold BOTH locks before calling this method:
//   - context.mutex (guards context.closed and context.cSubcontext)
//   - context.root.mu (guards context.root.closed and context.root.cContext)
//
// Lock order is always context.mutex then context.root.mu.
func (context *Context) isClosedAssumingBothLocked() bool {
	if context.root.closed.Load() {
		return true
	}
	if context.root.cContext == 0 {
		return true
	}
	if context.closed.Load() {
		return true
	}
	if context.isSubcontext() && context.cSubcontext == 0 {
		return true
	}
	return false
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
// Calling NewSubcontext on an existing subcontext creates another subcontext from
// the same root WAF context. The new subcontext does not inherit the current
// subcontext's ephemeral state.
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
		if context.closed.Load() || context.root.closed.Load() {
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

	context.mutex.Lock()
	defer context.mutex.Unlock()

	context.root.mu.Lock()
	defer context.root.mu.Unlock()

	if context.isClosedAssumingBothLocked() {
		return nil, waferrors.ErrContextClosed
	}

	cSubcontext := wafBindings.Lib.SubcontextInit(context.root.cContext)
	if cSubcontext == 0 {
		return nil, errors.New("failed to create subcontext: ddwaf_subcontext_init returned null")
	}

	parentStats := context.Timer.Stats()
	seen := make(map[timer.Key]struct{}, len(parentStats)+3)
	components := make([]timer.Key, 0, len(parentStats)+3)
	for k := range parentStats {
		seen[k] = struct{}{}
		components = append(components, k)
	}
	for _, key := range []timer.Key{EncodeTimeKey, DurationTimeKey, DecodeTimeKey} {
		if _, ok := seen[key]; !ok {
			components = append(components, key)
			seen[key] = struct{}{}
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
		Timer:       subTimer,
		parent:      context,
		cSub:        cSubcontext,
		truncations: make(map[TruncationReason][]int, numTruncationReasons),
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
		if context.closed.Load() || context.root.closed.Load() {
			return Result{}, waferrors.ErrContextClosed
		}
		return Result{}, nil
	}

	// If the context has already timed out, we don't need to run the WAF again
	if context.Timer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}

	runTimer, err := addressData.newTimer(context.Timer)
	if err != nil {
		return Result{}, err
	}

	defer func() {
		res.TimerStats = runTimer.Stats()
	}()

	context.mutex.Lock()
	defer context.mutex.Unlock()

	// First closed check: optimization to avoid expensive encoding work if
	// the context is already closed. This check releases root.mu before
	// encoding because encoding is pure Go work that does not touch the C
	// context. A concurrent Close() can run between here and the second
	// check below — that is safe because encoding only writes to Go memory.
	context.root.mu.Lock()
	if context.isClosedAssumingBothLocked() {
		context.root.mu.Unlock()
		return Result{}, waferrors.ErrContextClosed
	}
	context.root.mu.Unlock()

	runTimer.Start()
	defer runTimer.Stop()

	wafEncodeTimer := runTimer.MustLeaf(EncodeTimeKey)
	wafEncodeTimer.Start()
	defer wafEncodeTimer.Stop()

	// Data is stored by both contexts and subcontexts across multiple calls.
	// Use the context's pinner which gets unpinned when the context/subcontext is closed.
	data, err := context.encodeOneAddressType(&context.pinner, addressData.Data, wafEncodeTimer)
	if err != nil {
		return Result{}, err
	}

	wafEncodeTimer.Stop()

	context.root.mu.Lock()
	// Second closed check: safety gate after re-acquiring root.mu. This
	// ensures the C context is still alive before passing encoded data to
	// the C library.
	// root.mu is held for the full duration of the C call because libddwaf
	// requires serialized access to ddwaf_context_eval / ddwaf_subcontext_eval
	// on the same parent context. The activeRuns counter prevents Close() from
	// destroying the C context during evaluation but does not provide mutual
	// exclusion for the C call itself.
	defer context.root.mu.Unlock()

	if context.isClosedAssumingBothLocked() {
		return Result{}, waferrors.ErrContextClosed
	}

	context.root.activeRuns.Add(1)
	defer context.root.activeRuns.Add(-1)

	if runTimer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}

	return context.run(ctx, data, runTimer)
}

// merge combines two maps of slices into one. All returned slice values
// share a single backing array for efficiency. Callers MUST NOT append
// to individual slices in the returned map, as this would corrupt
// adjacent entries in the shared backing array.
//
// It contains all keys from both a and b, with the corresponding values
// from a and b concatenated in that order. The named return keeps the
// empty-input fast path concise while still allowing the accumulator to be
// built without extra copies.
func merge[K comparable, V any](a, b map[K][]V) (merged map[K][]V) {
	if len(a) == 0 && len(b) == 0 {
		return
	}

	totalCount := 0
	for _, v := range a {
		totalCount += len(v)
	}
	for _, v := range b {
		totalCount += len(v)
	}

	merged = make(map[K][]V, len(a)+len(b))
	values := make([]V, 0, totalCount)

	for k, av := range a {
		start := len(values)
		values = append(values, av...)
		values = append(values, b[k]...)
		merged[k] = values[start:]
	}

	for k, bv := range b {
		if _, ok := merged[k]; !ok {
			start := len(values)
			values = append(values, bv...)
			merged[k] = values[start:]
		}
	}

	return
}

// encodeOneAddressType encodes a single address-data map into its WAF object
// representation for a single [Context.Run] call. It returns nil for the WAF
// object when addressData is nil/empty; this is intentional and is what
// ddwaf_context_eval / ddwaf_subcontext_eval expect to signal that no new
// address data is being supplied for this evaluation.
//
// Note: in v5, a single [RunAddressData.Data] map is encoded per call.
// Ephemeral data is no longer a separate field and is instead scoped via
// [Context.NewSubcontext].
//
// If the encoder times out, [waferrors.ErrTimeout] is returned. Any truncations
// recorded by the encoder are merged into context.truncations.
//
// The caller must hold context.mutex.
func (context *Context) encodeOneAddressType(pinner pin.Pinner, addressData map[string]any, timer timer.Timer) (*WAFObject, error) {
	data, truncations, err := encodeAddressData(pinner, addressData, timer)
	if err != nil {
		return nil, err
	}
	if len(truncations) > 0 {
		context.truncationsMu.Lock()
		context.truncations = merge(context.truncations, truncations)
		context.truncationsMu.Unlock()
	}
	return data, nil
}

// run executes the ddwaf_run call with the provided data on this context.
// The caller is responsible for holding both context.mutex and context.root.mu.
func (context *Context) run(ctx context.Context, data *WAFObject, runTimer timer.NodeTimer) (Result, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	result := newWAFObject()
	pinner.Pin(result.raw())
	defer wafBindings.Lib.ObjectDestroy(result.raw(), wafBindings.Lib.DefaultAllocator())

	timeout := effectiveTimeoutMicros(ctx, runTimer)
	cContext := context.root.cContext
	var ret wafBindings.WAFReturnCode
	if context.isSubcontext() {
		ret = wafBindings.Lib.SubcontextEval(context.cSubcontext, data.raw(), 0, result.raw(), timeout)
	} else {
		ret = wafBindings.Lib.ContextEval(cContext, data.raw(), 0, result.raw(), timeout)
	}

	return decodeWafResult(ctx, ret, &result, runTimer)
}

// Close disposes of the underlying context or subcontext.
// It destroys the context, releases associated data, and decreases
// the reference count of the [Handle] created for this [Context].
func (context *Context) Close() {
	context.mutex.Lock()
	if context.closed.Load() {
		context.mutex.Unlock()
		return
	}
	defer context.mutex.Unlock()
	defer context.handle.Close()

	context.root.mu.Lock()

	if context.isSubcontext() {
		if context.cSubcontext != 0 && !context.root.closed.Load() && context.root.cContext != 0 {
			wafBindings.Lib.SubcontextDestroy(context.cSubcontext)
		}
		context.closed.Store(true)
		context.cSubcontext = 0
		context.root.mu.Unlock()
		context.pinner.Close()
		return
	}

	if !context.root.closed.Load() && context.root.cContext != 0 {
		cContext := context.root.cContext
		context.root.closed.Store(true)
		context.root.cContext = 0
		context.closed.Store(true)
		context.root.mu.Unlock()

		for context.root.activeRuns.Load() > 0 {
			runtime.Gosched()
		}

		if cContext != 0 {
			wafBindings.Lib.ContextDestroy(cContext)
		}
		context.pinner.Close()
		return
	}
	context.closed.Store(true)
	context.root.mu.Unlock()

	context.pinner.Close()
}

// Truncations returns the truncations that occurred while encoding address data for WAF execution.
// The key is the truncation reason: either because the object was too deep, the arrays where to large or the strings were too long.
// The value is a slice of integers, each integer being the original size of the object that was truncated.
// In case of the [ObjectTooDeep] reason, the original size can only be approximated because of recursive objects.
func (context *Context) Truncations() map[TruncationReason][]int {
	context.truncationsMu.RLock()
	defer context.truncationsMu.RUnlock()

	return maps.Clone(context.truncations)
}
