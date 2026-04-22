// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"fmt"
	"maps"
	"runtime"
	"sync"
	"time"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// Context is a WAF execution context. It allows running the WAF incrementally when calling it
// multiple times to run its rules every time new addresses become available. Each request must have
// its own [Context]. New [Context] instances can be created by calling
// [Handle.NewContext].
//
// Subcontexts can be created via [Context.SubContext]. Data passed to a subcontext is stored
// and persists across multiple calls to Run on that subcontext, until the subcontext is closed.
type Context struct {
	// Timer registers the time spent in the WAF and go-libddwaf. It is created alongside the Context using the options
	// passed in to NewContext. Once its time budget is exhausted, each new call to Context.Run will return a timeout error.
	Timer timer.NodeTimer

	handle *Handle // Instance of the WAF

	root        *contextRoot           // Shared root state for the C ddwaf_context pointer
	cSubcontext bindings.WAFSubcontext // The C ddwaf_subcontext pointer (nil for root context)

	// mutex protecting local fields such as truncations, pinner and cSubcontext.
	mutex sync.Mutex

	// truncations provides details about truncations that occurred while encoding address data for the WAF execution.
	truncations map[TruncationReason][]int

	// pinner is used to retain Go data that is being passed to the WAF as part of
	// [RunAddressData.Data] until the [Context.Close] method results in the context being
	// destroyed.
	pinner pin.ConcurrentPinner
}

type contextRoot struct {
	mu       sync.Mutex
	cContext bindings.WAFContext
	closed   bool
}

// RunAddressData provides address data to the [Context.Run] method.
// When encoding Go structs to the WAF-compatible format, fields with the `ddwaf:"ignore"` tag are
// ignored and will not be visible to the WAF.
//
// Data passed to Run is stored and persists for the lifetime of the context or subcontext.
// Use SubContext() to scope data to a shorter lifetime.
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
	if d.TimerKey == "" {
		return timer.NewTreeTimer(
			timer.WithComponents(
				EncodeTimeKey,
				DurationTimeKey,
				DecodeTimeKey,
			),
			timer.WithBudget(parent.SumRemaining()),
		)
	}

	return parent.NewNode(d.TimerKey,
		timer.WithComponents(
			EncodeTimeKey,
			DurationTimeKey,
			DecodeTimeKey,
		),
		timer.WithInheritedSumBudget(),
	)
}

// isSubcontext returns true if this context is a subcontext.
func (context *Context) isSubcontext() bool {
	return context.cSubcontext != 0
}

func (context *Context) isClosedLocked() bool {
	return context.root.closed || context.root.cContext == 0 || (context.isSubcontext() && context.cSubcontext == 0)
}

// SubContext creates a subcontext derived from this context.
// Data passed to the subcontext's Run() is stored and persists across multiple calls
// to Run on that subcontext, but does not persist in the parent context.
// When the subcontext is closed, its data is released.
//
// Usage:
//
//	subCtx, err := ctx.SubContext()
//	if err != nil {
//	    return err
//	}
//	defer subCtx.Close()
//	result, err := subCtx.Run(RunAddressData{Data: data})
func (context *Context) SubContext() (*Context, error) {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	if context.isSubcontext() {
		return nil, fmt.Errorf("cannot create subcontext from subcontext; create from root context")
	}

	context.root.mu.Lock()
	defer context.root.mu.Unlock()

	if context.isClosedLocked() {
		return nil, waferrors.ErrContextClosed
	}

	if !context.handle.retain() {
		return nil, fmt.Errorf("WAF handle has been released")
	}
	success := false
	defer func() {
		if !success {
			context.handle.Close()
		}
	}()

	cSubcontext := bindings.Lib.SubcontextInit(context.root.cContext)
	if cSubcontext == 0 {
		return nil, fmt.Errorf("failed to create subcontext: ddwaf_subcontext_init returned null")
	}

	// Inherit timer from parent
	subTimer, err := timer.NewTreeTimer(
		timer.WithComponents(
			EncodeTimeKey,
			DurationTimeKey,
			DecodeTimeKey,
		),
		timer.WithBudget(context.Timer.SumRemaining()),
	)
	if err != nil {
		bindings.Lib.SubcontextDestroy(cSubcontext)
		return nil, fmt.Errorf("failed to create subcontext timer: %w", err)
	}

	success = true
	return &Context{
		Timer:       subTimer,
		handle:      context.handle,
		root:        context.root,
		cSubcontext: cSubcontext,
	}, nil
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
// Callers must check the returned [Result] object even when an error is returned, as the WAF might
// have been able to match some rules and generate events or actions before the error was reached;
// especially when the error is [waferrors.ErrTimeout].
func (context *Context) Run(addressData RunAddressData) (res Result, err error) {
	if addressData.isEmpty() {
		context.mutex.Lock()
		defer context.mutex.Unlock()

		context.root.mu.Lock()
		defer context.root.mu.Unlock()

		if context.isClosedLocked() {
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

	context.root.mu.Lock()
	if context.isClosedLocked() {
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
	defer context.root.mu.Unlock()

	if context.isClosedLocked() {
		// Context or subcontext has been closed, returning an empty result...
		return Result{}, waferrors.ErrContextClosed
	}

	if runTimer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}

	return context.run(data, runTimer)
}

// merge merges two maps of slices into a single map of slices. The resulting map will contain all
// keys from both a and b, with the corresponding value from a and b concatenated (in this order) in
// a single slice. The implementation tries to minimize reallocations.
func merge[K comparable, V any](a, b map[K][]V) (merged map[K][]V) {
	count := len(a) + len(b)
	if count == 0 {
		return
	}

	keys := make(map[K]struct{}, count)
	nothing := struct{}{}
	totalCount := 0
	for _, m := range [2]map[K][]V{a, b} {
		for k, v := range m {
			keys[k] = nothing
			totalCount += len(v)
		}
	}

	merged = make(map[K][]V, count)
	values := make([]V, 0, totalCount)

	for k := range keys {
		idxS := len(values) // Start index
		values = append(values, a[k]...)
		values = append(values, b[k]...)
		idxE := len(values) // End index

		merged[k] = values[idxS:idxE]
	}

	return
}

// encodeOneAddressType encodes the given addressData values and returns the corresponding WAF
// object and its refs. If the addressData is empty, it returns nil for the WAF object and an empty
// ref pool.
// At this point, if the encoder does not timeout, the only error we can get is an error in case the
// top level object is a nil map, but this behavior is expected since either persistent or
// ephemeral addresses are allowed to be null one at a time. In this case, Encode will return nil,
// which is what we need to send to ddwaf_run to signal that the address data is empty.
// The caller must hold context.mutex.
func (context *Context) encodeOneAddressType(pinner pin.Pinner, addressData map[string]any, timer timer.Timer) (*bindings.WAFObject, error) {
	if addressData == nil {
		return nil, nil
	}

	encoder, err := newEncoder(newEncoderConfig(pinner, timer))
	if err != nil {
		return nil, fmt.Errorf("could not create encoder: %w", err)
	}

	data, _ := encoder.Encode(addressData)
	if len(encoder.truncations) > 0 {
		context.truncations = merge(context.truncations, encoder.truncations)
	}

	if timer.Exhausted() {
		return nil, waferrors.ErrTimeout
	}

	return data, nil
}

// run executes the ddwaf_run call with the provided data on this context.
// The caller is responsible for holding both context.mutex and context.root.mu.
func (context *Context) run(data *bindings.WAFObject, runTimer timer.NodeTimer) (Result, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var result bindings.WAFObject
	pinner.Pin(&result)
	defer bindings.Lib.ObjectDestroy(&result, bindings.Lib.DefaultAllocator())

	// The value of the timeout cannot exceed 2^55
	// cf. https://en.cppreference.com/w/cpp/chrono/duration
	timeout := uint64(runTimer.SumRemaining().Microseconds()) & 0x008FFFFFFFFFFFFF
	cContext := context.root.cContext
	var ret bindings.WAFReturnCode
	if context.isSubcontext() {
		ret = bindings.Lib.SubcontextEval(context.cSubcontext, data, 0, &result, timeout)
	} else {
		ret = bindings.Lib.ContextEval(cContext, data, 0, &result, timeout)
	}

	decodeTimer := runTimer.MustLeaf(DecodeTimeKey)
	decodeTimer.Start()
	defer decodeTimer.Stop()

	res, duration, err := unwrapWafResult(ret, &result)
	runTimer.AddTime(DurationTimeKey, duration)
	return res, err
}

func unwrapWafResult(ret bindings.WAFReturnCode, result *bindings.WAFObject) (Result, time.Duration, error) {
	if !result.IsMap() {
		return Result{}, 0, fmt.Errorf("invalid result (expected map, got %s)", result.Type())
	}

	entries, err := result.MapEntries()
	if err != nil {
		return Result{}, 0, err
	}

	var (
		res      Result
		duration time.Duration
	)
	for _, entry := range entries {
		key, err := entry.Key.StringValue()
		if err != nil {
			return Result{}, 0, fmt.Errorf("failed to decode WAF result key: %w", err)
		}

		switch key {
		case "timeout":
			timeout, err := entry.Val.BoolValue()
			if err != nil {
				return Result{}, 0, fmt.Errorf("failed to decode timeout: %w", err)
			}
			if timeout {
				err = waferrors.ErrTimeout
			}
		case "keep":
			keep, err := entry.Val.BoolValue()
			if err != nil {
				return Result{}, 0, fmt.Errorf("failed to decode keep: %w", err)
			}
			res.Keep = keep
		case "duration":
			dur, err := entry.Val.UIntValue()
			if err != nil {
				return Result{}, 0, fmt.Errorf("failed to decode duration: %w", err)
			}
			duration = time.Duration(dur) * time.Nanosecond
		case "events":
			if !entry.Val.IsArray() {
				return Result{}, 0, fmt.Errorf("invalid events (expected array, got %s)", entry.Val.Type())
			}
			size, err := entry.Val.ArraySize()
			if err != nil {
				return Result{}, 0, fmt.Errorf("failed to get events array size: %w", err)
			}
			if size != 0 {
				events, err := entry.Val.ArrayValue()
				if err != nil {
					return Result{}, 0, fmt.Errorf("failed to decode events: %w", err)
				}
				res.Events = events
			}
		case "actions":
			if !entry.Val.IsMap() {
				return Result{}, 0, fmt.Errorf("invalid actions (expected map, got %s)", entry.Val.Type())
			}
			size, err := entry.Val.MapSize()
			if err != nil {
				return Result{}, 0, fmt.Errorf("failed to get actions map size: %w", err)
			}
			if size != 0 {
				actions, err := entry.Val.MapValue()
				if err != nil {
					return Result{}, 0, fmt.Errorf("failed to decode actions: %w", err)
				}
				res.Actions = actions
			}
		case "attributes":
			if !entry.Val.IsMap() {
				return Result{}, 0, fmt.Errorf("invalid attributes (expected map, got %s)", entry.Val.Type())
			}
			size, err := entry.Val.MapSize()
			if err != nil {
				return Result{}, 0, fmt.Errorf("failed to get attributes map size: %w", err)
			}
			if size != 0 {
				derivatives, err := entry.Val.MapValue()
				if err != nil {
					return Result{}, 0, fmt.Errorf("failed to decode attributes: %w", err)
				}
				res.Derivatives = derivatives
			}
		}
	}

	return res, duration, goRunError(ret)
}

// Close disposes of the underlying context or subcontext.
// It destroys the context, releases associated data, and decreases
// the reference count of the [Handle] created for this [Context].
func (context *Context) Close() {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	defer context.handle.Close() // Reduce the reference counter of the Handle.

	context.root.mu.Lock()
	defer context.root.mu.Unlock()

	if context.isSubcontext() {
		if context.cSubcontext != 0 && !context.root.closed && context.root.cContext != 0 {
			bindings.Lib.SubcontextDestroy(context.cSubcontext)
		}
		context.cSubcontext = 0
		context.pinner.Unpin()
		return
	}

	if !context.root.closed && context.root.cContext != 0 {
		bindings.Lib.ContextDestroy(context.root.cContext)
		context.root.cContext = 0
		context.root.closed = true
	}

	context.pinner.Unpin()
}

// Truncations returns the truncations that occurred while encoding address data for WAF execution.
// The key is the truncation reason: either because the object was too deep, the arrays where to large or the strings were too long.
// The value is a slice of integers, each integer being the original size of the object that was truncated.
// In case of the [ObjectTooDeep] reason, the original size can only be approximated because of recursive objects.
func (context *Context) Truncations() map[TruncationReason][]int {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	return maps.Clone(context.truncations)
}
