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
// v2: Subcontexts can be created via [Context.SubContext]. Data passed to a subcontext is stored
// and persists across multiple calls to Run on that subcontext, until the subcontext is closed.
type Context struct {
	// Timer registers the time spent in the WAF and go-libddwaf. It is created alongside the Context using the options
	// passed in to NewContext. Once its time budget is exhausted, each new call to Context.Run will return a timeout error.
	Timer timer.NodeTimer

	handle *Handle // Instance of the WAF

	cContext    bindings.WAFContext    // The C ddwaf_context pointer
	cSubcontext bindings.WAFSubcontext // v2: The C ddwaf_subcontext pointer (nil for root context)
	parent      *Context               // v2: Parent context (nil for root context)

	// mutex protecting the use of cContext which is not thread-safe and truncations
	mutex sync.Mutex

	// truncations provides details about truncations that occurred while encoding address data for the WAF execution.
	truncations map[TruncationReason][]int

	// pinner is used to retain Go data that is being passed to the WAF as part of
	// [RunAddressData.Data] until the [Context.Close] method results in the context being
	// destroyed.
	pinner pin.ConcurrentPinner
}

// RunAddressData provides address data to the [Context.Run] method.
// When encoding Go structs to the WAF-compatible format, fields with the `ddwaf:"ignore"` tag are
// ignored and will not be visible to the WAF.
//
// v2: The Persistent/Ephemeral split has been removed. Data passed to Run is stored and persists
// for the lifetime of the context or subcontext. Use SubContext() to scope data to a shorter lifetime.
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

	if context.cContext == 0 {
		return nil, waferrors.ErrContextClosed
	}

	// v2: Create subcontext from parent context
	// If this is already a subcontext, we create from its parent's context
	parentCContext := context.cContext
	if context.isSubcontext() {
		// Subcontexts can't create sub-subcontexts; use the root context
		parentCContext = context.parent.cContext
	}

	cSubcontext := bindings.Lib.SubcontextInit(parentCContext)
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

	// Determine the actual parent (root context)
	parent := context
	if context.isSubcontext() {
		parent = context.parent
	}

	return &Context{
		Timer:       subTimer,
		handle:      context.handle,
		cContext:    parentCContext,
		cSubcontext: cSubcontext,
		parent:      parent,
	}, nil
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
// Callers must check the returned [Result] object even when an error is returned, as the WAF might
// have been able to match some rules and generate events or actions before the error was reached;
// especially when the error is [waferrors.ErrTimeout].
func (context *Context) Run(addressData RunAddressData) (res Result, err error) {
	if addressData.isEmpty() {
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

	runTimer.Start()
	defer runTimer.Stop()

	wafEncodeTimer := runTimer.MustLeaf(EncodeTimeKey)
	wafEncodeTimer.Start()
	defer wafEncodeTimer.Stop()

	// v2: Data is stored by both contexts and subcontexts across multiple calls.
	// Use the context's pinner which gets unpinned when the context/subcontext is closed.
	data, err := context.encodeOneAddressType(&context.pinner, addressData.Data, wafEncodeTimer)
	if err != nil {
		return Result{}, err
	}

	wafEncodeTimer.Stop()

	// ddwaf_run cannot run concurrently, so we need to lock the context
	context.mutex.Lock()
	defer context.mutex.Unlock()

	if context.cContext == 0 {
		// Context has been closed, returning an empty result...
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
// top level object is a nil map, but this behaviour is expected since either persistent or
// ephemeral addresses are allowed to be null one at a time. In this case, Encode will return nil,
// which is what we need to send to ddwaf_run to signal that the address data is empty.
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
		context.mutex.Lock()
		defer context.mutex.Unlock()

		context.truncations = merge(context.truncations, encoder.truncations)
	}

	if timer.Exhausted() {
		return nil, waferrors.ErrTimeout
	}

	return data, nil
}

// run executes the ddwaf_run call with the provided data on this context. The caller is responsible for locking the
// context appropriately around this call.
func (context *Context) run(data *bindings.WAFObject, runTimer timer.NodeTimer) (Result, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var result bindings.WAFObject
	pinner.Pin(&result)
	defer bindings.Lib.ObjectDestroy(&result, bindings.Lib.DefaultAllocator())

	// The value of the timeout cannot exceed 2^55
	// cf. https://en.cppreference.com/w/cpp/chrono/duration
	timeout := uint64(runTimer.SumRemaining().Microseconds()) & 0x008FFFFFFFFFFFFF

	// v2: Use ContextEval for root contexts, SubcontextEval for subcontexts
	// Pass 0 for allocator since we're managing memory in Go
	var ret bindings.WAFReturnCode
	if context.isSubcontext() {
		ret = bindings.Lib.SubcontextEval(context.cSubcontext, data, 0, &result, timeout)
	} else {
		ret = bindings.Lib.ContextEval(context.cContext, data, 0, &result, timeout)
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

	// v2: Maps are now arrays of WAFObjectKV pairs
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
			continue // Skip entries with non-string keys
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
			size, _ := entry.Val.ArraySize()
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
			size, _ := entry.Val.MapSize()
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
			size, _ := entry.Val.MapSize()
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
//
// For subcontexts: destroys the subcontext and returns the parent context.
// For root contexts: destroys the context, releases associated data, and decreases
// the reference count of the [Handle] which created this [Context].
//
// v2: Returns the parent context for subcontexts, nil for root contexts.
func (context *Context) Close() *Context {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	if context.isSubcontext() {
		// Destroy subcontext only
		bindings.Lib.SubcontextDestroy(context.cSubcontext)
		context.cSubcontext = 0
		context.pinner.Unpin()
		return context.parent
	}

	// Root context: full cleanup
	bindings.Lib.ContextDestroy(context.cContext)
	context.cContext = 0 // Makes it easy to spot use-after-free/double-free issues

	context.pinner.Unpin() // The pinned data is no longer needed, explicitly release
	context.handle.Close() // Reduce the reference counter of the Handle.
	return nil
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
