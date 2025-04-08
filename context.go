// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/go-libddwaf/v4/errors"
	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/pin"
	"github.com/DataDog/go-libddwaf/v4/timer"
)

// Context is a WAF execution context. It allows running the WAF incrementally when calling it
// multiple times to run its rules every time new addresses become available. Each request must have
// its own [Context]. New [Context] instances can be created by calling
// [Handle.NewContextWithBudget].
type Context struct {
	handle *Handle // Instance of the WAF

	cContext bindings.WafContext // The C ddwaf_context pointer

	// timeoutCount count all calls which have timeout'ed by scope. Keys are fixed at creation time.
	timeoutCount map[Scope]*atomic.Uint64

	// mutex protecting the use of cContext which is not thread-safe and cgoRefs.
	mutex sync.Mutex

	// timer registers the time spent in the WAF and go-libddwaf
	timer timer.NodeTimer

	// metrics stores the cumulative time spent in various parts of the WAF
	metrics metricsStore

	// truncations provides details about truncations that occurred while encoding address data for
	// WAF execution.
	truncations map[Scope]map[TruncationReason][]int

	// pinner is used to retain Go data that is being passed to the WAF as part of
	// [RunAddressData.Persistent] until the [Context.Close] method results in the context being
	// destroyed.
	pinner pin.ConcurrentPinner
}

// RunAddressData provides address data to the [Context.Run] method. If a given key is present in
// both [RunAddressData.Persistent] and [RunAddressData.Ephemeral], the value from
// [RunAddressData.Persistent] will take precedence.
// When encoding Go structs to the WAF-compatible format, fields with the `ddwaf:"ignore"` tag are
// ignored and will not be visible to the WAF.
type RunAddressData struct {
	// Persistent address data is scoped to the lifetime of a given Context, and subsquent calls to
	// [Context.Run] with the same address name will be silently ignored.
	Persistent map[string]any
	// Ephemeral address data is scoped to a given [Context.Run] call and is not persisted across
	// calls. This is used for protocols such as gRPC client/server streaming or GraphQL, where a
	// single request can incur multiple subrequests.
	Ephemeral map[string]any
	// Scope is the way to classify the different runs in the same context in order to have different
	// metrics.
	Scope Scope
}

func (d RunAddressData) isEmpty() bool {
	return len(d.Persistent) == 0 && len(d.Ephemeral) == 0
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
// Callers must check the returned [Result] object even when an error is returned, as the WAF might
// have been able to match some rules and generate events or actions before the error was reached;
// especially when the error is [errors.ErrTimeout].
func (context *Context) Run(addressData RunAddressData) (res Result, err error) {
	if addressData.isEmpty() {
		return
	}

	if addressData.Scope == "" {
		addressData.Scope = DefaultScope
	}

	defer func() {
		if err == errors.ErrTimeout {
			context.timeoutCount[addressData.Scope].Add(1)
		}
	}()

	// If the context has already timed out, we don't need to run the WAF again
	if context.timer.SumExhausted() {
		return Result{}, errors.ErrTimeout
	}

	runTimer, err := context.timer.NewNode(wafRunTag,
		timer.WithComponents(
			wafEncodeTag,
			wafDecodeTag,
			wafDurationTag,
		),
	)
	if err != nil {
		return Result{}, err
	}

	runTimer.Start()
	defer func() {
		context.metrics.add(addressData.Scope, wafRunTag, runTimer.Stop())
		context.metrics.merge(addressData.Scope, runTimer.Stats())
	}()

	wafEncodeTimer := runTimer.MustLeaf(wafEncodeTag)
	wafEncodeTimer.Start()
	persistentData, err := context.encodeOneAddressType(&context.pinner, addressData.Scope, addressData.Persistent, wafEncodeTimer)
	if err != nil {
		wafEncodeTimer.Stop()
		return res, err
	}

	// The WAF releases ephemeral address data at the max of each run call, so we need not keep the Go
	// values live beyond that in the same way we need for persistent data. We hence use a separate
	// encoder.
	var ephemeralPinner runtime.Pinner
	defer ephemeralPinner.Unpin()
	ephemeralData, err := context.encodeOneAddressType(&ephemeralPinner, addressData.Scope, addressData.Ephemeral, wafEncodeTimer)
	if err != nil {
		wafEncodeTimer.Stop()
		return res, err
	}

	wafEncodeTimer.Stop()

	// ddwaf_run cannot run concurrently and we are going to mutate the context.cgoRefs, so we need to
	// lock the context
	context.mutex.Lock()
	defer context.mutex.Unlock()

	if context.cContext == 0 {
		// Context has been closed, returning an empty result...
		return res, errors.ErrContextClosed
	}

	if runTimer.SumExhausted() {
		return res, errors.ErrTimeout
	}

	wafDecodeTimer := runTimer.MustLeaf(wafDecodeTag)
	res, err = context.run(persistentData, ephemeralData, wafDecodeTimer, runTimer.SumRemaining())

	runTimer.AddTime(wafDurationTag, res.TimeSpent)

	return
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
// top level object is a nil map, but this  behaviour is expected since either persistent or
// ephemeral addresses are allowed to be null one at a time. In this case, Encode will return nil,
// which is what we need to send to ddwaf_run to signal that the address data is empty.
func (context *Context) encodeOneAddressType(pinner pin.Pinner, scope Scope, addressData map[string]any, timer timer.Timer) (*bindings.WafObject, error) {
	encoder := newLimitedEncoder(pinner, timer)
	if addressData == nil {
		return nil, nil
	}

	data, _ := encoder.Encode(addressData)
	if len(encoder.truncations) > 0 {
		context.mutex.Lock()
		defer context.mutex.Unlock()

		context.truncations[scope] = merge(context.truncations[scope], encoder.truncations)
	}

	if timer.Exhausted() {
		return nil, errors.ErrTimeout
	}

	return data, nil
}

// run executes the ddwaf_run call with the provided data on this context. The caller is responsible for locking the
// context appropriately around this call.
func (context *Context) run(persistentData, ephemeralData *bindings.WafObject, wafDecodeTimer timer.Timer, timeBudget time.Duration) (Result, error) {
	result := new(bindings.WafResult)
	defer wafLib.WafResultFree(result)

	// The value of the timeout cannot exceed 2^55
	// cf. https://en.cppreference.com/w/cpp/chrono/duration
	timeout := uint64(timeBudget.Microseconds()) & 0x008FFFFFFFFFFFFF
	ret := wafLib.WafRun(context.cContext, persistentData, ephemeralData, result, timeout)

	wafDecodeTimer.Start()
	defer wafDecodeTimer.Stop()

	return unwrapWafResult(ret, result)
}

func unwrapWafResult(ret bindings.WafReturnCode, result *bindings.WafResult) (res Result, err error) {
	if result.Timeout > 0 {
		err = errors.ErrTimeout
	} else {
		// Derivatives can be generated even if no security event gets detected, so we decode them as long as the WAF
		// didn't timeout
		res.Derivatives, err = decodeMap(&result.Derivatives)
	}

	res.TimeSpent = time.Duration(result.TotalRuntime) * time.Nanosecond

	if ret == bindings.WafOK {
		return res, err
	}

	if ret != bindings.WafMatch {
		return res, goRunError(ret)
	}

	res.Events, err = decodeArray(&result.Events)
	if err != nil {
		return res, err
	}
	if size := result.Actions.NbEntries; size > 0 {
		res.Actions, err = decodeMap(&result.Actions)
		if err != nil {
			return res, err
		}
	}

	return res, err
}

// Close disposes of the underlying `ddwaf_context` and releases the associated
// internal data. It also decreases the reference count of the [Handle] which
// created this [Context], possibly releasing it completely (if this was the
// last [Context] created from it, and it is no longer in use by its creator).
func (context *Context) Close() {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	wafLib.WafContextDestroy(context.cContext)
	defer context.handle.Close() // Reduce the reference counter of the Handle.
	context.cContext = 0         // Makes it easy to spot use-after-free/double-free issues

	context.pinner.Unpin() // The pinned data is no longer needed, explicitly release
}

// Stats returns the cumulative time spent in various parts of the WAF, at
// nanosecond resolution, as well as the timeout value used, and other
// information about this [Context]'s usage.
func (context *Context) Stats() Stats {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	truncations := make(map[TruncationReason][]int, len(context.truncations[DefaultScope]))
	for reason, counts := range context.truncations[DefaultScope] {
		truncations[reason] = make([]int, len(counts))
		copy(truncations[reason], counts)
	}

	raspTruncations := make(map[TruncationReason][]int, len(context.truncations[RASPScope]))
	for reason, counts := range context.truncations[RASPScope] {
		raspTruncations[reason] = make([]int, len(counts))
		copy(raspTruncations[reason], counts)
	}

	var (
		timeoutDefault uint64
		timeoutRASP    uint64
	)

	if atomic, ok := context.timeoutCount[DefaultScope]; ok {
		timeoutDefault = atomic.Load()
	}

	if atomic, ok := context.timeoutCount[RASPScope]; ok {
		timeoutRASP = atomic.Load()
	}

	return Stats{
		Timers:           context.metrics.timers(),
		TimeoutCount:     timeoutDefault,
		TimeoutRASPCount: timeoutRASP,
		Truncations:      truncations,
		TruncationsRASP:  raspTruncations,
	}
}
