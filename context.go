// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"github.com/DataDog/go-libddwaf/v2/timer"
	"sync"
	"time"

	"github.com/DataDog/go-libddwaf/v2/errors"
	"github.com/DataDog/go-libddwaf/v2/internal/bindings"
	"github.com/DataDog/go-libddwaf/v2/internal/unsafe"

	"go.uber.org/atomic"
)

// Context is a WAF execution context. It allows running the WAF incrementally
// when calling it multiple times to run its rules every time new addresses
// become available. Each request must have its own Context.
type Context struct {
	handle *Handle // Instance of the WAF

	cgoRefs  cgoRefPool          // Used to retain go data referenced by WAF Objects the context holds
	cContext bindings.WafContext // The C ddwaf_context pointer

	timeoutCount atomic.Uint64 // Cumulative timeout count for this context.

	// Mutex protecting the use of cContext which is not thread-safe and cgoRefs.
	mutex sync.Mutex

	// timer registers the time spent in the WAF and go-libddwaf
	timer timer.NodeTimer

	// stats stores the cumulative time spent in various parts of the WAF
	stats metrics
}

// NewContext returns a new WAF context of to the given WAF handle.
// A nil value is returned when the WAF handle was released or when the
// WAF context couldn't be created.
// handle. A nil value is returned when the WAF handle can no longer be used
// or the WAF context couldn't be created.
func NewContext(handle *Handle) *Context {
	return NewContextWithBudget(handle, timer.UnlimitedBudget)
}

// NewContextWithBudget returns a new WAF context of to the given WAF handle.
// A nil value is returned when the WAF handle was released or when the
// WAF context couldn't be created.
// handle. A nil value is returned when the WAF handle can no longer be used
// or the WAF context couldn't be created.
func NewContextWithBudget(handle *Handle, budget time.Duration) *Context {
	// Handle has been released
	if !handle.retain() {
		return nil
	}

	cContext := wafLib.WafContextInit(handle.cHandle)
	if cContext == 0 {
		handle.release() // We couldn't get a context, so we no longer have an implicit reference to the Handle in it...
		return nil
	}

	timer, err := timer.NewTreeTimer(timer.WithBudget(budget), timer.WithComponents("dd.appsec.waf.run"))
	if err != nil {
		return nil
	}

	return &Context{handle: handle, cContext: cContext, timer: timer, stats: metrics{data: make(map[string]time.Duration, 5)}}
}

// RunAddressData provides address data to the Context.Run method. If a given key is present in both
// RunAddressData.Persistent and RunAddressData.Ephemeral, the value from RunAddressData.Persistent will take precedence.
type RunAddressData struct {
	// Persistent address data is scoped to the lifetime of a given Context, and subsquent calls to Context.Run with the
	// same address name will be silently ignored.
	Persistent map[string]any
	// Ephemeral address data is scoped to a given Context.Run call and is not persisted across calls. This is used for
	// protocols such as gRPC client/server streaming or GraphQL, where a single request can incur multiple subrequests.
	Ephemeral map[string]any
}

func (d RunAddressData) isEmpty() bool {
	return len(d.Persistent) == 0 && len(d.Ephemeral) == 0
}

// Run encodes the given addressData values and runs them against the WAF rules within the given timeout value. If a
// given address is present both as persistent and ephemeral, the persistent value takes precedence. It returns the
// matches as a JSON string (usually opaquely used) along with the corresponding actions in any. In case of an error,
// matches and actions can still be returned, for instance in the case of a timeout error. Errors can be tested against
// the RunError type.
// Struct fields having the tag `ddwaf:"ignore"` will not be encoded and sent to the WAF
// if the output of TotalTime() exceeds the value of Timeout, the function will immediately return with errors.ErrTimeout
// The second parameter is deprecated and should be passed to NewContextWithBudget instead.
func (context *Context) Run(addressData RunAddressData, _ time.Duration) (res Result, err error) {
	if addressData.isEmpty() {
		return
	}

	defer func() {
		if err == errors.ErrTimeout {
			context.timeoutCount.Inc()
		}
	}()

	// If the context has already timed out, we don't need to run the WAF again
	if context.timer.SumExhausted() {
		return Result{}, errors.ErrTimeout
	}

	runTimer, err := context.timer.NewNode("dd.appsec.waf.run",
		timer.WithComponents(
			"dd.appsec.waf.encode.persistent",
			"dd.appsec.waf.encode.ephemeral",
			"dd.appsec.waf.duration_ext",
			"dd.appsec.waf.duration",
		),
	)
	if err != nil {
		return Result{}, err
	}

	runTimer.Start()
	defer func() {
		context.stats.add("dd.appsec.waf.run", runTimer.Stop())
		context.stats.merge(runTimer.Stats())
	}()

	persistentData, persistentEncoder, err := encodeOneAddressType(addressData.Persistent, runTimer.MustLeaf("dd.appsec.waf.encode.persistent"))
	if err != nil {
		return res, err
	}

	// The WAF releases ephemeral address data at the max of each run call, so we need not keep the Go values live beyond
	// that in the same way we need for persistent data. We hence use a separate encoder.
	ephemeralData, ephemeralEncoder, err := encodeOneAddressType(addressData.Ephemeral, runTimer.MustLeaf("dd.appsec.waf.encode.ephemeral"))
	if err != nil {
		return res, err
	}

	// ddwaf_run cannot run concurrently and we are going to mutate the context.cgoRefs, so we need to lock the context
	context.mutex.Lock()
	defer context.mutex.Unlock()

	if runTimer.SumExhausted() {
		return res, errors.ErrTimeout
	}

	// Save the Go pointer references to addressesToData that were referenced by the encoder
	// into C ddwaf_objects. libddwaf's API requires to keep this data for the lifetime of the ddwaf_context.
	defer context.cgoRefs.append(persistentEncoder.cgoRefs)

	wafExtTimer := runTimer.MustLeaf("dd.appsec.waf.duration_ext")
	res, err = context.run(persistentData, ephemeralData, wafExtTimer, runTimer.SumRemaining())

	runTimer.AddTime("dd.appsec.waf.duration", res.TimeSpent)

	// Ensure the ephemerals don't get optimized away by the compiler before the WAF had a chance to use them.
	unsafe.KeepAlive(ephemeralEncoder.cgoRefs)
	unsafe.KeepAlive(persistentEncoder.cgoRefs)

	res.Truncations = merge(persistentEncoder.Truncations(), ephemeralEncoder.Truncations())
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

// encodeOneAddressType encodes the given addressData values and returns the corresponding WAF object and its refs.
// If the addressData is empty, it returns nil for the WAF object and an empty ref pool.
// At this point, if the encoder does not timeout, the only error we can get is an error in case the top level object
// is a nil map, but this  behaviour is expected since either persistent or ephemeral addresses are allowed to be null
// one at a time. In this case, EncodeAddresses will return nil contrary to Encode which will return a nil wafObject,
// which is what we need to send to ddwaf_run to signal that the address data is empty.
func encodeOneAddressType(addressData map[string]any, timer timer.Timer) (*bindings.WafObject, encoder, error) {
	encoder := newLimitedEncoder(timer)
	if addressData == nil {
		return nil, encoder, nil
	}

	data, _ := encoder.EncodeAddresses(addressData)
	if timer.Exhausted() {
		return nil, encoder, errors.ErrTimeout
	}

	return data, encoder, nil
}

// run executes the ddwaf_run call with the provided data on this context. The caller is responsible for locking the
// context appropriately around this call.
func (context *Context) run(persistentData, ephemeralData *bindings.WafObject, wafTimer timer.Timer, timeBudget time.Duration) (Result, error) {
	result := new(bindings.WafResult)
	defer wafLib.WafResultFree(result)

	wafTimer.Start()
	defer wafTimer.Stop()

	// The value of the timeout cannot exceed 2^55
	// cf. https://en.cppreference.com/w/cpp/chrono/duration
	timeout := uint64(timeBudget.Microseconds()) & 0x008FFFFFFFFFFFFF
	ret := wafLib.WafRun(context.cContext, persistentData, ephemeralData, result, timeout)

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
		// using ruleIdArray cause it decodes string array (I think)
		res.Actions, err = decodeStringArray(&result.Actions)
		// TODO: use decode array, and eventually genericize the function
		if err != nil {
			return res, err
		}
	}

	res.TimeSpent = time.Duration(result.TotalRuntime)
	return res, err
}

// Close the underlying `ddwaf_context` and releases the associated internal
// data. Also decreases the reference count of the `ddwaf_hadnle` which created
// this context, possibly releasing it completely (if this was the last context
// created from this handle & it was released by its creator).
func (context *Context) Close() {
	context.mutex.Lock()
	defer context.mutex.Unlock()

	wafLib.WafContextDestroy(context.cContext)
	unsafe.KeepAlive(context.cgoRefs) // Keep the Go pointer references until the max of the context
	defer context.handle.release()    // Reduce the reference counter of the Handle.

	context.cgoRefs = cgoRefPool{} // The data in context.cgoRefs is no longer needed, explicitly release
	context.cContext = 0           // Makes it easy to spot use-after-free/double-free issues
}

// TotalRuntime returns the cumulated WAF runtime across various run calls within the same WAF context.
// Returned time is in nanoseconds.
// Deprecated: use Timings instead
func (context *Context) TotalRuntime() (uint64, uint64) {
	return uint64(context.stats.get("dd.appsec.waf.run") * time.Nanosecond), uint64(context.stats.get("dd.appsec.waf.duration"))
}

// TotalTimeouts returns the cumulated amount of WAF timeouts across various run calls within the same WAF context.
// Deprecated: use Timings instead
func (context *Context) TotalTimeouts() uint64 {
	return context.timeoutCount.Load()
}

// Stats returns the cumulative time spent in various parts of the WAF, all in nanoseconds
// and the timeout value used
func (context *Context) Stats() map[string]time.Duration {
	return context.stats.copy()
}

type metrics struct {
	data  map[string]time.Duration
	mutex sync.RWMutex
}

func (metrics *metrics) add(key string, duration time.Duration) {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.data == nil {
		metrics.data = make(map[string]time.Duration, 5)
	}

	metrics.data[key] += duration
}

func (metrics *metrics) get(key string) time.Duration {
	metrics.mutex.RLock()
	defer metrics.mutex.RUnlock()
	return metrics.data[key]
}

func (metrics *metrics) copy() map[string]time.Duration {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.data == nil {
		return nil
	}

	copy := make(map[string]time.Duration, len(metrics.data))
	for k, v := range metrics.data {
		copy[k] = v
	}
	return copy
}

// merge merges the current metrics with the new run
func (metrics *metrics) merge(other map[string]time.Duration) {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.data == nil {
		metrics.data = make(map[string]time.Duration, 5)
	}

	for key, val := range other {
		prev, ok := metrics.data[key]
		if !ok {
			prev = 0
		}
		metrics.data[key] = prev + val
	}
}
