// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"sync"
	"time"

	"go.uber.org/atomic"
)

// Context is a WAF execution context.
// It's a wrapper over the void * the WAF returns with ddwaf_context_init()
// We store in there:
// * A mutex to order calls to ddwaf_run()
// * The handle it was created with
// * cgoRefs to keep references to the go waf objects we sent
// * A number of metrics
type Context struct {
	// Instance of the WAF
	handle   *Handle
	cContext wafContext

	// Mutex protecting the use of context which is not thread-safe.
	mutex sync.Mutex

	// cgoRefs is used to retain go references to WafObjects until the context is destroyed.
	// As per libddwaf documentation, WAF Objects must be alive during all the context lifetime
	cgoRefs cgoRefPool

	// Stats
	// Cumulated internal WAF run time - in nanoseconds - for this context.
	totalRuntimeNs atomic.Uint64
	// Cumulated overall run time - in nanoseconds - for this context.
	totalOverallRuntimeNs atomic.Uint64
	// Cumulated timeout count for this context.
	timeoutCount atomic.Uint64
}

// Run encodes the input data to send it to the WAF and returns the return values of ddwaf_run()
// The parameters are the following:
// * addressesToData: a map of key WAF addresses to the user input. The user input can be any go type.
// * timeout: a timeout value to run the waf. If the threshold is exceeded, ddwaf_run will return without completing everything
// The return values are the following:
// * matches: A json string directly sent by the WAF containing all the data necessary for the backend
// * actions: A array of string referencing actions from triggered rules (`on_match` rule field)
// * err: a RunError error from the error codes the WAF returns
func (context *Context) Run(addressesToData map[string]any, timeout time.Duration) (matches []byte, actions []string, err error) {
	if len(addressesToData) == 0 {
		return
	}

	now := time.Now()
	defer func() {
		dt := time.Since(now)
		context.totalOverallRuntimeNs.Add(uint64(dt.Nanoseconds()))
	}()

	encoder := encoder{
		stringMaxSize:    wafMaxStringLength,
		containerMaxSize: wafMaxContainerSize,
		objectMaxDepth:   wafMaxContainerDepth,
	}
	obj, err := encoder.Encode(addressesToData)
	if err != nil {
		return nil, nil, err
	}

	// ddwaf_run cannot run concurrently and the next append write on the context state so we need a mutex
	context.mutex.Lock()
	defer context.mutex.Unlock()
	defer context.cgoRefs.append(encoder.cgoRefs)

	return context.run(obj, timeout, &encoder.cgoRefs)
}

func (context *Context) run(obj *wafObject, timeout time.Duration, cgoRefs *cgoRefPool) ([]byte, []string, error) {
	// RLock the handle to safely get read access to the WAF handle and prevent concurrent changes of it
	// such as a rules-data update.
	context.handle.mutex.RLock()
	defer context.handle.mutex.RUnlock()

	var result wafResult
	defer func() {
		wafLib.wafResultFree(&result)

		// Force everything on the heap and prevent and early GC during C calls
		keepAlive(obj)
		keepAlive(&result)
		cgoRefs.KeepAlive()
	}()

	ret := wafLib.wafRun(context.cContext, obj, &result, uint64(timeout/time.Microsecond))

	context.totalRuntimeNs.Add(result.total_runtime)
	matches, actions, err := unwrapWafResult(ret, &result)
	if err == ErrTimeout {
		context.timeoutCount.Inc()
	}

	return matches, actions, err
}

func unwrapWafResult(ret wafReturnCode, result *wafResult) (matches []byte, actions []string, err error) {
	if result.timeout > 0 {
		err = ErrTimeout
	}

	if ret == wafOK {
		return nil, nil, err
	}

	if ret != wafMatch {
		return nil, nil, goRunError(ret)
	}

	if result.data != 0 {
		matches = []byte(gostring(cast[byte](result.data)))
	}

	if size := result.actions.size; size > 0 {
		actions = decodeActions(result.actions.array, uint64(size))
	}

	return matches, actions, err
}

// Close calls handle.closeContext which calls ddwaf_context_destroy and maybe also close the handle if it in termination state.
func (context *Context) Close() {
	// Needed to make sure the garbage collector does not throw the values send to the WAF earlier than necessary
	context.cgoRefs.KeepAlive()
	context.handle.closeContext(context)
}

// TotalRuntime returns the cumulated WAF runtime across various run calls within the same WAF context.
// Returned time is in nanoseconds.
func (context *Context) TotalRuntime() (overallRuntimeNs, internalRuntimeNs uint64) {
	return context.totalOverallRuntimeNs.Load(), context.totalRuntimeNs.Load()
}

// TotalTimeouts returns the cumulated amount of WAF timeouts across various run calls within the same WAF context.
func (context *Context) TotalTimeouts() uint64 {
	return context.timeoutCount.Load()
}
