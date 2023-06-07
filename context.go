// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"go.uber.org/atomic"
	"runtime"
	"sync"
	"time"
)

// Context is a WAF execution context.
type Context struct {
	handle    *Handle
	cContext  wafContext
	mutex     sync.Mutex
	allocator allocator

	// Stats
	// Cumulated internal WAF run time - in nanoseconds - for this context.
	totalRuntimeNs atomic.Uint64
	// Cumulated overall run time - in nanoseconds - for this context.
	totalOverallRuntimeNs atomic.Uint64
	// Cumulated timeout count for this context.
	timeoutCount atomic.Uint64
}

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
	defer context.allocator.append(encoder.allocator)

	return context.run(obj, timeout, &encoder.allocator)
}

func (context *Context) run(obj *wafObject, timeout time.Duration, allocator *allocator) ([]byte, []string, error) {
	// RLock the handle to safely get read access to the WAF handle and prevent concurrent changes of it
	// such as a rules-data update.
	context.handle.mutex.RLock()
	defer context.handle.mutex.RUnlock()

	result := new(wafResult)
	defer wafLib.wafResultFree(result)

	ret := wafLib.wafRun(context.cContext, obj, result, uint64(timeout/time.Microsecond))
	// Needed to prevent the GC
	allocator.KeepAlive()
	runtime.KeepAlive(obj)

	context.totalRuntimeNs.Add(result.total_runtime)
	matches, actions, err := unwrapWafResult(ret, result)
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
		matches = []byte(gostring(result.data))
	}

	if size := result.actions.size; size > 0 {
		actions = decodeActions(result.actions.array, size)
	}

	return matches, actions, err
}

// Close calls handle.CloseContext which calls ddwaf_context_destroy
func (context *Context) Close() {
	// Needed to make sure the garbage collector does not throw the values send to the WAF
	// earlier than necessary
	context.allocator.KeepAlive()
	context.handle.CloseContext(context)
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
