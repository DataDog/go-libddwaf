// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"sync"
	"time"

	"go.uber.org/atomic"
)

// TODO: temps d'execution
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

	context.allocator.append(encoder.allocator)

	return context.run(obj, timeout)
}

func (context *Context) run(obj *wafObject, timeout time.Duration) ([]byte, []string, error) {
	return nil, nil, nil
}

// Close calls handle.CloseContext which calls ddwaf_context_destroy
func (context *Context) Close() {
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
