// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"sync"

	"go.uber.org/atomic"
)

type Handle struct {
	cLibrary       *wafDl
	cHandle        wafHandle
	mutex          sync.RWMutex
	contextCounter atomic.Uint32
	//TODO: add ddwaf_init related data (like RulesetInfo)
}

// TODO Add NewHandleFromRuleset
// Set default value of contextCounter to 1 for defer closing
func NewHandle(rulesJson []byte, keyObfuscatorRegex string, valueObfuscatorRegex string) (*Handle, error) {
	return nil, nil
}

func (handle *Handle) NewContext() *Context {
	handle.contextCounter.Inc()
	return nil
}

// CloseContext call ddwaf_context_destroy and eventually ddwaf_destroy on the handle
func (handle *Handle) CloseContext(context *Context) {
	handle.cLibrary.wafContextDestroy(context.cContext)
	if handle.contextCounter.Dec() == 0 {
		handle.cLibrary.wafDestroy(handle.cHandle)
		handle.cLibrary.Close()
	}
}

// Close put the handle in termination state, when all the contexts are close the handle will be destroyed
func (handle *Handle) Close() {
	if handle.contextCounter.Dec() == 0 {
		handle.cLibrary.wafDestroy(handle.cHandle)
		handle.cLibrary.Close()
	}
}

func (handle *Handle) RequiredAddresses() []string {
	return handle.cLibrary.wafRequiredAddresses(handle.cHandle)
}
