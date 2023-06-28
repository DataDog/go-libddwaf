// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"fmt"
	"os"
)

// wafDl is the type wrapper for all C calls to the waf
// It uses `libwaf` to make C calls
// All calls must go though this one liner to be type safe
// since purego calls are not type safe
type wafDl struct {
	libDl

	Ddwaf_ruleset_info_free  uintptr `dlsym:"ddwaf_ruleset_info_free"`
	Ddwaf_init               uintptr `dlsym:"ddwaf_init"`
	Ddwaf_destroy            uintptr `dlsym:"ddwaf_destroy"`
	Ddwaf_required_addresses uintptr `dlsym:"ddwaf_required_addresses"`
	Ddwaf_get_version        uintptr `dlsym:"ddwaf_get_version"`
	Ddwaf_context_init       uintptr `dlsym:"ddwaf_context_init"`
	Ddwaf_context_destroy    uintptr `dlsym:"ddwaf_context_destroy"`
	Ddwaf_result_free        uintptr `dlsym:"ddwaf_result_free"`
	Ddwaf_run                uintptr `dlsym:"ddwaf_run"`
}

func dumpWafLibrary() (*os.File, error) {
	file, err := os.CreateTemp("", "libddwaf-*.so")
	if err != nil {
		return nil, fmt.Errorf("Error creating temp file: %w", err)
	}

	if err := os.WriteFile(file.Name(), libddwaf, 0400); err != nil {
		return nil, fmt.Errorf("Error writing file: %w", err)
	}

	return file, nil
}

// newWafDl loads the waf shared library and loads all the needed symbols
func newWafDl() (_ *wafDl, err error) {
	file, err := dumpWafLibrary()
	if err != nil {
		return nil, err
	}

	defer func() {
		// TODO(eliott.bouhana): find a way to send to the tracer some non-fatal errors while opening the waf libg
		file.Close()
		os.Remove(file.Name())
	}()

	var waf wafDl

	if err := dlOpen(file.Name(), &waf); err != nil {
		return nil, fmt.Errorf("Error opening waf library: %w", err)
	}

	// try a call to the waf to make sure everything is fine
	if err := waf.tryCall(); err != nil {
		return nil, fmt.Errorf("test call in the C world failed: cannot load %s shared object. Reason: %v", file.Name(), err)
	}

	return &waf, nil
}

func (waf *wafDl) tryCall() (err any) {
	defer func() {
		err = recover()
	}()

	waf.wafGetVersion()
	return nil
}

// wafGetVersion returned string is a static string so we do not need to free it
func (waf *wafDl) wafGetVersion() string {
	return gostring(cast[byte](waf.syscall(waf.Ddwaf_get_version)))
}

func (waf *wafDl) wafInit(obj *wafObject, config *wafConfig, info *wafRulesetInfo) wafHandle {
	handle := wafHandle(waf.syscall(waf.Ddwaf_init, ptrToUintptr(obj), ptrToUintptr(config), ptrToUintptr(info)))
	keepAlive(obj)
	keepAlive(config)
	keepAlive(info)
	return handle
}

func (waf *wafDl) wafRulesetInfoFree(info *wafRulesetInfo) {
	waf.syscall(waf.Ddwaf_ruleset_info_free, ptrToUintptr(info))
	keepAlive(info)
}

func (waf *wafDl) wafDestroy(handle wafHandle) {
	waf.syscall(waf.Ddwaf_destroy, uintptr(handle))
	keepAlive(handle)
}

// wafRequiredAddresses returns static strings so we do not need to free them
func (waf *wafDl) wafRequiredAddresses(handle wafHandle) []string {
	var nbAddresses uint32

	arrayVoidC := waf.syscall(waf.Ddwaf_required_addresses, uintptr(handle), ptrToUintptr(&nbAddresses))
	if arrayVoidC == 0 {
		return nil
	}

	addresses := make([]string, int(nbAddresses))
	for i := 0; i < int(nbAddresses); i++ {
		addresses[i] = gostring(*castWithOffset[*byte](arrayVoidC, uint64(i)))
	}

	keepAlive(&nbAddresses)
	keepAlive(handle)

	return addresses
}

func (waf *wafDl) wafContextInit(handle wafHandle) wafContext {
	ctx := wafContext(waf.syscall(waf.Ddwaf_context_init, uintptr(handle)))
	keepAlive(handle)
	return ctx
}

func (waf *wafDl) wafContextDestroy(context wafContext) {
	waf.syscall(waf.Ddwaf_context_destroy, uintptr(context))
	keepAlive(context)
}

func (waf *wafDl) wafResultFree(result *wafResult) {
	waf.syscall(waf.Ddwaf_result_free, ptrToUintptr(result))
	keepAlive(result)
}

func (waf *wafDl) wafRun(context wafContext, obj *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	rc := wafReturnCode(waf.syscall(waf.Ddwaf_run, uintptr(context), ptrToUintptr(obj), ptrToUintptr(result), uintptr(timeout)))
	keepAlive(context)
	keepAlive(obj)
	keepAlive(result)
	keepAlive(timeout)
	return rc
}
