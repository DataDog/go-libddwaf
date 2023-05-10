// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import (
	"fmt"
	"os"
	"unsafe"
)

// wafLoader is the type wrapper for all C calls to the waf
// It uses `libLoader` to make C calls
// All calls must go though this one liner to be type safe
// since purego calls are not type safe
type wafLoader struct {
	LibLoader

	Ddwaf_ruleset_info_free  uintptr `dlsym:"ddwaf_ruleset_info_free"`
	Ddwaf_init               uintptr `dlsym:"ddwaf_init"`
	Ddwaf_object_free        uintptr `dlsym:"ddwaf_object_free"`
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

// newWafLoader loads the waf shared library and loads all the needed symbols
func newWafLoader() (*wafLoader, error) {
	file, err := dumpWafLibrary()
	if err != nil {
		return nil, err
	}

	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()

	var loader wafLoader
	if err := dlOpen(file.Name(), &loader); err != nil {
		return nil, fmt.Errorf("Error opening waf library: %w", err)
	}

	// try a call to the waf to make sure everything is fine
	if err := loader.tryCall(); err != nil {
		return nil, fmt.Errorf("test call in the C world failed: cannot load %s shared object. Reason: %v", file.Name(), err)
	}

	return &loader, nil
}

func (loader *wafLoader) tryCall() (err any) {
	defer func() {
		err = recover()
	}()

	loader.wafGetVersion()
	return nil
}

// wafGetVersion returned string is a static string so we do not need to free it
func (loader *wafLoader) wafGetVersion() string {
	return gostring(loader.syscall(loader.Ddwaf_get_version))
}

func (loader *wafLoader) wafInit(obj *wafObject, config *wafConfig, info *wafRulesetInfo) wafHandle {
	return wafHandle(loader.syscall(loader.Ddwaf_init, uintptr(unsafe.Pointer(obj)), uintptr(unsafe.Pointer(config)), uintptr(unsafe.Pointer(info))))
}

func (loader *wafLoader) wafRulesetInfoFree(info *wafRulesetInfo) {
	loader.syscall(loader.Ddwaf_ruleset_info_free, uintptr(unsafe.Pointer(info)))
}

func (loader *wafLoader) wafObjectFree(obj *wafObject) {
	loader.syscall(loader.Ddwaf_object_free, uintptr(unsafe.Pointer(obj)))
}

func (loader *wafLoader) wafDestroy(handle wafHandle) {
	loader.syscall(loader.Ddwaf_destroy, uintptr(handle))
}

// wafRequiredAddresses returns statis strings so we do not need to free them
func (loader *wafLoader) wafRequiredAddresses(handle wafHandle) []string {
	var nbAddresses uint32
	arrayVoidC := loader.syscall(loader.Ddwaf_required_addresses, uintptr(handle), uintptr(unsafe.Pointer(&nbAddresses)))
	if arrayVoidC == 0 {
		return nil
	}

	addresses := make([]string, int(nbAddresses))
	for i := 0; i < int(nbAddresses); i++ {
		addresses[i] = gostring(uintptr(unsafe.Add(unsafe.Pointer(arrayVoidC), uintptr(i))))
	}

	return addresses
}

func (loader *wafLoader) wafContextInit(handle wafHandle) wafContext {
	return wafContext(loader.syscall(loader.Ddwaf_context_init, uintptr(handle)))
}

func (loader *wafLoader) wafContextDestroy(context wafContext) {
	loader.syscall(loader.Ddwaf_context_destroy, uintptr(context))
}

func (loader *wafLoader) wafResultFree(result *wafResult) {
	loader.syscall(loader.Ddwaf_result_free, uintptr(unsafe.Pointer(result)))
}

func (loader *wafLoader) wafRun(context wafContext, obj *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	return wafReturnCode(loader.syscall(loader.Ddwaf_run, uintptr(context), uintptr(unsafe.Pointer(obj)), uintptr(unsafe.Pointer(result)), uintptr(timeout)))
}
