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

var wafSymbols = []string{
	"ddwaf_ruleset_info_free",
	"ddwaf_init",
	"ddwaf_object_free",
	"ddwaf_destroy",
	"ddwaf_required_addresses",
	"ddwaf_get_version",
	"ddwaf_context_init",
	"ddwaf_context_destroy",
	"ddwaf_result_free",
	"ddwaf_run",
}

// wafLoader is the type wrapper for all C calls to the waf
// It uses `libLoader` to make C calls
// All calls must go though this one liner to be type safe
// since purego calls are not type safe
type wafLoader struct {
	libLoader

	ddwaf_ruleset_info_free  uintptr
	ddwaf_init               uintptr
	ddwaf_object_free        uintptr
	ddwaf_destroy            uintptr
	ddwaf_required_addresses uintptr
	ddwaf_get_version        uintptr
	ddwaf_context_init       uintptr
	ddwaf_context_destroy    uintptr
	ddwaf_result_free        uintptr
	ddwaf_run                uintptr
}

// newWafLoader loads the waf shared library and loads all the needed symbols
func newWafLoader() (*wafLoader, error) {
	file, err := os.CreateTemp("", "libddwaf-*.so")
	if err != nil {
		return nil, fmt.Errorf("Error creating temp file: %w", err)
	}

	defer os.Remove(file.Name())

	if err := os.WriteFile(file.Name(), libddwaf, 0400); err != nil {
		return nil, fmt.Errorf("Error writing file: %w", err)
	}

	lib, symbols, err := dlOpen(file.Name(), wafSymbols)
	if err != nil {
		return nil, fmt.Errorf("Error opening waf library: %w", err)
	}

	waf := &wafLoader{
		libLoader:                *lib,
		ddwaf_ruleset_info_free:  symbols["ddwaf_ruleset_info_free"],
		ddwaf_init:               symbols["ddwaf_init"],
		ddwaf_object_free:        symbols["ddwaf_object_free"],
		ddwaf_destroy:            symbols["ddwaf_destroy"],
		ddwaf_required_addresses: symbols["ddwaf_required_addresses"],
		ddwaf_get_version:        symbols["ddwaf_get_version"],
		ddwaf_context_init:       symbols["ddwaf_context_init"],
		ddwaf_context_destroy:    symbols["ddwaf_context_destroy"],
		ddwaf_result_free:        symbols["ddwaf_result_free"],
		ddwaf_run:                symbols["ddwaf_run"],
	}

	// try a call to the waf to make sure everything is fine
	if waf.syscall(waf.ddwaf_get_version) == 0 {
		return nil, fmt.Errorf("Test call in the C world failed: cannot load %s shared object", file.Name())
	}

	return waf, nil
}

func (loader *wafLoader) wafGetVersion() string {
	return gostring(loader.syscall(loader.ddwaf_get_version))
}

func (loader *wafLoader) wafInit(obj *wafObject, config *wafConfig, info *wafRulesetInfo) wafHandle {
	return wafHandle(loader.syscall(loader.ddwaf_init, uintptr(unsafe.Pointer(obj)), uintptr(unsafe.Pointer(config)), uintptr(unsafe.Pointer(info))))
}

func (loader *wafLoader) wafRulesetInfoFree(info *wafRulesetInfo) {
	loader.syscall(loader.ddwaf_ruleset_info_free, uintptr(unsafe.Pointer(info)))
}

func (loader *wafLoader) wafObjectFree(obj *wafObject) {
	loader.syscall(loader.ddwaf_object_free, uintptr(unsafe.Pointer(obj)))
}

func (loader *wafLoader) wafDestroy(handle wafHandle) {
	loader.syscall(loader.ddwaf_destroy, uintptr(handle))
}

func (loader *wafLoader) wafRequiredAddresses(handle wafHandle) []string {
	var nbAddresses uint32
	arrayVoidC := loader.syscall(loader.ddwaf_required_addresses, uintptr(handle), uintptr(unsafe.Pointer(&nbAddresses)))
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
	return wafContext(loader.syscall(loader.ddwaf_context_init, uintptr(handle)))
}

func (loader *wafLoader) wafContextDestroy(context wafContext) {
	loader.syscall(loader.ddwaf_context_destroy, uintptr(context))
}

func (loader *wafLoader) wafResultFree(result *wafResult) {
	loader.syscall(loader.ddwaf_result_free, uintptr(unsafe.Pointer(result)))
}

func (loader *wafLoader) wafRun(context wafContext, obj *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	return wafReturnCode(loader.syscall(loader.ddwaf_run, uintptr(context), uintptr(unsafe.Pointer(obj)), uintptr(unsafe.Pointer(result)), uintptr(timeout)))
}
