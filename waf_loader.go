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

	"github.com/ebitengine/purego"
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

type wafLoader struct {
	libLoader
}

func wafOpen() (*libLoader, error) {
	file, err := os.CreateTemp("", "libddwaf-*.so")
	if err != nil {
		return nil, fmt.Errorf("Error creating temp file: %w", err)
	}

	defer os.Remove(file.Name())

	if err := os.WriteFile(file.Name(), libddwaf, 0400); err != nil {
		return nil, fmt.Errorf("Error writing file: %w", err)
	}

	return dlOpen(file.Name(), wafSymbols)
}

func (loader *wafLoader) wafClose() {
	loader.libLoader.dlClose()
}

func (loader *wafLoader) wafGetVersion() string {
	versionCString, _, _ := purego.SyscallN(loader.GetSymbol("ddwaf_get_version"))
	return Gostring(versionCString)
}

func (loader *wafLoader) wafInit(obj *wafObject, config *wafConfig, info *wafRulesetInfo) wafHandle {
	handle, _, _ := purego.SyscallN(loader.GetSymbol("ddwaf_init"), uintptr(unsafe.Pointer(obj)), uintptr(unsafe.Pointer(config)), uintptr(unsafe.Pointer(info)))
	return wafHandle(handle)
}

func (loader *wafLoader) wafRulesetInfoFree(info *wafRulesetInfo) {
	purego.SyscallN(loader.GetSymbol("ddwaf_ruleset_info_free"), uintptr(unsafe.Pointer(info)))
}

func (loader *wafLoader) wafObjectFree(obj *wafObject) {
	purego.SyscallN(loader.GetSymbol("ddwaf_object_free"), uintptr(unsafe.Pointer(obj)))
}

func (loader *wafLoader) wafDestroy(handle wafHandle) {
	purego.SyscallN(loader.GetSymbol("ddwaf_destroy"), uintptr(handle))
}

func (loader *wafLoader) wafRequiredAddresses(handle wafHandle) []string {
	var nbAddresses uint32
	arrayVoidC, _, _ := purego.SyscallN(loader.GetSymbol("ddwaf_required_addresses"), uintptr(unsafe.Pointer(handle)), uintptr(unsafe.Pointer(&nbAddresses)))
	if arrayVoidC == 0 {
		return nil
	}

	addresses := make([]string, int(nbAddresses))
	for i := 0; i < int(nbAddresses); i++ {
		addresses[i] = Gostring(uintptr(unsafe.Add(unsafe.Pointer(arrayVoidC), uintptr(i))))
	}

	return addresses
}

func (loader *wafLoader) wafContextInit(handle wafHandle) wafContext {
	context, _, _ := purego.SyscallN(loader.GetSymbol("ddwaf_context_init"), uintptr(handle))
	return wafContext(context)
}

func (loader *wafLoader) wafContextDestroy(context wafContext) {
	purego.SyscallN(loader.GetSymbol("ddwaf_context_destroy"), uintptr(context))
}

func (loader *wafLoader) wafResultFree(result *wafResult) {
	purego.SyscallN(loader.GetSymbol("ddwaf_result_free"), uintptr(unsafe.Pointer(result)))
}

func (loader *wafLoader) wafRun(context wafContext, obj *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	ret, _, _ := purego.SyscallN(loader.GetSymbol("ddwaf_run"), uintptr(context), uintptr(unsafe.Pointer(obj)), uintptr(unsafe.Pointer(result)), uintptr(timeout))
	return wafReturnCode(ret)
}

// Gostring copies a char* to a Go string.
func Gostring(c uintptr) string {
	// We take the address and then dereference it to trick go vet from creating a possible misuse of unsafe.Pointer
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&c))
	if ptr == nil {
		return ""
	}
	var length int
	for {
		if *(*byte)(unsafe.Add(ptr, uintptr(length))) == '\x00' {
			break
		}
		length++
	}
	return string(unsafe.Slice((*byte)(ptr), length))
}

// Cstring converts a go string to *byte that can be passed to C code.
func Cstring(name string) *byte {
	// Has suffix
	if len(name) >= len("\x00") && name[len(name)-len("\x00"):] == "\x00" {
		return &(*(*[]byte)(unsafe.Pointer(&name)))[0]
	}
	var b = make([]byte, len(name)+1)
	copy(b, name)
	return &b[0]
}
