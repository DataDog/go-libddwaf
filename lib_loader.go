// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import (
	"fmt"

	"github.com/ebitengine/purego"
)

// libLoader is created to wraps all interactions with the purego library
type libLoader struct {
	handle uintptr
}

// dlOpen open a handle for the shared library `name`.
// the libLoader object is only a wrapped type for the linker handle
// The `symbolsNeeded` is the list of symbols needed in the lib to load.
// These symbols are returned via the map of symbols
func dlOpen(name string, symbolsNeeded []string) (*libLoader, map[string]uintptr, error) {
	handle, err := purego.Dlopen(name, purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return nil, nil, fmt.Errorf("Error opening shared library '%s'. Reason: %w", name, err)
	}

	symbols := make(map[string]uintptr, len(symbolsNeeded))
	loader := &libLoader{
		handle: handle,
	}

	for _, symbolName := range symbolsNeeded {
		symbols[symbolName], err = purego.Dlsym(handle, symbolName)
		if err != nil {
			return nil, nil, fmt.Errorf("Cannot load symbol '%s' from library '%s'. Reason: %w", symbolName, name, err)
		}
	}

	return loader, symbols, nil
}

// getSymbol reloads a symbol from the shared library
// if the uintptr symbol returned is 0 (nil), the error is a string given by dlerror()
func (loader *libLoader) getSymbol(name string) (uintptr, error) {
	return purego.Dlsym(loader.handle, name)
}

// syscall is the only way to make C calls with this interface.
// purego implementation limits the number of arguments to 9, it will panic if more are provided
// Note: `purego.SyscallN` has 3 return values: these are the following:
//
//	1st - The return value is a pointer or a int of any type
//	2nd - The return value is a float
//	3rd - The value of `errno` at the end of the call
func (loader *libLoader) syscall(fn uintptr, args ...uintptr) uintptr {
	ret, _, _ := purego.SyscallN(fn, args...)
	return ret
}

func (loader *libLoader) dlClose() {
	purego.Dlclose(loader.handle)
}
