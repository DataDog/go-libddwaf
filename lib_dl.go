// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import (
	"fmt"
	"reflect"

	"github.com/ebitengine/purego"
)

// libDl is created to wraps all interactions with the purego library
type libDl struct {
	handle uintptr
}

// dlOpen open a handle for the shared library `name`.
// the libLoader object is only a wrapped type for the linker handle
// the `loader` parameter must have tags in the form of `dlsym:<symbol_name>`
// dlOpen will fill the object with symbols loaded from the library
// the struct of type `loader` must have a field of type `LibLoader`
// to be able to close the handle later
func dlOpen(name string, loader any) error {
	handle, err := purego.Dlopen(name, purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return fmt.Errorf("error opening shared library '%s'. Reason: %w", name, err)
	}

	foundHandle := false

	libValue := reflect.ValueOf(lib).Elem()
	libType := reflect.TypeOf(lib).Elem()
	liblib := &libDl{handle: handle}

	for i := 0; i < libValue.NumField(); i++ {
		fieldType := libType.Field(i)

		symbolName, ok := fieldType.Tag.Lookup("dlsym")
		if ok {
			symbol, err := purego.Dlsym(handle, symbolName)
			if err != nil {
				return fmt.Errorf("cannot load symbol '%s' from library '%s'. Reason: %w", symbolName, name, err)
			}

			libValue.Field(i).Set(reflect.ValueOf(symbol))
			continue
		}

		if fieldType.Type == reflect.TypeOf(liblib).Elem() {
			libValue.Field(i).Set(reflect.ValueOf(liblib).Elem())
			foundHandle = true
		}
	}

	if !foundHandle {
		return fmt.Errorf("could not find `libLoader` embedding to set the library handle, cowardly refusing the handle to be lost")
	}

	return nil
}

// syscall is the only way to make C calls with this interface.
// purego implementation limits the number of arguments to 9, it will panic if more are provided
// Note: `purego.SyscallN` has 3 return values: these are the following:
//
//	1st - The return value is a pointer or a int of any type
//	2nd - The return value is a float
//	3rd - The value of `errno` at the end of the call
func (lib *libDl) syscall(fn uintptr, args ...uintptr) uintptr {
	ret, _, _ := purego.SyscallN(fn, args...)
	return ret
}

func (lib *libDl) Close() error {
	return purego.Dlclose(lib.handle)
}
