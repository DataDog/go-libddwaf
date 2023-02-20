// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && !windows && (amd64 || arm64) && (linux || darwin)

package waf

import (
	"fmt"
	"unsafe"
	"os"

	"github.com/ebitengine/purego"

	vendor "github.com/DataDog/go-libddwaf/lib/darwin-arm64"
)

var dlState struct {
	symbolCache map[string]uintptr
	libddwaf uintptr
	opened bool
} = struct {
	symbolCache map[string]uintptr
	libddwaf uintptr
	opened bool
}{
	symbolCache: make(map[string]uintptr),
	libddwaf: 0,
	opened: false,
}

// goString copies a char* to a Go string.
func goString(c uintptr) string {
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

// cString converts a go string to *byte that can be passed to C code.
func cString(name string) *byte {
	// Has suffix
	if len(name) >= len("\x00") && name[len(name)-len("\x00"):] == "\x00" {
		return &(*(*[]byte)(unsafe.Pointer(&name)))[0]
	}
	var b = make([]byte, len(name)+1)
	copy(b, name)
	return &b[0]
}

// Using the embeded shared library file, we dump it into a file and load it using dlopen
func loadLib() (uintptr, error) {
	
	file, err := os.CreateTemp("dd", "libddwaf")
	if err != nil {
		return uintptr(0), err
	}

	if err := os.WriteFile(file.Name(), vendor.Libddwaf, 0400); err != nil {
		return uintptr(0), err
	}

	lib := purego.Dlopen(file.Name(), purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err := purego.Dlerror(); err != "" {
		return uintptr(0), fmt.Errorf("Error opening shared library at path '%s'. Reason: %s", file.Name(), err)
	}

	return lib, nil
}

// Main utility load library and symbols, also maintains a symbols cache
// TODO, make it thread safe
func getSymbol(symbolName string) uintptr {
	if !dlState.opened {
		lib, err := loadLib()
		if err != nil {
			panic(err)
		}

		dlState.libddwaf = lib
		dlState.opened = true
	}

	if symbol, ok := dlState.symbolCache[symbolName]; ok {
		return symbol
	}

	symbol := purego.Dlsym(dlState.libddwaf, symbolName)
	dlState.symbolCache[symbolName] = symbol
	return symbol
}

func Health() error {
	return nil
}

func Version() string {
	symbol := getSymbol("ddwaf_get_version")
	r1, _, _ := purego.SyscallN(symbol)
	return goString(r1)
}