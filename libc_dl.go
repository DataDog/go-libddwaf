// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import (
	"fmt"
	"unsafe"
)

type libcDl struct {
	libDl

	Libc_malloc uintptr `dlsym:malloc`
	Libc_free   uintptr `dlsym:free`
}

func newLibcDl() (*libcDl, error) {
	var libc libcDl

	// libc.so.6 is already loaded so it's cheap
	if err := dlOpen("libc.so.6", &libc); err != nil {
		return nil, fmt.Errorf("Error opening libc library: %w", err)
	}

	return &libc, nil
}

func (lib *libcDl) malloc(size uint) unsafe.Pointer {
	return unsafe.Pointer(lib.syscall(lib.Libc_malloc, uintptr(size)))
}

func (lib *libcDl) free(ptr unsafe.Pointer) {
	lib.syscall(lib.Libc_free, uintptr(ptr))
}
