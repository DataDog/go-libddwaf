// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"fmt"

	"github.com/ebitengine/purego"
)

type libcDl struct {
	libDl

	Libc_malloc uintptr `dlsym:"malloc"`
	Libc_calloc uintptr `dlsym:"calloc"`
	Libc_free   uintptr `dlsym:"free"`
	Libc_strlen uintptr `dlsym:"strlen"`
}

func newLibcDl() (*libcDl, error) {
	var libc libcDl

	// RTLD_DEFAULT is a pseudo-handle to search symbols from any already loaded library
	if err := dlOpenFromHandle(purego.RTLD_DEFAULT, &libc); err != nil {
		return nil, fmt.Errorf("Reading libc symbols: %w", err)
	}

	return &libc, nil
}

func (lib *libcDl) malloc(size uint64) uintptr {
	return lib.syscall(lib.Libc_malloc, uintptr(size))
}

func (lib *libcDl) calloc(num, objSize uint64) uintptr {
	return lib.syscall(lib.Libc_calloc, uintptr(num), uintptr(objSize))
}

func (lib *libcDl) free(ptr uintptr) {
	lib.syscall(lib.Libc_free, ptr)
}

func (lib *libcDl) strlen(str uintptr) uint64 {
	return uint64(lib.syscall(lib.Libc_strlen, str))
}
