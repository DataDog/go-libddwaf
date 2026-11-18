// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package bindings

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/DataDog/go-libddwaf/v5/internal/unsafeutil"
)

// systemInfo is the SYSTEM_INFO structure of the Windows API.
type systemInfo struct {
	ProcessorArchitecture     uint16
	_                         uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

// pageSize returns the real page size of the system. The Getpagesize functions
// of the standard library and of x/sys/windows always return 4096 on Windows.
func pageSize() int {
	var info systemInfo
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemInfo")
	// GetSystemInfo has no result and cannot fail.
	_, _, _ = proc.Call(uintptr(unsafe.Pointer(&info)))
	return int(info.PageSize)
}

// TestStringValueCopiesFromUnmappedMemory runs the unmapped-memory cases with
// memory from VirtualAlloc, and releases it with VirtualFree (MEM_RELEASE).
func TestStringValueCopiesFromUnmappedMemory(t *testing.T) {
	testStringValueCopiesFromUnmappedMemory(t, func(t *testing.T, size int) ([]byte, func()) {
		length := max(size, pageSize())
		addr, err := windows.VirtualAlloc(0, uintptr(length), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		require.NoError(t, err)
		mem := unsafeutil.Slice(unsafeutil.Cast[byte](addr), uint64(length))
		// With MEM_RELEASE, the size must be 0: Windows releases the whole region.
		return mem, func() { require.NoError(t, windows.VirtualFree(addr, 0, windows.MEM_RELEASE)) }
	})
}
