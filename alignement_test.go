// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/ffi"

	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/require"
)

func getSymbol(t *testing.T, lib uintptr, symbol string) uintptr {
	sym, err := purego.Dlsym(lib, symbol)
	require.NoError(t, err)
	return sym
}

func TestWafObject(t *testing.T) {
	_, err := Load()
	require.NoError(t, err)

	lib := bindings.Lib.Handle()

	t.Run("invalid", func(t *testing.T) {
		var actual bindings.WAFObject
		expected := bindings.WAFObject{
			Type: bindings.WAFInvalidType,
		}
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_invalid"), uintptr(unsafe.Pointer(&actual)))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, expected, actual)
	})

	t.Run("int", func(t *testing.T) {
		var actual bindings.WAFObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_signed"), uintptr(unsafe.Pointer(&actual)), 42)
		require.NotEqualValues(t, 0, r1)
		require.EqualValues(t, 42, actual.Value)
		require.EqualValues(t, bindings.WAFIntType, actual.Type)
	})

	t.Run("uint", func(t *testing.T) {
		var actual bindings.WAFObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_unsigned"), uintptr(unsafe.Pointer(&actual)), 42)
		require.NotEqualValues(t, 0, r1)
		require.EqualValues(t, 42, actual.Value)
		require.EqualValues(t, bindings.WAFUintType, actual.Type)
	})

	t.Run("string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var actual bindings.WAFObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual)), uintptr(unsafe.Pointer(ffi.Cstring(&pinner, "toto"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto", ffi.Gostring(ffi.Cast[byte](actual.Value)))
		require.EqualValues(t, bindings.WAFStringType, actual.Type)
	})

	t.Run("padding", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var actual [3]bindings.WAFObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual[0])), uintptr(unsafe.Pointer(ffi.Cstring(&pinner, "toto1"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto1", ffi.Gostring(ffi.Cast[byte](actual[0].Value)))
		require.EqualValues(t, bindings.WAFStringType, actual[0].Type)
		r1, _, _ = purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual[1])), uintptr(unsafe.Pointer(ffi.Cstring(&pinner, "toto2"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto2", ffi.Gostring(ffi.Cast[byte](actual[1].Value)))
		require.EqualValues(t, bindings.WAFStringType, actual[1].Type)
		r1, _, _ = purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual[2])), uintptr(unsafe.Pointer(ffi.Cstring(&pinner, "toto3"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto3", ffi.Gostring(ffi.Cast[byte](actual[2].Value)))
		require.EqualValues(t, bindings.WAFStringType, actual[2].Type)
	})
}
