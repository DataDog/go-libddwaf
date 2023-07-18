// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !go1.21

package waf

import (
	"os"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/require"
)

func getLibddwaf(t *testing.T) uintptr {
	file, err := os.CreateTemp("", "libddwaf-*.so")
	require.NoError(t, err)

	defer os.Remove(file.Name())

	err = os.WriteFile(file.Name(), libddwaf, 0400)
	require.NoError(t, err)

	lib, err := purego.Dlopen(file.Name(), purego.RTLD_GLOBAL|purego.RTLD_NOW)
	require.NoError(t, err)

	return lib
}

func getSymbol(t *testing.T, lib uintptr, symbol string) uintptr {
	sym, err := purego.Dlsym(lib, symbol)
	require.NoError(t, err)
	return sym
}

func TestWafObject(t *testing.T) {
	lib := getLibddwaf(t)

	t.Run("invalid", func(t *testing.T) {
		var actual wafObject
		expected := wafObject{
			_type: wafInvalidType,
		}
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_invalid"), uintptr(unsafe.Pointer(&actual)))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, expected, actual)
	})

	t.Run("int", func(t *testing.T) {
		var actual wafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_signed_force"), uintptr(unsafe.Pointer(&actual)), 42)
		require.NotEqualValues(t, 0, r1)
		require.EqualValues(t, 42, actual.value)
		require.EqualValues(t, wafIntType, actual._type)
	})

	t.Run("uint", func(t *testing.T) {
		var actual wafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_unsigned_force"), uintptr(unsafe.Pointer(&actual)), 42)
		require.NotEqualValues(t, 0, r1)
		require.EqualValues(t, 42, actual.value)
		require.EqualValues(t, wafUintType, actual._type)
	})

	t.Run("string", func(t *testing.T) {
		var actual wafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual)), uintptr(unsafe.Pointer(cstring("toto"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto", gostring(cast[byte](actual.value)))
		require.EqualValues(t, wafStringType, actual._type)
	})

	t.Run("padding", func(t *testing.T) {
		var actual [3]wafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual[0])), uintptr(unsafe.Pointer(cstring("toto1"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto1", gostring(cast[byte](actual[0].value)))
		require.EqualValues(t, wafStringType, actual[0]._type)
		r1, _, _ = purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual[1])), uintptr(unsafe.Pointer(cstring("toto2"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto2", gostring(cast[byte](actual[1].value)))
		require.EqualValues(t, wafStringType, actual[1]._type)
		r1, _, _ = purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), uintptr(unsafe.Pointer(&actual[2])), uintptr(unsafe.Pointer(cstring("toto3"))))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto3", gostring(cast[byte](actual[2].value)))
		require.EqualValues(t, wafStringType, actual[2]._type)
	})

	require.NoError(t, purego.Dlclose(lib))
}
