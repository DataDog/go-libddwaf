// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !go1.24 && !datadog.no_waf && (cgo || appsec)

package waf

import (
	"testing"

	"github.com/DataDog/go-libddwaf/v3/internal/bindings"
	"github.com/DataDog/go-libddwaf/v3/internal/unsafe"

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

	lib := wafLib.Handle()

	t.Run("invalid", func(t *testing.T) {
		var actual bindings.WafObject
		expected := bindings.WafObject{
			Type: bindings.WafInvalidType,
		}
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_invalid"), unsafe.PtrToUintptr(&actual))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, expected, actual)
	})

	t.Run("int", func(t *testing.T) {
		var actual bindings.WafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_signed"), unsafe.PtrToUintptr(&actual), 42)
		require.NotEqualValues(t, 0, r1)
		require.EqualValues(t, 42, actual.Value)
		require.EqualValues(t, bindings.WafIntType, actual.Type)
	})

	t.Run("uint", func(t *testing.T) {
		var actual bindings.WafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_unsigned"), unsafe.PtrToUintptr(&actual), 42)
		require.NotEqualValues(t, 0, r1)
		require.EqualValues(t, 42, actual.Value)
		require.EqualValues(t, bindings.WafUintType, actual.Type)
	})

	t.Run("string", func(t *testing.T) {
		var actual bindings.WafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), unsafe.PtrToUintptr[bindings.WafObject](&actual), unsafe.PtrToUintptr[byte](unsafe.Cstring("toto")))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto", unsafe.Gostring(unsafe.Cast[byte](actual.Value)))
		require.EqualValues(t, bindings.WafStringType, actual.Type)
	})

	t.Run("padding", func(t *testing.T) {
		var actual [3]bindings.WafObject
		r1, _, _ := purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), unsafe.PtrToUintptr(&actual[0]), unsafe.PtrToUintptr(unsafe.Cstring("toto1")))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto1", unsafe.Gostring(unsafe.Cast[byte](actual[0].Value)))
		require.EqualValues(t, bindings.WafStringType, actual[0].Type)
		r1, _, _ = purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), unsafe.PtrToUintptr(&actual[1]), unsafe.PtrToUintptr(unsafe.Cstring("toto2")))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto2", unsafe.Gostring(unsafe.Cast[byte](actual[1].Value)))
		require.EqualValues(t, bindings.WafStringType, actual[1].Type)
		r1, _, _ = purego.SyscallN(getSymbol(t, lib, "ddwaf_object_string"), unsafe.PtrToUintptr(&actual[2]), unsafe.PtrToUintptr(unsafe.Cstring("toto3")))
		require.NotEqualValues(t, 0, r1)
		require.Equal(t, "toto3", unsafe.Gostring(unsafe.Cast[byte](actual[2].Value)))
		require.EqualValues(t, bindings.WafStringType, actual[2].Type)
	})
}
