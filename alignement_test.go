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

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"

	"github.com/stretchr/testify/require"
)

// TestWAFObjectSize verifies that our WAFObject struct matches the v2 16-byte size
func TestWAFObjectSize(t *testing.T) {
	_, err := Load()
	require.NoError(t, err)

	require.Equal(t, 16, int(unsafe.Sizeof(bindings.WAFObject{})), "WAFObject must be 16 bytes")
	require.Equal(t, 32, int(unsafe.Sizeof(bindings.WAFObjectKV{})), "WAFObjectKV must be 32 bytes")
}

// TestWAFObjectSetAndGet tests that our Go methods correctly encode and decode values
func TestWAFObjectSetAndGet(t *testing.T) {
	_, err := Load()
	require.NoError(t, err)

	t.Run("invalid", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetInvalid()
		require.True(t, obj.IsInvalid())
		require.Equal(t, bindings.WAFInvalidType, obj.Type())
	})

	t.Run("nil", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetNil()
		require.True(t, obj.IsNil())
		require.Equal(t, bindings.WAFNilType, obj.Type())
	})

	t.Run("bool true", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetBool(true)
		require.True(t, obj.IsBool())
		require.Equal(t, bindings.WAFBoolType, obj.Type())
		val, err := obj.BoolValue()
		require.NoError(t, err)
		require.True(t, val)
	})

	t.Run("bool false", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetBool(false)
		require.True(t, obj.IsBool())
		val, err := obj.BoolValue()
		require.NoError(t, err)
		require.False(t, val)
	})

	t.Run("int", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetInt(42)
		require.True(t, obj.IsInt())
		require.Equal(t, bindings.WAFIntType, obj.Type())
		val, err := obj.IntValue()
		require.NoError(t, err)
		require.EqualValues(t, 42, val)
	})

	t.Run("int negative", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetInt(-12345)
		require.True(t, obj.IsInt())
		val, err := obj.IntValue()
		require.NoError(t, err)
		require.EqualValues(t, -12345, val)
	})

	t.Run("uint", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetUint(42)
		require.True(t, obj.IsUint())
		require.Equal(t, bindings.WAFUintType, obj.Type())
		val, err := obj.UIntValue()
		require.NoError(t, err)
		require.EqualValues(t, 42, val)
	})

	t.Run("float", func(t *testing.T) {
		var obj bindings.WAFObject
		obj.SetFloat(3.14159)
		require.True(t, obj.IsFloat())
		require.Equal(t, bindings.WAFFloatType, obj.Type())
		val, err := obj.FloatValue()
		require.NoError(t, err)
		require.InDelta(t, 3.14159, val, 0.00001)
	})

	t.Run("small string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj bindings.WAFObject
		// Small string <= 14 bytes should use small string optimization
		obj.SetString(&pinner, "hello")
		require.True(t, obj.IsString())
		require.Equal(t, bindings.WAFSmallStringType, obj.Type())
		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "hello", val)
	})

	t.Run("regular string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj bindings.WAFObject
		// String > 14 bytes should use regular string type
		longStr := "this is a long string that exceeds 14 bytes"
		obj.SetString(&pinner, longStr)
		require.True(t, obj.IsString())
		require.Equal(t, bindings.WAFStringType, obj.Type())
		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, longStr, val)
	})

	t.Run("empty string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj bindings.WAFObject
		obj.SetString(&pinner, "")
		require.True(t, obj.IsString())
		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "", val)
	})
}

// TestWAFObjectArrayPadding tests that arrays of WAFObjects work correctly
func TestWAFObjectArrayPadding(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var objects [3]bindings.WAFObject

	objects[0].SetString(&pinner, "first")
	objects[1].SetInt(42)
	objects[2].SetBool(true)

	// Verify each object is properly set
	require.True(t, objects[0].IsString())
	str, err := objects[0].StringValue()
	require.NoError(t, err)
	require.Equal(t, "first", str)

	require.True(t, objects[1].IsInt())
	i, err := objects[1].IntValue()
	require.NoError(t, err)
	require.EqualValues(t, 42, i)

	require.True(t, objects[2].IsBool())
	b, err := objects[2].BoolValue()
	require.NoError(t, err)
	require.True(t, b)
}

// TestWAFObjectKVPadding tests that arrays of WAFObjectKV work correctly
func TestWAFObjectKVPadding(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var kvs [2]bindings.WAFObjectKV

	kvs[0].Key.SetString(&pinner, "key1")
	kvs[0].Val.SetInt(100)

	kvs[1].Key.SetString(&pinner, "key2")
	kvs[1].Val.SetString(&pinner, "value2")

	// Verify first KV pair
	key1, err := kvs[0].Key.StringValue()
	require.NoError(t, err)
	require.Equal(t, "key1", key1)

	val1, err := kvs[0].Val.IntValue()
	require.NoError(t, err)
	require.EqualValues(t, 100, val1)

	// Verify second KV pair
	key2, err := kvs[1].Key.StringValue()
	require.NoError(t, err)
	require.Equal(t, "key2", key2)

	val2, err := kvs[1].Val.StringValue()
	require.NoError(t, err)
	require.Equal(t, "value2", val2)
}

// TestWAFObjectContainers tests array and map container functionality
func TestWAFObjectContainers(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	t.Run("array", func(t *testing.T) {
		var arr bindings.WAFObject
		items := arr.SetArray(&pinner, 3)
		require.Len(t, items, 3)

		items[0].SetInt(1)
		items[1].SetInt(2)
		items[2].SetInt(3)
		arr.SetArraySize(3)

		require.True(t, arr.IsArray())
		require.Equal(t, bindings.WAFArrayType, arr.Type())

		size, err := arr.ArraySize()
		require.NoError(t, err)
		require.EqualValues(t, 3, size)

		values, err := arr.ArrayValues()
		require.NoError(t, err)
		require.Len(t, values, 3)

		for i, v := range values {
			val, err := v.IntValue()
			require.NoError(t, err)
			require.EqualValues(t, i+1, val)
		}
	})

	t.Run("map", func(t *testing.T) {
		var m bindings.WAFObject
		kvs := m.SetMap(&pinner, 2)
		require.Len(t, kvs, 2)

		kvs[0].Key.SetString(&pinner, "a")
		kvs[0].Val.SetInt(1)
		kvs[1].Key.SetString(&pinner, "b")
		kvs[1].Val.SetInt(2)
		m.SetMapSize(2)

		require.True(t, m.IsMap())
		require.Equal(t, bindings.WAFMapType, m.Type())

		size, err := m.MapSize()
		require.NoError(t, err)
		require.EqualValues(t, 2, size)

		entries, err := m.MapEntries()
		require.NoError(t, err)
		require.Len(t, entries, 2)

		// Verify map can be converted to Go map
		goMap, err := m.MapValue()
		require.NoError(t, err)
		require.EqualValues(t, 1, goMap["a"])
		require.EqualValues(t, 2, goMap["b"])
	})
}
