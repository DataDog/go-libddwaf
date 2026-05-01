// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"encoding/binary"
	"runtime"
	"testing"
	"unsafe"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/require"
)

// TestWAFObjectStringRoundTrip verifies that encoding and decoding strings through
// WAFObject preserves the original values for all string types.
func TestWAFObjectStringRoundTrip(t *testing.T) {
	t.Run("small string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "hello")
		require.Equal(t, WAFSmallStringType, obj.Type())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "hello", val)
	})

	t.Run("regular string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		longStr := "this string is longer than fourteen bytes"
		obj.SetString(&pinner, longStr)
		require.Equal(t, WAFStringType, obj.Type())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, longStr, val)
	})

	t.Run("literal string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		litStr := "this literal is longer than fourteen bytes"
		obj.SetLiteralString(&pinner, litStr)
		require.Equal(t, WAFLiteralStringType, obj.Type())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, litStr, val)
	})

	t.Run("empty string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "")
		require.True(t, obj.IsString())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "", val)
	})

	t.Run("empty literal string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetLiteralString(&pinner, "")
		require.Equal(t, WAFLiteralStringType, obj.Type())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "", val)
	})

	t.Run("14 byte boundary", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "12345678901234")
		require.Equal(t, WAFSmallStringType, obj.Type())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "12345678901234", val)
	})

	t.Run("15 byte boundary", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "123456789012345")
		require.Equal(t, WAFStringType, obj.Type())

		val, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "123456789012345", val)
	})
}

func TestWAFObjectStringMatches(t *testing.T) {
	t.Run("small string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "timeout")

		match, err := obj.StringMatches("timeout")
		require.NoError(t, err)
		require.True(t, match)

		match, err = obj.StringMatches("keep")
		require.NoError(t, err)
		require.False(t, match)
	})

	t.Run("regular string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "ruleset_version")

		match, err := obj.StringMatches("ruleset_version")
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("literal string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetLiteralString(&pinner, "processor_overrides")

		match, err := obj.StringMatches("processor_overrides")
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("empty string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "")

		match, err := obj.StringMatches("")
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("non string", func(t *testing.T) {
		var obj WAFObject
		obj.SetBool(true)

		match, err := obj.StringMatches("timeout")
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		require.False(t, match)
	})

	t.Run("malformed small string metadata", func(t *testing.T) {
		var obj WAFObject
		obj.setType(WAFSmallStringType)
		obj.data[wafObjectSStrSize] = wafObjectSStrMaxLen + 1

		match, err := obj.StringMatches("timeout")
		require.Error(t, err)
		require.Contains(t, err.Error(), "small string size")
		require.False(t, match)
	})
}

// TestWAFObjectArrayRoundTrip verifies array encode/decode round-trips for both
// SetArray (allocate+fill) and SetArrayData (pre-existing slice) paths.
func TestWAFObjectArrayRoundTrip(t *testing.T) {
	t.Run("SetArray", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var arr WAFObject
		items := arr.SetArray(&pinner, 3)
		require.Len(t, items, 3)

		items[0].SetInt(10)
		items[1].SetInt(20)
		items[2].SetInt(30)
		arr.SetArraySize(3)

		values, err := arr.ArrayValues()
		require.NoError(t, err)
		require.Len(t, values, 3)

		for i, v := range values {
			val, err := v.IntValue()
			require.NoError(t, err)
			require.EqualValues(t, (i+1)*10, val)
		}
	})

	t.Run("SetArrayData", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		data := make([]WAFObject, 3)
		data[0].SetInt(100)
		data[1].SetInt(200)
		data[2].SetInt(300)

		var arr WAFObject
		err := arr.SetArrayData(&pinner, data)
		require.NoError(t, err)

		values, err := arr.ArrayValues()
		require.NoError(t, err)
		require.Len(t, values, 3)

		for i, v := range values {
			val, err := v.IntValue()
			require.NoError(t, err)
			require.EqualValues(t, (i+1)*100, val)
		}
	})

	t.Run("empty array", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var arr WAFObject
		items := arr.SetArray(&pinner, 0)
		require.Nil(t, items)

		size, err := arr.ArraySize()
		require.NoError(t, err)
		require.EqualValues(t, 0, size)

		values, err := arr.ArrayValues()
		require.NoError(t, err)
		require.Nil(t, values)
	})

	t.Run("ArrayValue recursive decode", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var arr WAFObject
		items := arr.SetArray(&pinner, 2)
		items[0].SetInt(42)
		items[1].SetString(&pinner, "hi")
		arr.SetArraySize(2)

		result, err := arr.ArrayValue()
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.EqualValues(t, 42, result[0])
		require.Equal(t, "hi", result[1])
	})
}

// TestWAFObjectMapRoundTrip verifies map encode/decode round-trips for both
// SetMap (allocate+fill) and SetMapData (pre-existing slice) paths.
func TestWAFObjectMapRoundTrip(t *testing.T) {
	t.Run("SetMap", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var m WAFObject
		kvs := m.SetMap(&pinner, 2)
		require.Len(t, kvs, 2)

		kvs[0].Key.SetString(&pinner, "key1")
		kvs[0].Val.SetInt(1)
		kvs[1].Key.SetString(&pinner, "key2")
		kvs[1].Val.SetInt(2)
		m.SetMapSize(2)

		entries, err := m.MapEntries()
		require.NoError(t, err)
		require.Len(t, entries, 2)

		k0, err := entries[0].Key.StringValue()
		require.NoError(t, err)
		require.Equal(t, "key1", k0)
		v0, err := entries[0].Val.IntValue()
		require.NoError(t, err)
		require.EqualValues(t, 1, v0)
	})

	t.Run("SetMapData", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		data := make([]WAFObjectKV, 2)
		data[0].Key.SetString(&pinner, "a")
		data[0].Val.SetBool(true)
		data[1].Key.SetString(&pinner, "b")
		data[1].Val.SetBool(false)

		var m WAFObject
		err := m.SetMapData(&pinner, data)
		require.NoError(t, err)

		entries, err := m.MapEntries()
		require.NoError(t, err)
		require.Len(t, entries, 2)

		k0, err := entries[0].Key.StringValue()
		require.NoError(t, err)
		require.Equal(t, "a", k0)
		v0, err := entries[0].Val.BoolValue()
		require.NoError(t, err)
		require.True(t, v0)

		k1, err := entries[1].Key.StringValue()
		require.NoError(t, err)
		require.Equal(t, "b", k1)
		v1, err := entries[1].Val.BoolValue()
		require.NoError(t, err)
		require.False(t, v1)
	})

	t.Run("empty map", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var m WAFObject
		kvs := m.SetMap(&pinner, 0)
		require.Nil(t, kvs)

		size, err := m.MapSize()
		require.NoError(t, err)
		require.EqualValues(t, 0, size)

		entries, err := m.MapEntries()
		require.NoError(t, err)
		require.Nil(t, entries)
	})

	t.Run("MapValue recursive decode", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var m WAFObject
		kvs := m.SetMap(&pinner, 2)
		kvs[0].Key.SetString(&pinner, "x")
		kvs[0].Val.SetFloat(3.14)
		kvs[1].Key.SetString(&pinner, "y")
		kvs[1].Val.SetUint(99)
		m.SetMapSize(2)

		result, err := m.MapValue()
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.InDelta(t, 3.14, result["x"], 0.001)
		require.EqualValues(t, uint64(99), result["y"])
	})
}

func TestWAFObjectStringValueError(t *testing.T) {
	var obj WAFObject
	obj.SetInt(42)

	_, err := obj.StringValue()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)

	obj.setType(WAFSmallStringType)
	obj.data[wafObjectSStrSize] = wafObjectSStrMaxLen + 1

	_, err = obj.StringValue()
	require.Error(t, err)
	require.Contains(t, err.Error(), "small string size")
}

func TestWAFObjectArrayValuesError(t *testing.T) {
	var obj WAFObject
	obj.SetInt(42)

	_, err := obj.ArrayValues()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)

	obj.setType(WAFArrayType)
	binary.NativeEndian.PutUint16(obj.data[wafObjectContainerSizeOffset:], 2)
	binary.NativeEndian.PutUint16(obj.data[wafObjectContainerCapacityOffset:], 1)

	_, err = obj.ArrayValues()
	require.Error(t, err)
	require.Contains(t, err.Error(), "array size 2 exceeds capacity 1")
}

func TestWAFObjectMapEntriesError(t *testing.T) {
	var obj WAFObject
	obj.SetInt(42)

	_, err := obj.MapEntries()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)

	obj.setType(WAFMapType)
	binary.NativeEndian.PutUint16(obj.data[wafObjectContainerSizeOffset:], 2)
	binary.NativeEndian.PutUint16(obj.data[wafObjectContainerCapacityOffset:], 1)

	_, err = obj.MapEntries()
	require.Error(t, err)
	require.Contains(t, err.Error(), "map size 2 exceeds capacity 1")
}

// TestWAFObjectAlignment verifies that WAFObject has at least 8-byte alignment,
// matching the C union it represents. Without proper alignment, pointer operations
// at byte offset 8 (where the C union stores pointers, int64, uint64, float64)
// cause "checkptr: misaligned pointer conversion" under -race.
func TestWAFObjectAlignment(t *testing.T) {
	const pointerAlignment = unsafe.Sizeof(uintptr(0)) // 8 on 64-bit

	t.Run("WAFObject", func(t *testing.T) {
		require.GreaterOrEqual(t, unsafe.Alignof(WAFObject{}), pointerAlignment,
			"WAFObject must be pointer-aligned to match C union layout")
		require.Equal(t, uintptr(16), unsafe.Sizeof(WAFObject{}),
			"WAFObject size must remain 16 bytes")
	})

	t.Run("WAFObjectKV", func(t *testing.T) {
		require.GreaterOrEqual(t, unsafe.Alignof(WAFObjectKV{}), pointerAlignment,
			"WAFObjectKV must be pointer-aligned")
		require.Equal(t, uintptr(32), unsafe.Sizeof(WAFObjectKV{}),
			"WAFObjectKV size must remain 32 bytes")
	})

	t.Run("stack allocation alignment", func(t *testing.T) {
		var obj WAFObject
		addr := uintptr(unsafe.Pointer(&obj))
		require.Zero(t, addr%pointerAlignment,
			"stack-allocated WAFObject at %#x is not %d-byte aligned", addr, pointerAlignment)
	})

	t.Run("slice element alignment", func(t *testing.T) {
		objs := make([]WAFObject, 3)
		for i := range objs {
			addr := uintptr(unsafe.Pointer(&objs[i]))
			require.Zero(t, addr%pointerAlignment,
				"slice element [%d] at %#x is not %d-byte aligned", i, addr, pointerAlignment)
		}
	})

	t.Run("pointer field offset alignment", func(t *testing.T) {
		// The pointer/value field is at byte 8 within the WAFObject.
		// If WAFObject is N-byte aligned and N >= 8, then data[8] is also 8-byte aligned.
		var obj WAFObject
		ptrFieldAddr := uintptr(unsafe.Pointer(&obj.data[wafObjectPtrOffset]))
		require.Zero(t, ptrFieldAddr%pointerAlignment,
			"pointer field at data[%d] (addr %#x) is not %d-byte aligned",
			wafObjectPtrOffset, ptrFieldAddr, pointerAlignment)
	})
}
