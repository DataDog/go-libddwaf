// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"runtime"
	"testing"

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
}

func TestWAFObjectArrayValuesError(t *testing.T) {
	var obj WAFObject
	obj.SetInt(42)

	_, err := obj.ArrayValues()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
}

func TestWAFObjectMapEntriesError(t *testing.T) {
	var obj WAFObject
	obj.SetInt(42)

	_, err := obj.MapEntries()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
}
