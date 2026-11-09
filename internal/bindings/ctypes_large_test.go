// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build amd64 || arm64

package bindings

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/unsafeutil"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

const (
	largeTestSize     = 70_000  // More than math.MaxUint16 items
	largeTestCapacity = 131_070 // Any capacity above the size works: 2 * (1<<16) - 2
)

// writeLargeHeader writes the header of a large array or map by hand, as
// libddwaf 2.1.0 and later do for containers with more than 65,535 items:
//
//	uint64_t type : 8, size : 28, capacity : 28; followed by the pointer.
//
// The caller owns the memory that ptr points to, and must keep it alive and
// pinned until the last use of obj.
func writeLargeHeader(obj *WAFObject, typ WAFObjectType, size, capacity uint64, ptr unsafe.Pointer) {
	clear(obj.data[:])
	binary.NativeEndian.PutUint64(obj.data[:wafObjectPtrOffset], uint64(typ)|size<<wafObjectLargeSizeShift|capacity<<36)
	unsafeutil.WritePtr(&obj.data[wafObjectPtrOffset], ptr)
}

// TestWAFObjectLargeContainers checks the decoding of the large array and
// large map layouts, with objects that Go memory backs. These objects are
// never passed to C: Go owns their memory, so they must never be destroyed
// with ddwaf_object_destroy.
func TestWAFObjectLargeContainers(t *testing.T) {
	// Runs after the last decode assertion, so that the backing arrays and the
	// string buffers they reference stay pinned for the whole test.
	var pinner runtime.Pinner
	defer pinner.Unpin()

	const longValue = "this value is longer than fourteen bytes"

	items := make([]WAFObject, largeTestSize, largeTestCapacity)
	for i := range items {
		items[i].SetUint(uint64(i))
	}
	items[0].SetString(&pinner, longValue)
	items[largeTestSize-1].SetString(&pinner, longValue+"-last")
	pinner.Pin(&items[0])

	kvs := make([]WAFObjectKV, largeTestSize, largeTestCapacity)
	for i := range kvs {
		kvs[i].Key.SetString(&pinner, fmt.Sprintf("k%d", i)) // 14 bytes or less: stored inline
		kvs[i].Val.SetUint(uint64(i))
	}
	kvs[largeTestSize-1].Val.SetString(&pinner, longValue+"-last")
	pinner.Pin(&kvs[0])

	var arr, mp WAFObject
	writeLargeHeader(&arr, WAFLargeArrayType, largeTestSize, largeTestCapacity, unsafe.Pointer(unsafe.SliceData(items)))
	writeLargeHeader(&mp, WAFLargeMapType, largeTestSize, largeTestCapacity, unsafe.Pointer(unsafe.SliceData(kvs)))

	// This is what the C compilers produce on the supported targets (little-endian
	// amd64 and arm64): type, then size at bit 8, then capacity at bit 36.
	require.Equal(t, []byte{0xa0, 0x70, 0x11, 0x01, 0xe0, 0xff, 0x1f, 0x00}, arr.data[:wafObjectPtrOffset])
	require.Equal(t, []byte{0xc0, 0x70, 0x11, 0x01, 0xe0, 0xff, 0x1f, 0x00}, mp.data[:wafObjectPtrOffset])

	t.Run("type", func(t *testing.T) {
		require.Equal(t, WAFObjectType(0xA0), WAFLargeArrayType)
		require.Equal(t, WAFObjectType(0xC0), WAFLargeMapType)
		require.Equal(t, WAFLargeArrayType, arr.Type())
		require.Equal(t, WAFLargeMapType, mp.Type())
		require.Equal(t, "large_array", arr.Type().String())
		require.Equal(t, "large_map", mp.Type().String())
	})

	t.Run("is", func(t *testing.T) {
		require.True(t, arr.IsArray())
		require.False(t, arr.IsMap())
		require.True(t, mp.IsMap())
		require.False(t, mp.IsArray())
		require.False(t, arr.IsString())
		require.False(t, mp.IsNil())
	})

	t.Run("ArrayValues", func(t *testing.T) {
		values, err := arr.ArrayValues()
		require.NoError(t, err)
		require.Len(t, values, largeTestSize)

		first, err := values[0].StringValue()
		require.NoError(t, err)
		require.Equal(t, longValue, first)

		middle, err := values[65_536].UIntValue()
		require.NoError(t, err)
		require.EqualValues(t, 65_536, middle)

		last, err := values[largeTestSize-1].StringValue()
		require.NoError(t, err)
		require.Equal(t, longValue+"-last", last)
	})

	t.Run("MapEntries", func(t *testing.T) {
		entries, err := mp.MapEntries()
		require.NoError(t, err)
		require.Len(t, entries, largeTestSize)

		key, err := entries[0].Key.StringValue()
		require.NoError(t, err)
		require.Equal(t, "k0", key)
		val, err := entries[0].Val.UIntValue()
		require.NoError(t, err)
		require.EqualValues(t, 0, val)

		key, err = entries[largeTestSize-1].Key.StringValue()
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("k%d", largeTestSize-1), key)
		last, err := entries[largeTestSize-1].Val.StringValue()
		require.NoError(t, err)
		require.Equal(t, longValue+"-last", last)
	})

	t.Run("ArrayValue and AnyValue", func(t *testing.T) {
		for name, decode := range map[string]func() (any, error){
			"ArrayValue": func() (any, error) { return arr.ArrayValue() },
			"AnyValue":   arr.AnyValue,
		} {
			t.Run(name, func(t *testing.T) {
				decoded, err := decode()
				require.NoError(t, err)
				slice, ok := decoded.([]any)
				require.True(t, ok, "got %T", decoded)
				require.Len(t, slice, largeTestSize)
				require.Equal(t, longValue, slice[0])
				require.EqualValues(t, 65_535, slice[65_535])
				require.Equal(t, longValue+"-last", slice[largeTestSize-1])
			})
		}
	})

	t.Run("MapValue and AnyValue", func(t *testing.T) {
		for name, decode := range map[string]func() (any, error){
			"MapValue": func() (any, error) { return mp.MapValue() },
			"AnyValue": mp.AnyValue,
		} {
			t.Run(name, func(t *testing.T) {
				decoded, err := decode()
				require.NoError(t, err)
				m, ok := decoded.(map[string]any)
				require.True(t, ok, "got %T", decoded)
				require.Len(t, m, largeTestSize)
				require.EqualValues(t, 0, m["k0"])
				require.EqualValues(t, 65_536, m["k65536"])
				require.Equal(t, longValue+"-last", m[fmt.Sprintf("k%d", largeTestSize-1)])
			})
		}
	})

	t.Run("sizes", func(t *testing.T) {
		// ArraySize and MapSize cannot return a size that does not fit a uint16.
		size, err := arr.ArraySize()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		require.Zero(t, size)

		size, err = mp.MapSize()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		require.Zero(t, size)

		// A large array is not a map, and the other way around.
		_, err = arr.MapSize()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		_, err = mp.ArraySize()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		_, err = arr.MapEntries()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		_, err = mp.ArrayValues()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
	})

	t.Run("SetArraySize and SetMapSize do not change large containers", func(t *testing.T) {
		arrBefore, mpBefore := arr.data, mp.data

		arr.SetArraySize(3)
		arr.SetMapSize(3)
		mp.SetArraySize(3)
		mp.SetMapSize(3)

		require.Equal(t, arrBefore, arr.data)
		require.Equal(t, mpBefore, mp.data)
	})

	t.Run("empty and nil pointer", func(t *testing.T) {
		var empty, bad WAFObject
		writeLargeHeader(&empty, WAFLargeArrayType, 0, 0, nil)
		values, err := empty.ArrayValues()
		require.NoError(t, err)
		require.Empty(t, values)

		// Never dereferenced: the pointer is nil.
		writeLargeHeader(&bad, WAFLargeMapType, largeTestSize, largeTestSize, nil)
		_, err = bad.MapEntries()
		require.Error(t, err)
	})

	runtime.KeepAlive(items)
	runtime.KeepAlive(kvs)
}

// TestWAFObjectCompactContainersUnchanged checks that the compact layout is
// still decoded and updated as before, including at the 65,535 items limit.
func TestWAFObjectCompactContainersUnchanged(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	const maxCompact = 1<<16 - 1

	var arr WAFObject
	items := arr.SetArray(&pinner, maxCompact)
	for i := range items {
		items[i].SetUint(uint64(i))
	}
	arr.SetArraySize(maxCompact)

	require.Equal(t, WAFArrayType, arr.Type())
	size, err := arr.ArraySize()
	require.NoError(t, err)
	require.EqualValues(t, maxCompact, size)
	values, err := arr.ArrayValues()
	require.NoError(t, err)
	require.Len(t, values, maxCompact)

	var mp WAFObject
	kvs := mp.SetMap(&pinner, maxCompact)
	for i := range kvs {
		kvs[i].Key.SetString(&pinner, "k")
		kvs[i].Val.SetUint(uint64(i))
	}
	mp.SetMapSize(maxCompact)

	require.Equal(t, WAFMapType, mp.Type())
	size, err = mp.MapSize()
	require.NoError(t, err)
	require.EqualValues(t, maxCompact, size)
	entries, err := mp.MapEntries()
	require.NoError(t, err)
	require.Len(t, entries, maxCompact)

	// A compact array is not a map, and the other way around.
	_, err = arr.MapSize()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
	_, err = mp.ArraySize()
	require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
}
