// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build amd64 || arm64

package bindings

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// TestWAFObjectSize checks Size on compact and large containers. The large
// objects are backed by Go memory and are never passed to C.
func TestWAFObjectSize(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	t.Run("compact array", func(t *testing.T) {
		items := make([]WAFObject, 3, 10)
		var obj WAFObject
		require.NoError(t, obj.SetArrayData(&pinner, items))
		require.Equal(t, WAFArrayType, obj.Type())

		size, err := obj.Size()
		require.NoError(t, err)
		require.EqualValues(t, 3, size)
		runtime.KeepAlive(items)
	})

	t.Run("compact map", func(t *testing.T) {
		entries := make([]WAFObjectKV, 5)
		var obj WAFObject
		require.NoError(t, obj.SetMapData(&pinner, entries))
		require.Equal(t, WAFMapType, obj.Type())

		size, err := obj.Size()
		require.NoError(t, err)
		require.EqualValues(t, 5, size)
		runtime.KeepAlive(entries)
	})

	t.Run("empty containers", func(t *testing.T) {
		for name, set := range map[string]func(*WAFObject){
			"array": func(o *WAFObject) { o.SetArray(&pinner, 0) },
			"map":   func(o *WAFObject) { o.SetMap(&pinner, 0) },
		} {
			t.Run(name, func(t *testing.T) {
				var obj WAFObject
				set(&obj)
				size, err := obj.Size()
				require.NoError(t, err)
				require.Zero(t, size)
			})
		}
	})

	t.Run("large array", func(t *testing.T) {
		items := make([]WAFObject, largeTestSize, largeTestCapacity)
		var obj WAFObject
		require.NoError(t, obj.SetArrayData(&pinner, items))
		require.Equal(t, WAFLargeArrayType, obj.Type())

		size, err := obj.Size()
		require.NoError(t, err)
		require.EqualValues(t, largeTestSize, size)
		runtime.KeepAlive(items)
	})

	t.Run("large map", func(t *testing.T) {
		entries := make([]WAFObjectKV, largeTestSize, largeTestCapacity)
		var obj WAFObject
		require.NoError(t, obj.SetMapData(&pinner, entries))
		require.Equal(t, WAFLargeMapType, obj.Type())

		size, err := obj.Size()
		require.NoError(t, err)
		require.EqualValues(t, largeTestSize, size)
		runtime.KeepAlive(entries)
	})

	t.Run("large containers with no item", func(t *testing.T) {
		// libddwaf can make a large container with a large capacity and no item.
		for name, typ := range map[string]WAFObjectType{"array": WAFLargeArrayType, "map": WAFLargeMapType} {
			t.Run(name, func(t *testing.T) {
				var obj WAFObject
				writeLargeHeader(&obj, typ, 0, largeTestCapacity, unsafe.Pointer(nil))
				size, err := obj.Size()
				require.NoError(t, err)
				require.Zero(t, size)
			})
		}
	})

	t.Run("largest size", func(t *testing.T) {
		// Only the header is built: no memory is backing the items.
		var obj WAFObject
		writeLargeHeader(&obj, WAFLargeArrayType, MaxLargeContainerSize, MaxLargeContainerSize, unsafe.Pointer(nil))
		size, err := obj.Size()
		require.NoError(t, err)
		require.EqualValues(t, MaxLargeContainerSize, size)
	})

	t.Run("not a container", func(t *testing.T) {
		var invalid, nilObj, str, number WAFObject
		nilObj.SetNil()
		str.SetString(&pinner, "a string that is longer than fourteen bytes")
		number.SetInt(42)

		for name, obj := range map[string]*WAFObject{"invalid": &invalid, "nil type": &nilObj, "string": &str, "int": &number} {
			t.Run(name, func(t *testing.T) {
				size, err := obj.Size()
				require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
				require.Zero(t, size)
			})
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var obj *WAFObject
		size, err := obj.Size()
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		require.Zero(t, size)
	})
}
