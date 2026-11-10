// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/unsafeutil"
)

// legacyCompactHeader is a copy of the compact writer that SetArrayData and
// SetMapData used before they could write the large layout. It must not follow
// the code under test: it is the reference for "the compact bytes did not change".
func legacyCompactHeader(obj *WAFObject, typ WAFObjectType, length, capacity int, ptr unsafe.Pointer) {
	clear(obj.data[:])
	obj.setType(typ)
	binary.NativeEndian.PutUint16(obj.data[wafObjectContainerSizeOffset:], uint16(length))
	binary.NativeEndian.PutUint16(obj.data[wafObjectContainerCapacityOffset:], uint16(capacity))
	unsafeutil.WritePtr(&obj.data[wafObjectPtrOffset], ptr)
}

// TestSetContainerDataCompactUnchanged checks that every input which
// SetArrayData and SetMapData accepted before gives the same 16 bytes now.
func TestSetContainerDataCompactUnchanged(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	for _, length := range []int{1, 255, 256, 65_534, 65_535} {
		capacities := []int{length}
		if length != math.MaxUint16 {
			capacities = append(capacities, math.MaxUint16)
		}
		for _, capacity := range capacities {
			t.Run(fmt.Sprintf("array/len=%d/cap=%d", length, capacity), func(t *testing.T) {
				data := make([]WAFObject, length, capacity)
				var got, want WAFObject
				require.NoError(t, got.SetArrayData(&pinner, data))
				legacyCompactHeader(&want, WAFArrayType, length, capacity, unsafe.Pointer(&data[0]))
				require.Equal(t, want.data, got.data, "the compact array header must not change")
				runtime.KeepAlive(data)
			})
			t.Run(fmt.Sprintf("map/len=%d/cap=%d", length, capacity), func(t *testing.T) {
				data := make([]WAFObjectKV, length, capacity)
				var got, want WAFObject
				require.NoError(t, got.SetMapData(&pinner, data))
				legacyCompactHeader(&want, WAFMapType, length, capacity, unsafe.Pointer(&data[0]))
				require.Equal(t, want.data, got.data, "the compact map header must not change")
				runtime.KeepAlive(data)
			})
		}
	}
}

// TestSetContainerDataLarge checks the large layout that SetArrayData and
// SetMapData write when the capacity is more than 65,535. The objects are
// backed by Go memory and are never passed to C, so they must never be freed
// with ddwaf_object_destroy.
func TestSetContainerDataLarge(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	const failure = "SetArrayData/SetMapData must accept more than 65,535 items"

	// The C probe value for size 70,000 and capacity 131,070.
	wantHeader := [8]byte{0xa0, 0x70, 0x11, 0x01, 0xe0, 0xff, 0x1f, 0x00}

	for _, tc := range []struct {
		name     string
		length   int
		capacity int
	}{
		{"len=65536/cap=65536", 65_536, 65_536},
		{"len=70000/cap=131070", largeTestSize, largeTestCapacity},
		{"len=10/cap=70000", 10, 70_000},
	} {
		t.Run("array/"+tc.name, func(t *testing.T) {
			data := make([]WAFObject, tc.length, tc.capacity)
			for i := range data {
				data[i].SetUint(uint64(i))
			}
			var obj WAFObject
			require.NoError(t, obj.SetArrayData(&pinner, data), failure)

			require.Equal(t, WAFLargeArrayType, obj.Type())
			var want WAFObject
			writeLargeHeader(&want, WAFLargeArrayType, uint64(tc.length), uint64(tc.capacity), unsafe.Pointer(&data[0]))
			require.Equal(t, want.data, obj.data)
			if tc.length == largeTestSize {
				require.Equal(t, wantHeader[:], obj.data[:8])
			}

			values, err := obj.ArrayValues()
			require.NoError(t, err)
			require.Len(t, values, tc.length)
			require.Same(t, &data[0], &values[0], "the decoder must read the same backing array")
			last, err := values[len(values)-1].UIntValue()
			require.NoError(t, err)
			require.EqualValues(t, tc.length-1, last)
			runtime.KeepAlive(data)
		})
		t.Run("map/"+tc.name, func(t *testing.T) {
			data := make([]WAFObjectKV, tc.length, tc.capacity)
			for i := range data {
				data[i].Val.SetUint(uint64(i))
			}
			var obj WAFObject
			require.NoError(t, obj.SetMapData(&pinner, data), failure)

			require.Equal(t, WAFLargeMapType, obj.Type())
			var want WAFObject
			writeLargeHeader(&want, WAFLargeMapType, uint64(tc.length), uint64(tc.capacity), unsafe.Pointer(&data[0]))
			require.Equal(t, want.data, obj.data)
			if tc.length == largeTestSize {
				// Same size and capacity as the array, other type byte.
				require.Equal(t, append([]byte{0xc0}, wantHeader[1:]...), obj.data[:8])
			}

			entries, err := obj.MapEntries()
			require.NoError(t, err)
			require.Len(t, entries, tc.length)
			require.Same(t, &data[0], &entries[0], "the decoder must read the same backing array")
			last, err := entries[len(entries)-1].Val.UIntValue()
			require.NoError(t, err)
			require.EqualValues(t, tc.length-1, last)
			runtime.KeepAlive(data)
		})
	}
}
