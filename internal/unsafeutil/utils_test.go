// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package unsafeutil

import (
	"math"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestSliceData(t *testing.T) {
	s := []int{10, 20, 30}
	require.Equal(t, &s[0], SliceData(s))

	empty := make([]byte, 0, 4)
	require.Equal(t, unsafe.SliceData(empty), SliceData(empty))
}

func TestStringData(t *testing.T) {
	const str = "hello"
	require.Equal(t, unsafe.StringData(str), StringData(str))
}

func TestGostring(t *testing.T) {
	t.Run("nil-returns-empty", func(t *testing.T) {
		require.Equal(t, "", Gostring(nil))
	})

	t.Run("stops-at-first-nul", func(t *testing.T) {
		b := []byte("hello\x00world\x00")
		require.Equal(t, "hello", Gostring(&b[0]))
	})

	t.Run("empty-when-leading-nul", func(t *testing.T) {
		b := []byte("\x00rest")
		require.Equal(t, "", Gostring(&b[0]))
	})
}

func TestGostringSized(t *testing.T) {
	t.Run("nil-returns-empty", func(t *testing.T) {
		require.Equal(t, "", GostringSized(nil, 8))
	})

	t.Run("copies-exact-size-including-nul", func(t *testing.T) {
		// Unlike Gostring, GostringSized does not stop at a NUL terminator.
		b := []byte("hi\x00there")
		require.Equal(t, "hi\x00there", GostringSized(&b[0], uint64(len(b))))
	})

	t.Run("truncates-to-size", func(t *testing.T) {
		b := []byte("abcdef")
		require.Equal(t, "abc", GostringSized(&b[0], 3))
	})
}

func TestNativeStringUnwrap(t *testing.T) {
	const str = "datadog"
	h := NativeStringUnwrap(str)
	require.Equal(t, len(str), h.Len)
	require.Equal(t, unsafe.StringData(str), h.Data)
	require.Equal(t, str, String(h.Data, uint64(h.Len)))
}

func TestCstring(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	cs := Cstring(&pinner, "test")
	require.NotNil(t, cs)
	require.Equal(t, "test", Gostring(cs))

	empty := Cstring(&pinner, "")
	require.Equal(t, "", Gostring(empty))
}

func TestReadWritePtr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	target := 1234
	pinner.Pin(&target)

	// A byte buffer wide enough to hold a single pointer.
	buf := make([]byte, unsafe.Sizeof(uintptr(0)))
	pinner.Pin(&buf[0])

	WritePtr(&buf[0], unsafe.Pointer(&target))
	got := ReadPtr[int](&buf[0])

	require.Equal(t, &target, got)
	require.Equal(t, 1234, *got)
	runtime.KeepAlive(&target)
}

func TestCast(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	value := 42
	pinner.Pin(&value)

	got := Cast[int](PtrToUintptr(&value))
	require.Equal(t, 42, *got)
	runtime.KeepAlive(&value)
}

func TestCastNative(t *testing.T) {
	f := 1.5
	// Reinterpret the float64 bit pattern as an int64 without conversion.
	bits := CastNative[float64, int64](&f)
	require.Equal(t, int64(math.Float64bits(1.5)), *bits)
	runtime.KeepAlive(&f)
}

func TestNativeUintptrRoundTrip(t *testing.T) {
	t.Run("int64", func(t *testing.T) {
		u := NativeToUintptr(int64(-123))
		require.Equal(t, int64(-123), UintptrToNative[int64](u))
	})

	t.Run("float64", func(t *testing.T) {
		u := NativeToUintptr(3.14159)
		require.Equal(t, 3.14159, UintptrToNative[float64](u))
	})

	t.Run("bool", func(t *testing.T) {
		u := NativeToUintptr(true)
		require.True(t, UintptrToNative[bool](u))
	})
}

func TestCastWithOffset(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	arr := [4]int32{10, 20, 30, 40}
	pinner.Pin(&arr)

	base := PtrToUintptr(&arr[0])
	require.Equal(t, int32(10), *CastWithOffset[int32](base, 0))
	require.Equal(t, int32(30), *CastWithOffset[int32](base, 2))
	require.Equal(t, int32(40), *CastWithOffset[int32](base, 3))
	runtime.KeepAlive(&arr)
}

func TestPtrToUintptr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	value := 7
	pinner.Pin(&value)

	require.Equal(t, uintptr(unsafe.Pointer(&value)), PtrToUintptr(&value))
	runtime.KeepAlive(&value)
}

func TestSliceToUintptr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	s := []byte{1, 2, 3}
	pinner.Pin(&s[0])

	require.Equal(t, uintptr(unsafe.Pointer(&s[0])), SliceToUintptr(s))
	runtime.KeepAlive(&s)
}

func TestSlice(t *testing.T) {
	arr := [3]int{7, 8, 9}
	got := Slice(&arr[0], uint64(len(arr)))
	require.Equal(t, []int{7, 8, 9}, got)
	runtime.KeepAlive(&arr)
}

func TestString(t *testing.T) {
	b := []byte("hello")
	require.Equal(t, "hello", String(&b[0], uint64(len(b))))
	require.Equal(t, "hel", String(&b[0], 3))
	runtime.KeepAlive(&b)
}
