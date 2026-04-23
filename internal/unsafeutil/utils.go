// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package unsafeutil provides helpers for unsafe pointer operations at the FFI boundary.
// All functions in this package bypass Go's type system and must be used with care.
package unsafeutil

import (
	"runtime"
	"unsafe"
)

type Pointer = unsafe.Pointer

func SliceData[E any, T ~[]E](slice T) *E {
	return unsafe.SliceData(slice)
}

func StringData(str string) *byte {
	return unsafe.StringData(str)
}

// Gostring copies a char* to a Go string.
func Gostring(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var length int
	for *(*byte)(unsafe.Add(unsafe.Pointer(ptr), uintptr(length))) != '\x00' {
		length++
	}
	//string builtin copies the slice
	return string(unsafe.Slice(ptr, length))
}

type StringHeader struct {
	Len  int
	Data *byte
}

// NativeStringUnwrap cast a native string type into it's runtime value.
func NativeStringUnwrap(str string) StringHeader {
	return StringHeader{
		Data: unsafe.StringData(str),
		Len:  len(str),
	}
}

func GostringSized(ptr *byte, size uint64) string {
	if ptr == nil {
		return ""
	}
	return string(unsafe.Slice(ptr, size))
}

// Cstring converts a go string to *byte that can be passed to C code.
func Cstring(pinner *runtime.Pinner, name string) *byte {
	var b = make([]byte, len(name)+1)
	copy(b, name)
	pinner.Pin(&b[0])
	return unsafe.SliceData(b)
}

// ReadPtr reads a typed pointer stored at the given byte address.
// Use this instead of materializing a stack-local uintptr from raw bytes
// and reinterpreting it, which escapes Go's pointer analysis.
func ReadPtr[T any](from *byte) *T {
	return *(**T)(unsafe.Pointer(from))
}

// WritePtr writes a pointer value into the given byte address.
// This is the inverse of ReadPtr: it stores a pointer into a byte-level
// memory location (e.g. a C struct overlay) without converting through uintptr.
func WritePtr(dst *byte, ptr unsafe.Pointer) {
	*(*unsafe.Pointer)(unsafe.Pointer(dst)) = ptr
}

type Native interface {
	~byte | ~float64 | ~float32 | ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~bool | ~uintptr
}

func CastNative[N Native, T Native](ptr *N) *T {
	return (*T)(unsafe.Pointer(ptr))
}

func Slice[T any](ptr *T, length uint64) []T {
	return unsafe.Slice(ptr, length)
}

func String(ptr *byte, length uint64) string {
	return unsafe.String(ptr, length)
}
