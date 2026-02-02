// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

<<<<<<<< HEAD:internal/ffi/utils.go
package ffi
|||||||| parent of cf09387 (feat!: libddwaf v2 alpha (#160)):internal/unsafe/utils.go
package unsafe
========
// Package unsafeutil provides helpers for unsafe pointer operations at the FFI boundary.
// All functions in this package bypass Go's type system and must be used with care.
package unsafeutil
>>>>>>>> cf09387 (feat!: libddwaf v2 alpha (#160)):internal/unsafeutil/utils.go

import (
	"runtime"
	"unsafe"
)

// SliceData returns a pointer to the underlying array of the slice. It is a
// generic wrapper around [unsafe.SliceData].
func SliceData[E any, T ~[]E](slice T) *E {
	return unsafe.SliceData(slice)
}

// StringData returns a pointer to the underlying bytes of str. It is a wrapper
// around [unsafe.StringData].
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
	return string(unsafe.Slice(ptr, length))
}

// StringHeader is the runtime representation of a Go string value, mirroring
// the internal layout used by the compiler.
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

// GostringSized copies size bytes starting at ptr into a new Go string. Unlike
// [Gostring], it does not scan for a NUL terminator. Returns "" if ptr is nil.
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

<<<<<<<< HEAD:internal/ffi/utils.go
// Cast converts a uintptr obtained from C-allocated memory into a Go pointer
// of the desired type. The pointer must not originate from Go-allocated memory,
// as the uintptr argument is invisible to the garbage collector and violates
// the [unsafe.Pointer] conversion rules (the pointer-to-uintptr and
// uintptr-to-pointer conversions do not occur in the same expression).
//
// The implementation bypasses go vet's [unsafe.Pointer] checks by
// reinterpreting the uintptr through its memory representation rather than
// using a direct unsafe.Pointer(ptr) conversion.
func Cast[T any](ptr uintptr) *T {
	return (*T)(*(*unsafe.Pointer)(unsafe.Pointer(&ptr)))
|||||||| parent of cf09387 (feat!: libddwaf v2 alpha (#160)):internal/unsafe/utils.go
// Cast is used to centralize unsafe use C of allocated pointer.
// We take the address and then dereference it to trick go vet from creating a possible misuse of unsafe.Pointer
func Cast[T any](ptr uintptr) *T {
	return (*T)(*(*unsafe.Pointer)(unsafe.Pointer(&ptr)))
========
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
>>>>>>>> cf09387 (feat!: libddwaf v2 alpha (#160)):internal/unsafeutil/utils.go
}

// Native is a constraint that permits scalar types whose in-memory
// representation can safely be reinterpreted via [NativeToUintptr] and
// [UintptrToNative]. All permitted types have a well-defined, fixed-size
// layout with no pointers.
type Native interface {
<<<<<<<< HEAD:internal/ffi/utils.go
	~byte | ~float64 | ~float32 | ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint16 | ~uint32 | ~uint64 | ~bool | ~uintptr
}

// NativeToUintptr is a helper used by populate WafObject values
// with Go values
func NativeToUintptr[T Native](x T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&x))
}

// UintToNative is a helper used retrieve Go values from an uintptr encoded
// value from a WafObject
func UintptrToNative[T Native](x uintptr) T {
	return *(*T)(unsafe.Pointer(&x))
}

// CastWithOffset is the same as [Cast] but advances the pointer by offset
// elements of type T (i.e., by offset * unsafe.Sizeof(T) bytes) before
// converting. The same C-allocated memory restriction as [Cast] applies.
func CastWithOffset[T any](ptr uintptr, offset uint64) *T {
	return (*T)(unsafe.Add(*(*unsafe.Pointer)(unsafe.Pointer(&ptr)), offset*uint64(unsafe.Sizeof(*new(T)))))
}

// Slice returns a []T whose backing array starts at ptr and has the given
// length. It is a generic wrapper around [unsafe.Slice].
|||||||| parent of cf09387 (feat!: libddwaf v2 alpha (#160)):internal/unsafe/utils.go
	~byte | ~float64 | ~float32 | ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~bool | ~uintptr
}

func CastNative[N Native, T Native](ptr *N) *T {
	return (*T)(*(*unsafe.Pointer)(unsafe.Pointer(&ptr)))
}

// NativeToUintptr is a helper used by populate WafObject values
// with Go values
func NativeToUintptr[T any](x T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&x))
}

// UintToNative is a helper used retrieve Go values from an uintptr encoded
// value from a WafObject
func UintptrToNative[T any](x uintptr) T {
	return *(*T)(unsafe.Pointer(&x))
}

// CastWithOffset is the same as cast but adding an offset to the pointer by a multiple of the size
// of the type pointed.
func CastWithOffset[T any](ptr uintptr, offset uint64) *T {
	return (*T)(unsafe.Add(*(*unsafe.Pointer)(unsafe.Pointer(&ptr)), offset*uint64(unsafe.Sizeof(*new(T)))))
}

// PtrToUintptr is a helper to centralize of usage of unsafe.Pointer
// do not use this function to cast interfaces
func PtrToUintptr[T any](arg *T) uintptr {
	return uintptr(unsafe.Pointer(arg))
}

func SliceToUintptr[T any](arg []T) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(arg)))
}

========
	~byte | ~float64 | ~float32 | ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~bool | ~uintptr
}

func CastNative[N Native, T Native](ptr *N) *T {
	return (*T)(unsafe.Pointer(ptr))
}

>>>>>>>> cf09387 (feat!: libddwaf v2 alpha (#160)):internal/unsafeutil/utils.go
func Slice[T any](ptr *T, length uint64) []T {
	return unsafe.Slice(ptr, length)
}

// String returns a string whose bytes start at ptr and has the given length.
// It is a wrapper around [unsafe.String].
func String(ptr *byte, length uint64) string {
	return unsafe.String(ptr, length)
}
