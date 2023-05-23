// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 for now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import "unsafe"

const (
	wafMaxStringLength   = 4096
	wafMaxContainerDepth = 20
	wafMaxContainerSize  = 256
	wafRunTimeout        = 5000
)

type wafReturnCode int32

const (
	wafErrInternal        wafReturnCode = -3
	wafErrInvalidObject                 = -2
	wafErrInvalidArgument               = -1
	wafOK                               = 0
	wafMatch                            = 1
)

// wafObjectType is an enum in C which has the size of DWORD.
// But DWORD is 4 bytes in amd64 and arm64 so uint32 it is.
type wafObjectType uint32

const (
	wafInvalidType wafObjectType = 0
	wafIntType                   = 1 << 0
	wafUintType                  = 1 << 1
	wafStringType                = 1 << 2
	wafArrayType                 = 1 << 3
	wafMapType                   = 1 << 4
)

type wafObject struct {
	parameterName       uintptr
	parameterNameLength uint64
	value               uintptr
	nbEntries           uint64
	_type               wafObjectType
	_                   [4]byte
	// Forced padding
	// We only support 2 archs and cgo generated the same padding to both.
	// We don't want the C struct to be packed because actually go will do the same padding itself,
	// we just add it explicitly to not take any chance.
	// And we cannot pack a struct in go so it will get tricky if the struct is
	// packed (apart from breaking all tracers of course)
}

type wafConfig struct {
	limits     wafConfigLimits
	obfuscator wafConfigObfuscator
	freeFn     uintptr
}

type wafConfigLimits struct {
	maxContainerSize  uint32
	maxContainerDepth uint32
	maxStringLength   uint32
}

type wafConfigObfuscator struct {
	keyRegex   uintptr
	valueRegex uintptr
}

type wafResult struct {
	timeout       byte
	data          uintptr
	actions       wafResultActions
	total_runtime uint64
}

type wafResultActions struct {
	array *uintptr
	size  uint32
	_     [4]byte // Forced padding
}

type wafRulesetInfo struct {
	loaded  uint16
	failed  uint16
	errors  wafObject
	version uintptr
}

// wafHandle is a forward declaration in ddwaf.h header
// We basically don't need to modify it, only to give it to the waf
type wafHandle uintptr

// wafContext is a forward declaration in ddwaf.h header
// We basically don't need to modify it, only to give it to the waf
type wafContext uintptr

// gostring copies a char* to a Go string.
func gostring(c uintptr) string {
	// We take the address and then dereference it to trick go vet from creating a possible misuse of unsafe.Pointer
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&c))
	if ptr == nil {
		return ""
	}
	var length int
	for {
		if *(*byte)(unsafe.Add(ptr, uintptr(length))) == '\x00' {
			break
		}
		length++
	}
	//string builtin copies the slice
	return string(unsafe.Slice((*byte)(ptr), length))
}

// cstring converts a go string to *byte that can be passed to C code.
func cstring(name string) *byte {
	var b = make([]byte, len(name)+1)
	copy(b, name)
	return &b[0]
}
