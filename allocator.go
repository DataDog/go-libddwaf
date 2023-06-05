// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"runtime"
	"strconv"
	"unsafe"
)

// TODO document all this
type allocator struct {
	stringRefs [][]byte
	arrayRefs  [][]wafObject
}

func (allocator *allocator) append(newAllocs allocator) {
	allocator.stringRefs = append(allocator.stringRefs, newAllocs.stringRefs...)
	allocator.arrayRefs = append(allocator.arrayRefs, newAllocs.arrayRefs...)
}

// KeepAlive is needed at the end of the context life cycle to keep the GC from making a terrible mistake
func (allocator *allocator) KeepAlive() {
	runtime.KeepAlive(allocator.arrayRefs)
	runtime.KeepAlive(allocator.stringRefs)
}

func (allocator *allocator) AllocRawString(str string) uintptr {
	goArray := make([]byte, len(str)+1)
	copy(goArray, str)
	allocator.stringRefs = append(allocator.stringRefs, goArray)
	goArray[len(str)] = 0 // Null termination byte for C strings

	return uintptr(unsafe.Pointer(&goArray[0]))
}

func (allocator *allocator) AllocString(obj *wafObject, typ wafObjectType, str string) {
	if typ != wafIntType && typ != wafStringType && typ != wafUintType {
		panic("Cannot allocate this waf object data type from a string: " + strconv.Itoa(int(typ)))
	}

	obj._type = typ

	if len(str) == 0 {
		obj.nbEntries = 0
		obj.value = 0
		return
	}

	goArray := make([]byte, len(str))
	copy(goArray, str)
	allocator.stringRefs = append(allocator.stringRefs, goArray)

	// This line firstly gets the value from the stringRef array. Then manage to get a *byte from the string.
	// Then cast it into unsafe.Pointer then into uintptr
	obj.value = uintptr(unsafe.Pointer(&goArray[0]))
	obj.nbEntries = uint64(len(goArray))
}

func (allocator *allocator) AllocArray(obj *wafObject, typ wafObjectType, size uint64) []wafObject {
	if typ != wafMapType && typ != wafArrayType {
		panic("Cannot allocate this waf object data type as an array: " + strconv.Itoa(int(typ)))
	}

	obj._type = typ
	obj.nbEntries = size

	// If the array size is zero no need to allocate anything
	if size == 0 {
		obj.value = 0
		return nil
	}

	goArray := make([]wafObject, size)
	allocator.arrayRefs = append(allocator.arrayRefs, goArray)

	//Here we transform the go array into a go pointer then we cast it into unsafe.Pointer then into uintptr
	obj.value = uintptr(unsafe.Pointer(&goArray[0]))
	return goArray
}

func (allocator *allocator) AllocMapKey(obj *wafObject, str string) {
	if len(str) == 0 {
		return
	}

	goArray := make([]byte, len(str))
	copy(goArray, str)
	allocator.stringRefs = append(allocator.stringRefs, goArray)

	obj.parameterName = uintptr(unsafe.Pointer(&goArray[0]))
	obj.parameterNameLength = uint64(len(goArray))
}
