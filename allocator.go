// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"reflect"
	"runtime"
	"strconv"
	"unsafe"
)

// TODO document all this
type allocator struct {
	stringRefs []string
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

// AllocRawString creates a null-terminated string and adds it to the allocator and returns a pointer to it
func (allocator *allocator) AllocRawString(str string) uintptr {
	// Is the string already null-terminated ?
	if len(str) < len("\x00") || str[len(str)-len("\x00"):] != "\x00" {
		str += "\x00"
	}

	allocator.stringRefs = append(allocator.stringRefs, str)

	// Since a string is a struct of type StringHeader we have to cast it to get the pointer to the real data
	return (*reflect.StringHeader)(unsafe.Pointer(&str)).Data
}

// AllocString fills a wafObject with the type typ. Since the string do not have to be null-terminated here we can
// directly grab the string passed as parameter and use it without anyway copy
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

	allocator.stringRefs = append(allocator.stringRefs, str)

	// Since a string is a struct of type StringHeader we have to cast it to get the pointer to the real data
	obj.value = (*reflect.StringHeader)(unsafe.Pointer(&str)).Data
	obj.nbEntries = uint64((*reflect.StringHeader)(unsafe.Pointer(&str)).Len)
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

// AllocMapKey fills only the elements of a wafObject that will transform it into a key-value pair for the waf.
func (allocator *allocator) AllocMapKey(obj *wafObject, str string) {
	if len(str) == 0 {
		return
	}

	allocator.stringRefs = append(allocator.stringRefs, str)

	// Since a string is a struct of type StringHeader we have to cast it to get the pointer to the real data
	obj.parameterName = (*reflect.StringHeader)(unsafe.Pointer(&str)).Data
	obj.parameterNameLength = uint64((*reflect.StringHeader)(unsafe.Pointer(&str)).Len)
}
