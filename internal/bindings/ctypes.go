// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"fmt"
	"structs"

	"github.com/DataDog/go-libddwaf/v4/internal/pin"
	"github.com/DataDog/go-libddwaf/v4/internal/unsafe"
)

const (
	MaxStringLength   = 4096
	MaxContainerDepth = 20
	MaxContainerSize  = 256
)

type WAFReturnCode int32

const (
	WAFErrInternal WAFReturnCode = iota - 3
	WAFErrInvalidObject
	WAFErrInvalidArgument
	WAFOK
	WAFMatch
)

// WAFObjectType is an enum in C which has the size of DWORD.
// But DWORD is 4 bytes in amd64 and arm64 so uint32 it is.
type WAFObjectType uint32

const WAFInvalidType WAFObjectType = 0
const (
	WAFIntType WAFObjectType = 1 << iota
	WAFUintType
	WAFStringType
	WAFArrayType
	WAFMapType
	WAFBoolType
	WAFFloatType
	WAFNilType
)

func (w WAFObjectType) String() string {
	switch w {
	case WAFInvalidType:
		return "invalid"
	case WAFIntType:
		return "int"
	case WAFUintType:
		return "uint"
	case WAFStringType:
		return "string"
	case WAFArrayType:
		return "array"
	case WAFMapType:
		return "map"
	case WAFBoolType:
		return "bool"
	case WAFFloatType:
		return "float"
	case WAFNilType:
		return "nil"
	default:
		return fmt.Sprintf("unknown(%d)", w)
	}
}

type WAFObject struct {
	_                   structs.HostLayout
	ParameterName       uintptr
	ParameterNameLength uint64
	Value               uintptr
	NbEntries           uint64
	Type                WAFObjectType
	_                   [4]byte
	// Forced padding
	// We only support 2 archs and cgo generated the same padding to both.
	// We don't want the C struct to be packed because actually go will do the same padding itself,
	// we just add it explicitly to not take any chance.
	// And we cannot pack a struct in go so it will get tricky if the struct is
	// packed (apart from breaking all tracers of course)
}

// IsInvalid determines whether this WAF Object has the invalid type (which is the 0-value).
func (w *WAFObject) IsInvalid() bool {
	return w.Type == WAFInvalidType
}

// IsNil determines whether this WAF Object is nil or not.
func (w *WAFObject) IsNil() bool {
	return w.Type == WAFNilType
}

// IsArray determines whether this WAF Object is an array or not.
func (w *WAFObject) IsArray() bool {
	return w.Type == WAFArrayType
}

// IsMap determines whether this WAF Object is a map or not.
func (w *WAFObject) IsMap() bool {
	return w.Type == WAFMapType
}

// IsUnusable returns true if the wafObject has no impact on the WAF execution
// But we still need this kind of objects to forward map keys in case the value of the map is invalid
func (w *WAFObject) IsUnusable() bool {
	return w.Type == WAFInvalidType || w.Type == WAFNilType
}

// SetArray sets the receiving [WAFObject] to a new array with the given
// capacity.
func (w *WAFObject) SetArray(pinner pin.Pinner, capacity uint64) []WAFObject {
	return w.setArrayTyped(pinner, capacity, WAFArrayType)
}

// SetMap sets the receiving [WAFObject] to a new map with the given capacity.
func (w *WAFObject) SetMap(pinner pin.Pinner, capacity uint64) []WAFObject {
	return w.setArrayTyped(pinner, capacity, WAFMapType)
}

// SetMapKey sets the receiving [WAFObject] to a new map key with the given
// string.
func (w *WAFObject) SetMapKey(pinner pin.Pinner, key string) {
	header := unsafe.NativeStringUnwrap(key)

	w.ParameterNameLength = uint64(header.Len)
	if w.ParameterNameLength == 0 {
		w.ParameterName = 0
		return
	}
	pinner.Pin(unsafe.Pointer(header.Data))
	w.ParameterName = uintptr(unsafe.Pointer(header.Data))
}

var blankCStringValue = unsafe.Pointer(unsafe.NativeStringUnwrap("\x00").Data)

// SetString sets the receiving [WAFObject] value to the given string.
func (w *WAFObject) SetString(pinner pin.Pinner, str string) {
	header := unsafe.NativeStringUnwrap(str)

	w.Type = WAFStringType
	w.NbEntries = uint64(header.Len)
	if w.NbEntries == 0 {
		w.Value = uintptr(blankCStringValue)
		return
	}
	pinner.Pin(unsafe.Pointer(header.Data))
	w.Value = uintptr(unsafe.Pointer(header.Data))
}

func (w *WAFObject) setArrayTyped(pinner pin.Pinner, capacity uint64, t WAFObjectType) []WAFObject {
	w.Type = t
	w.NbEntries = capacity
	if w.NbEntries == 0 {
		w.Value = 0
		return nil
	}

	arr := make([]WAFObject, capacity)
	data := unsafe.Pointer(unsafe.SliceData(arr))
	pinner.Pin(data)
	w.Value = uintptr(data)
	return arr
}

type WAFConfig struct {
	_          structs.HostLayout
	Limits     WAFConfigLimits
	Obfuscator WAFConfigObfuscator
	FreeFn     uintptr
}

type WAFConfigLimits struct {
	_                 structs.HostLayout
	MaxContainerSize  uint32
	MaxContainerDepth uint32
	MaxStringLength   uint32
}

type WAFConfigObfuscator struct {
	_          structs.HostLayout
	KeyRegex   uintptr // char *
	ValueRegex uintptr // char *
}

type WAFResult struct {
	_            structs.HostLayout
	Timeout      byte
	Events       WAFObject
	Actions      WAFObject
	Derivatives  WAFObject
	TotalRuntime uint64
}

// WAFBuilder is a forward declaration in ddwaf.h header
// We basically don't need to modify it, only to give it to the waf
type WAFBuilder uintptr

// WAFHandle is a forward declaration in ddwaf.h header
// We basically don't need to modify it, only to give it to the waf
type WAFHandle uintptr

// WAFContext is a forward declaration in ddwaf.h header
// We basically don't need to modify it, only to give it to the waf
type WAFContext uintptr
