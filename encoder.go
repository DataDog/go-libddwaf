// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"math"
	"reflect"
	"strings"
	"unicode"
)

// Encode Go values into wafObjects. Only the subset of Go types representable into wafObjects
// will be encoded while ignoring the rest of it.
// The encoder allocates the memory required for new wafObjects into the Go memory, which must be kept
// referenced for their lifetime in the C world. This lifetime depends on the ddwaf function being used with.
// the encoded result. The Go references of the allocated wafObjects, along with every Go pointer they may
// reference now or in the future, are stored and referenced in the `cgoRefs` field. The user MUST leverage
// `keepAlive()` with it according to its ddwaf use-case.
type encoder struct {
	containerMaxSize int
	stringMaxSize    int
	objectMaxDepth   int
	cgoRefs          cgoRefPool
}

type native interface {
	int64 | uint64 | uintptr
}

func newLimitedEncoder() *encoder {
	return &encoder{
		containerMaxSize: wafMaxContainerSize,
		stringMaxSize:    wafMaxStringLength,
		objectMaxDepth:   wafMaxContainerDepth,
	}
}

func newMaxEncoder() *encoder {
	return &encoder{
		containerMaxSize: math.MaxInt,
		stringMaxSize:    math.MaxInt,
		objectMaxDepth:   math.MaxInt,
	}
}

// Encode takes a Go value and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of imbriqued wafObjects representing the Go value.
// The only error case is if the top-level object is "Unusable" which means that the data is nil or a non-data type
// like a function or a channel.
func (encoder *encoder) Encode(data any) (*wafObject, error) {
	value := reflect.ValueOf(data)
	wo := &wafObject{}

	encoder.encode(value, wo, encoder.objectMaxDepth)

	if wo._type == wafInvalidType {
		return nil, errUnsupportedValue
	}

	return wo, nil
}

func encodeNative[T native](val T, t wafObjectType, obj *wafObject) {
	obj._type = t
	obj.value = (uintptr)(val)
}

var nullableTypeKinds = map[reflect.Kind]struct{}{
	reflect.Interface:     {},
	reflect.Pointer:       {},
	reflect.UnsafePointer: {},
	reflect.Map:           {},
	reflect.Slice:         {},
	reflect.Func:          {},
	reflect.Chan:          {},
}

// isValueNil check if the value is nullable and if it is actually nil
// we cannot directly use value.IsNil() because it panics on non-pointer values
func isValueNil(value reflect.Value) bool {
	_, nullable := nullableTypeKinds[value.Kind()]
	return nullable && value.IsNil()
}

func (encoder *encoder) encode(value reflect.Value, obj *wafObject, depth int) {
	value.IsValid()
	switch kind := value.Kind(); {
	// Terminal cases (leafs of the tree)
	case kind == reflect.Invalid:
		encodeNative[uintptr](0, wafInvalidType, obj)
	// Is nullable type kind
	case isValueNil(value):
		encodeNative[uintptr](0, wafNilType, obj)

	// 		Booleans
	case kind == reflect.Bool:
		encodeNative(nativeToUintptr(value.Bool()), wafBoolType, obj)
	// 		Numbers
	case value.CanInt(): // any int type or alias
		encodeNative(value.Int(), wafIntType, obj)
	case value.CanUint(): // any Uint type or alias
		encodeNative(value.Uint(), wafUintType, obj)
	case value.CanFloat(): // any float type or alias
		encodeNative(nativeToUintptr(value.Float()), wafFloatType, obj)

	//		Strings
	case kind == reflect.String: // string type
		encoder.encodeString(value.String(), obj)
	case value.Type() == reflect.TypeOf([]byte(nil)): // byte array -> string
		encoder.encodeString(string(value.Bytes()), obj)

	// Recursive cases (internal nodes of the tree)
	case kind == reflect.Interface || kind == reflect.Pointer: // Pointer and interfaces are not taken into account
		encoder.encode(value.Elem(), obj, depth)
	case kind == reflect.Array || kind == reflect.Slice: // either an array or a slice of an array
		encoder.encodeArray(value, obj, depth)
	case kind == reflect.Map:
		encoder.encodeMap(value, obj, depth)
	case kind == reflect.Struct:
		encoder.encodeStruct(value, obj, depth)

	default:
		encodeNative[uintptr](0, wafInvalidType, obj)
	}
}

func (encoder *encoder) encodeString(str string, obj *wafObject) {
	if len(str) > encoder.stringMaxSize {
		str = str[:encoder.stringMaxSize]
	}

	encoder.cgoRefs.AllocWafString(obj, str)
}

func getFieldNameFromType(field reflect.StructField) (string, bool) {
	fieldName := field.Name

	// Private and synthetics fields
	if len(fieldName) < 1 || unicode.IsLower(rune(fieldName[0])) {
		return "", false
	}

	// Use the json tag name as field name if present
	if tag, ok := field.Tag.Lookup("json"); ok {
		if i := strings.IndexByte(tag, byte(',')); i > 0 {
			tag = tag[:i]
		}
		if len(tag) > 0 {
			fieldName = tag
		}
	}

	return fieldName, true
}

// encodeStruct takes a reflect.Value and a wafObject pointer and iterates on the struct field to build
// a wafObject map of type wafMapType. The specificities are the following:
// - It will only take the first encoder.containerMaxSize elements of the struct
// - If the field has a json tag it will become the field name
// - Private fields and also values producing an error at encoding will be skipped
// - Even if the element values are invalid or null we still keep them to report the field name
func (encoder *encoder) encodeStruct(value reflect.Value, obj *wafObject, depth int) {
	if depth < 0 {
		encodeNative[uintptr](0, wafInvalidType, obj)
		return
	}

	typ := value.Type()
	nbFields := typ.NumField()
	capacity := nbFields
	length := 0
	if capacity > encoder.containerMaxSize {
		capacity = encoder.containerMaxSize
	}

	objArray := encoder.cgoRefs.AllocWafArray(obj, wafMapType, uint64(capacity))
	for i := 0; length < capacity && i < nbFields; i++ {
		fieldType := typ.Field(i)
		fieldName, usable := getFieldNameFromType(fieldType)
		if !usable {
			continue
		}

		objElem := &objArray[length]
		// If the Map key is of unsupported type, skip it
		if encoder.encodeMapKey(reflect.ValueOf(fieldName), objElem, depth) != nil {
			continue
		}

		encoder.encode(value.Field(i), objElem, depth-1)

		length++
	}

	// Set the length to the final number of successfully encoded elements
	obj.nbEntries = uint64(length)
}

// encodeMap takes a reflect.Value and a wafObject pointer and iterates on the map elements and returns
// a wafObject map of type wafMapType. The specificities are the following:
// - It will only take the first encoder.containerMaxSize elements of the map
// - Even if the element values are invalid or null we still keep them to report the map key
func (encoder *encoder) encodeMap(value reflect.Value, obj *wafObject, depth int) {
	if depth < 0 {
		encodeNative[uintptr](0, wafInvalidType, obj)
		return
	}

	capacity := value.Len()
	length := 0
	if capacity > encoder.containerMaxSize {
		capacity = encoder.containerMaxSize
	}

	objArray := encoder.cgoRefs.AllocWafArray(obj, wafMapType, uint64(capacity))
	for iter := value.MapRange(); iter.Next(); {
		if length == capacity {
			break
		}

		objElem := &objArray[length]
		if encoder.encodeMapKey(iter.Key(), objElem, depth) != nil {
			continue
		}

		encoder.encode(iter.Value(), objElem, depth-1)
		length++
	}

	// Fix the size because we skipped map entries
	obj.nbEntries = uint64(length)
}

// encodeMapKey takes a reflect.Value and a wafObject and returns a wafObject ready to be considered a map key
// We use the function cgoRefPool.AllocWafMapKey to store the key in the wafObject. But first we need
// to grab the real underlying value by recursing through the pointer and interface values.
func (encoder *encoder) encodeMapKey(value reflect.Value, obj *wafObject, depth int) error {
	kind := value.Kind()
	for ; depth > 0 && (kind == reflect.Pointer || kind == reflect.Interface); value, kind = value.Elem(), value.Elem().Kind() {
		if value.IsNil() {
			return errInvalidMapKey
		}

		depth--
	}

	if kind != reflect.String && value.Type() != reflect.TypeOf([]byte(nil)) {
		return errInvalidMapKey
	}

	if value.Type() == reflect.TypeOf([]byte(nil)) {
		encoder.cgoRefs.AllocWafMapKey(obj, string(value.Bytes()))
	}

	if reflect.String == kind {
		encoder.cgoRefs.AllocWafMapKey(obj, value.String())
	}

	return nil
}

// encodeArray takes a reflect.Value and a wafObject pointer and iterates on the elements and returns
// a wafObject array of type wafArrayType. The specificities are the following:
// - It will only take the first encoder.containerMaxSize elements of the array
// - Elements producing an error at encoding or null values will be skipped
func (encoder *encoder) encodeArray(value reflect.Value, obj *wafObject, depth int) {
	if depth < 0 {
		encodeNative[uintptr](0, wafInvalidType, obj)
		return
	}

	length := value.Len()
	capacity := length
	if capacity > encoder.containerMaxSize {
		capacity = encoder.containerMaxSize
	}

	currIndex := 0
	objArray := encoder.cgoRefs.AllocWafArray(obj, wafArrayType, uint64(capacity))
	for i := 0; currIndex < capacity && i < length; i++ {
		objElem := &objArray[currIndex]

		encoder.encode(value.Index(i), objElem, depth-1)

		// If the element is null or invalid, we have no map key to report so we can skip it
		if objElem.IsUnusable() {
			continue
		}

		currIndex++
	}

	// Fix the size because we skipped map entries
	obj.nbEntries = uint64(currIndex)
}
