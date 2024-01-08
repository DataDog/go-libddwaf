// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"errors"
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
	// For each TruncationReason, holds the size that is required to avoid truncation for each truncation that happened.
	truncations map[TruncationReason][]int

	cgoRefs          cgoRefPool
	containerMaxSize int
	stringMaxSize    int
	objectMaxDepth   int
}

// TruncationReason is a flag representing reasons why some input was not encoded in full.
type TruncationReason uint8

const (
	StringTooLong TruncationReason = 1 << iota
	ContainerTooLarge
	ObjectTooDeep
)

type native interface {
	int64 | uint64 | uintptr
}

func newLimitedEncoder() encoder {
	return encoder{
		containerMaxSize: wafMaxContainerSize,
		stringMaxSize:    wafMaxStringLength,
		objectMaxDepth:   wafMaxContainerDepth,
	}
}

func newMaxEncoder() encoder {
	return encoder{
		containerMaxSize: math.MaxInt,
		stringMaxSize:    math.MaxInt,
		objectMaxDepth:   math.MaxInt,
	}
}

// Encode takes a Go value and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of nested wafObjects representing the Go value.
// The only error case is if the top-level object is "Unusable" which means that the data is nil or a non-data type
// like a function or a channel.
func (encoder *encoder) Encode(data any) (*wafObject, error) {
	value := reflect.ValueOf(data)
	wo := &wafObject{}

	if _, err := encoder.encode(value, wo, encoder.objectMaxDepth); err != nil {
		return nil, err
	}

	return wo, nil
}

// Truncations returns all truncations that happened since the last call to `Truncations()`, and clears the internal
// list. This is a map from truncation reason to the list of un-truncated value sizes.
func (encoder *encoder) Truncations() map[TruncationReason][]int {
	result := encoder.truncations
	encoder.truncations = nil
	return result
}

// EncodeAddresses takes a map of Go values and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of nested wafObjects representing the Go values.
// This function is further optimized from Encode to take addresses as input and avoid further
// errors in case the top-level map with addresses as keys is nil.
// Since errors returned by Encode are not sent up between levels of the tree, this means that all errors come from the
// top layer of encoding, which is the map of addresses. Hence, all errors should be developer errors since the map of
// addresses is not user defined custom data.
func (encoder *encoder) EncodeAddresses(addresses map[string]any) (*wafObject, error) {
	if addresses == nil {
		return nil, errUnsupportedValue
	}

	return encoder.Encode(addresses)
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

const (
	measureOnlyDepth = wafMaxContainerDepth
)

func (encoder *encoder) encode(value reflect.Value, obj *wafObject, depth int) (int, error) {
	kind := value.Kind()

	for value.IsValid() && (kind == reflect.Interface || kind == reflect.Pointer) && !value.IsNil() {
		// 		Pointer and interfaces are not taken into account, we only recurse on them
		value = value.Elem()
		kind = value.Kind()
	}

	maxDepth := encoder.objectMaxDepth - depth

	switch {
	// Terminal cases (leaves of the tree)

	//		Measure-only runs for leaves
	case obj == nil && kind != reflect.Array && kind != reflect.Slice && kind != reflect.Map && kind != reflect.Struct:
		// Nothing to do, we were only here to measure object depth!

	//		Is invalid type: nil interfaces for example, cannot be used to run any reflect method or it's susceptible to panic
	case !value.IsValid() || kind == reflect.Invalid:
		return maxDepth, errUnsupportedValue
	// 		Is nullable type: nil pointers, channels, maps or functions
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

	// Containers (internal nodes of the tree)

	// 		All recursive cases can only execute if the depth is superior to 0, but we'll measure up to measureOnlyDepth more levels
	case obj != nil && depth <= 0:
		maxDepth, _ = encoder.encode(value, nil, depth)
		encoder.addTruncation(ObjectTooDeep, maxDepth)
		return maxDepth, errMaxDepthExceeded

	case obj == nil && depth <= -measureOnlyDepth:
		// We've measured as deep as we'd allow, cut off the loss at this point
		return maxDepth, errMaxDepthExceeded

	// 		Either an array or a slice of an array
	case kind == reflect.Array || kind == reflect.Slice:
		maxDepth = encoder.encodeArray(value, obj, depth-1)
	case kind == reflect.Map:
		maxDepth = encoder.encodeMap(value, obj, depth-1)
	case kind == reflect.Struct:
		maxDepth = encoder.encodeStruct(value, obj, depth-1)

	default:
		return maxDepth, errUnsupportedValue
	}

	return maxDepth, nil
}

func (encoder *encoder) encodeString(str string, obj *wafObject) {
	size := len(str)
	if size > encoder.stringMaxSize {
		str = str[:encoder.stringMaxSize]
		encoder.addTruncation(StringTooLong, size)
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
func (encoder *encoder) encodeStruct(value reflect.Value, obj *wafObject, depth int) int {
	typ := value.Type()
	nbFields := typ.NumField()

	capacity := nbFields
	length := 0
	if capacity > encoder.containerMaxSize {
		capacity = encoder.containerMaxSize
	}

	var objArray []wafObject
	if obj != nil {
		// If obj is nil, we're only measuring
		objArray = encoder.cgoRefs.AllocWafArray(obj, wafMapType, uint64(capacity))
	}
	maxDepth := encoder.objectMaxDepth - depth
	for i := 0; i < nbFields; i++ {
		if length == capacity {
			if obj != nil {
				encoder.addTruncation(ContainerTooLarge, nbFields)
			}
			break
		}

		fieldType := typ.Field(i)
		fieldName, usable := getFieldNameFromType(fieldType)
		if !usable {
			continue
		}

		var objElem *wafObject
		if objArray != nil {
			objElem = &objArray[length]
		}
		// If the Map key is of unsupported type, skip it
		encoder.encodeMapKey(fieldName, objElem)

		leafDepth, err := encoder.encode(value.Field(i), objElem, depth)
		if maxDepth < leafDepth {
			maxDepth = leafDepth
		}
		if err != nil {
			// We still need to keep the map key, so we can't discard the full object, instead, we make the value a noop
			encodeNative[uintptr](0, wafInvalidType, objElem)
		}

		length++
	}

	if obj != nil {
		// Set the length to the final number of successfully encoded elements
		obj.nbEntries = uint64(length)
	}

	return maxDepth
}

// encodeMap takes a reflect.Value and a wafObject pointer and iterates on the map elements and returns
// a wafObject map of type wafMapType. The specificities are the following:
// - It will only take the first encoder.containerMaxSize elements of the map
// - Even if the element values are invalid or null we still keep them to report the map key
func (encoder *encoder) encodeMap(value reflect.Value, obj *wafObject, depth int) int {
	capacity := value.Len()
	if capacity > encoder.containerMaxSize {
		capacity = encoder.containerMaxSize
	}

	var objArray []wafObject
	if obj != nil {
		// If obj is nil, we're only measuring
		objArray = encoder.cgoRefs.AllocWafArray(obj, wafMapType, uint64(capacity))
	}

	length := 0
	maxDepth := encoder.objectMaxDepth - depth
	for iter := value.MapRange(); iter.Next(); {
		if length == capacity {
			if obj != nil {
				encoder.addTruncation(ContainerTooLarge, value.Len())
			}
			break
		}

		var objElem *wafObject
		if objArray != nil {
			objElem = &objArray[length]
		}
		var keyOffMaxDepth bool
		if err := encoder.encodeMapKeyFromValue(iter.Key(), objElem); err != nil {
			if !errors.Is(err, errMaxDepthExceeded) {
				keyOffMaxDepth = true
			} else {
				continue
			}
		}

		leafDepth, err := encoder.encode(iter.Value(), objElem, depth)
		if maxDepth < leafDepth {
			maxDepth = leafDepth
		}
		if err != nil {
			// We still need to keep the map key, so we can't discard the full object, instead, we make the value a noop
			encodeNative[uintptr](0, wafInvalidType, objElem)
		}
		if keyOffMaxDepth {
			continue
		}

		length++
	}

	if obj != nil {
		// Fix the size because we skipped map entries
		obj.nbEntries = uint64(length)
	}

	return maxDepth
}

// encodeMapKeyFromValue takes a reflect.Value and a wafObject and returns a wafObject ready to be considered a map key
// We use the function cgoRefPool.AllocWafMapKey to store the key in the wafObject. But first we need
// to grab the real underlying value by recursing through the pointer and interface values.
func (encoder *encoder) encodeMapKeyFromValue(value reflect.Value, obj *wafObject) error {
	kind := value.Kind()
	// We have a depth limit in place to protect against self-referencing pointers, which are not a thing expected to
	// occur in "normal" go programs in any way. 8 levels of indirection should be plenty enough for any reasonable use
	// case, further than this is clearly abuse.
	for depth := 8; depth > 0 && kind == reflect.Pointer || kind == reflect.Interface; value, kind, depth = value.Elem(), value.Elem().Kind(), depth-1 {
		if value.IsNil() {
			return errInvalidMapKey
		}
	}

	var keyStr string
	switch {
	case kind == reflect.Invalid:
		return errInvalidMapKey
	case kind == reflect.String:
		keyStr = value.String()
	case value.Type() == reflect.TypeOf([]byte(nil)):
		keyStr = string(value.Bytes())
	default:
		return errInvalidMapKey
	}

	encoder.encodeMapKey(keyStr, obj)
	return nil
}

// encodeMapKey takes a string and a wafObject and sets the map key attribute on the wafObject to the supplied string.
// The key may be truncated if it exceeds the maximum string size allowed by the encoder.
func (encoder *encoder) encodeMapKey(keyStr string, obj *wafObject) {
	size := len(keyStr)
	if obj == nil {
		// If obj is nil, we're only measuring
		return
	}
	if size > encoder.stringMaxSize {
		keyStr = keyStr[:encoder.stringMaxSize]
		encoder.addTruncation(StringTooLong, size)
	}

	encoder.cgoRefs.AllocWafMapKey(obj, keyStr)
}

// encodeArray takes a reflect.Value and a wafObject pointer and iterates on the elements and returns
// a wafObject array of type wafArrayType. The specificities are the following:
// - It will only take the first encoder.containerMaxSize elements of the array
// - Elements producing an error at encoding or null values will be skipped
func (encoder *encoder) encodeArray(value reflect.Value, obj *wafObject, depth int) int {
	length := value.Len()

	capacity := length
	if capacity > encoder.containerMaxSize {
		capacity = encoder.containerMaxSize
	}

	currIndex := 0

	var objArray []wafObject
	if obj != nil {
		// If obj is nil, we're only measuring
		objArray = encoder.cgoRefs.AllocWafArray(obj, wafArrayType, uint64(capacity))
	}

	maxDepth := encoder.objectMaxDepth - depth

	for i := 0; i < length; i++ {
		if currIndex == capacity {
			if obj != nil {
				encoder.addTruncation(ContainerTooLarge, length)
			}
			break
		}

		var objElem *wafObject
		if objArray != nil {
			objElem = &objArray[currIndex]
		}

		leafDepth, err := encoder.encode(value.Index(i), objElem, depth)
		if maxDepth < leafDepth {
			maxDepth = leafDepth
		}
		if err != nil {
			continue
		}

		// If the element is null or invalid it has no impact on the waf execution, therefore we can skip its
		// encoding. In this specific case we just overwrite it at the next loop iteration.
		if objElem == nil || objElem.IsUnusable() {
			continue
		}

		currIndex++
	}

	if obj != nil {
		// Fix the size because we skipped map entries
		obj.nbEntries = uint64(currIndex)
	}

	return maxDepth
}

func (encoder *encoder) addTruncation(reason TruncationReason, size int) {
	if encoder.truncations == nil {
		encoder.truncations = make(map[TruncationReason][]int, 3)
	}
	encoder.truncations[reason] = append(encoder.truncations[reason], size)
}
