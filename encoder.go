// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

type EncoderConfig struct {
	// Pinner is used to pin the data referenced by the encoded wafObjects.
	Pinner pin.Pinner
	// Timer makes sure the encoder doesn't spend too much time doing its job.
	Timer timer.Timer
	// MaxContainerSize is the maximum number of elements in a container (list, map, struct) that will be encoded.
	MaxContainerSize int
	// MaxStringSize is the maximum length of a string that will be encoded.
	MaxStringSize int
	// MaxObjectDepth is the maximum depth of the object that will be encoded.
	MaxObjectDepth int
}

// encoder encodes Go values into wafObjects. Only the subset of Go types representable into wafObjects
// will be encoded while ignoring the rest of it.
// The encoder allocates memory for wafObjects in Go memory, which must remain referenced for their
// lifetime in the C world. This lifetime depends on the ddwaf function being used with the encoded result.
// The encoder's config.Pinner is used to pin Go pointers that the C library will reference, ensuring they
// aren't moved or collected by the garbage collector. Users must ensure the pinner remains valid until
// the C library is done with the encoded data.
type encoder struct {
	config EncoderConfig

	// For each TruncationReason, holds the size that is required to avoid truncation for each truncation that happened.
	truncations map[TruncationReason][]int
}

// TruncationReason is a flag representing reasons why some input was not encoded in full.
type TruncationReason uint8

const (
	// StringTooLong indicates a string exceeded the maximum string length configured. The truncation
	// values indicate the actual length of truncated strings.
	StringTooLong TruncationReason = 1 << iota
	// ContainerTooLarge indicates a container (list, map, struct) exceeded the maximum number of
	// elements configured. The truncation values indicate the actual number of elements in the
	// truncated container.
	ContainerTooLarge
	// ObjectTooDeep indicates an overall object exceeded the maximum encoding depths configured. The
	// truncation values indicate an estimated actual depth of the truncated object. The value is
	// guaranteed to be less than or equal to the actual depth (it may not be more).
	ObjectTooDeep
)

func (reason TruncationReason) String() string {
	switch reason {
	case ObjectTooDeep:
		return "container_depth"
	case ContainerTooLarge:
		return "container_size"
	case StringTooLong:
		return "string_length"
	default:
		return fmt.Sprintf("TruncationReason(%v)", int(reason))
	}
}

const (
	AppsecFieldTag            = "ddwaf"
	AppsecFieldTagValueIgnore = "ignore"
)

// WAFObject is the C struct that represents a WAF object. It is passed as-is to the C-world.
// It is highly advised to use the methods on the object to manipulate it and not set the fields manually.
type WAFObject = bindings.WAFObject

// WAFObjectKV is a key-value pair used in v2 maps.
// Maps are now arrays of {key, value} pairs where both are full WAFObjects.
type WAFObjectKV = bindings.WAFObjectKV

// Encodable represent a type that can encode itself into a WAFObject.
// The encodable is responsible for using the [pin.Pinner]
// object passed in the [EncoderConfig] to pin the data referenced by the encoded [bindings.WAFObject].
// The encoder must also use the [timer.Timer] passed in the [EncoderConfig] to
// make sure it doesn't spend too much time doing its job.
// The encoder must also respect the [EncoderConfig] limits and report truncations.
type Encodable interface {
	// Encode encodes the receiver as the WAFObject obj using the provided EncoderConfig and remaining depth allowed.
	// It returns a map of truncation reasons and their respective actual sizes. If the error returned is not nil,
	// it is greatly advised to return errors from the waferrors package error when it matters.
	// Outside of encoding the value, it is expected to check for truncations sizes as advised in the EncoderConfig
	// and to regularly call the EncoderConfig.Timer.Exhausted() method to check if the encoding is still allowed
	// and return waferrors.ErrTimeout if it is not.
	// This method is not expected or required to be safe to concurrently call from multiple goroutines.
	Encode(config EncoderConfig, obj *bindings.WAFObject, depth int) (map[TruncationReason][]int, error)
}

func newEncoder(config EncoderConfig) (*encoder, error) {
	if config.Pinner == nil {
		return nil, fmt.Errorf("pinner cannot be nil")
	}
	if config.Timer == nil {
		config.Timer, _ = timer.NewTimer(timer.WithUnlimitedBudget())
	}
	if config.MaxContainerSize < 0 {
		return nil, fmt.Errorf("invalid max container size: %d (must be >= 0)", config.MaxContainerSize)
	}
	if config.MaxStringSize < 0 {
		return nil, fmt.Errorf("invalid max string size: %d (must be >= 0)", config.MaxStringSize)
	}
	if config.MaxObjectDepth < 0 {
		return nil, fmt.Errorf("invalid max object depth: %d (must be >= 0)", config.MaxObjectDepth)
	}

	return &encoder{config: config}, nil
}

func newEncoderConfig(pinner pin.Pinner, timer timer.Timer) EncoderConfig {
	return EncoderConfig{
		Pinner:           pinner,
		Timer:            timer,
		MaxContainerSize: bindings.MaxContainerSize,
		MaxStringSize:    bindings.MaxStringLength,
		MaxObjectDepth:   bindings.MaxContainerDepth,
	}
}

func newUnlimitedEncoderConfig(pinner pin.Pinner) EncoderConfig {
	return EncoderConfig{
		Pinner:           pinner,
		MaxContainerSize: math.MaxInt,
		MaxStringSize:    math.MaxInt,
		MaxObjectDepth:   math.MaxInt,
	}
}

// Encode takes a Go value and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of nested wafObjects representing the Go value.
// The only error case is if the top-level object is "Unusable" which means that the data is nil or a non-data type
// like a function or a channel.
func (encoder *encoder) Encode(data any) (*bindings.WAFObject, error) {
	value := reflect.ValueOf(data)
	wo := &bindings.WAFObject{}

	err := encoder.encode(value, wo, encoder.config.MaxObjectDepth)

	if _, ok := encoder.truncations[ObjectTooDeep]; ok && !encoder.config.Timer.Exhausted() {
		ctx, cancelCtx := context.WithTimeout(context.Background(), encoder.config.Timer.Remaining())
		defer cancelCtx()

		depth, _ := depthOf(ctx, value)
		encoder.truncations[ObjectTooDeep] = []int{depth}
	}

	return wo, err
}

var (
	jsonNumberType = reflect.TypeFor[json.Number]()
	byteArrayType  = reflect.TypeFor[[]byte]()
)

// isNullableKind returns true if the given kind can be nil.
func isNullableKind(kind reflect.Kind) bool {
	switch kind {
	case reflect.Interface, reflect.Pointer, reflect.UnsafePointer,
		reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return true
	default:
		return false
	}
}

// isValueNil check if the value is nullable and if it is actually nil
// we cannot directly use value.IsNil() because it panics on non-pointer values
func isValueNil(value reflect.Value) bool {
	return isNullableKind(value.Kind()) && value.IsNil()
}

func (encoder *encoder) encode(value reflect.Value, obj *bindings.WAFObject, depth int) error {
	if encoder.config.Timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	if value.IsValid() && value.CanInterface() {
		if encodable, ok := value.Interface().(Encodable); ok {
			truncations, err := encodable.Encode(encoder.config, obj, depth)
			encoder.truncations = merge(encoder.truncations, truncations)
			return err
		}
	}

	value, kind := resolvePointer(value)
	if (kind == reflect.Interface || kind == reflect.Pointer) && !value.IsNil() {
		// resolvePointer failed to resolve to something that's not a pointer, it
		// has indirected too many times...
		return waferrors.ErrTooManyIndirections
	}

	// Measure-only runs for leaves
	if obj == nil && kind != reflect.Array && kind != reflect.Slice && kind != reflect.Map && kind != reflect.Struct {
		// Nothing to do, we were only here to measure object depth!
		return nil
	}

	switch {
	// Terminal cases (leaves of the tree)
	//		Is invalid type: nil interfaces for example, cannot be used to run any reflect method or it's susceptible to panic
	case !value.IsValid() || kind == reflect.Invalid:
		return waferrors.ErrUnsupportedValue
	// 		Is nullable type: nil pointers, channels, maps or functions
	case isValueNil(value):
		obj.SetNil()

	// 		Booleans
	case kind == reflect.Bool:
		obj.SetBool(value.Bool())

	// 		Numbers
	case value.CanInt(): // any int type or alias
		obj.SetInt(value.Int())
	case value.CanUint(): // any Uint type or alias
		obj.SetUint(value.Uint())
	case value.CanFloat(): // any float type or alias
		obj.SetFloat(value.Float())

	// 		json.Number -- string-represented arbitrary precision numbers
	case value.Type() == jsonNumberType:
		encoder.encodeJSONNumber(value.Interface().(json.Number), obj)

	//		Strings
	case kind == reflect.String: // string type
		encoder.encodeString(value.String(), obj)

	case (kind == reflect.Array || kind == reflect.Slice) && value.Type().Elem().Kind() == reflect.Uint8:
		// Byte Arrays are skipped voluntarily because they are often used
		// to do partial parsing which leads to false positives
		return nil

	// Containers (internal nodes of the tree)

	// 		All recursive cases can only execute if the depth is superior to 0.
	case depth <= 0:
		// Record that there was a truncation; we will try to measure the actual depth of the object afterwards.
		encoder.addTruncation(ObjectTooDeep, -1)
		return waferrors.ErrMaxDepthExceeded

	// 		Either an array or a slice of an array
	case kind == reflect.Array || kind == reflect.Slice:
		encoder.encodeArray(value, obj, depth-1)
	case kind == reflect.Map:
		encoder.encodeMap(value, obj, depth-1)
	case kind == reflect.Struct:
		encoder.encodeStruct(value, obj, depth-1)

	default:
		return waferrors.ErrUnsupportedValue
	}

	return nil
}

func (encoder *encoder) encodeJSONNumber(num json.Number, obj *bindings.WAFObject) {
	// Important to attempt int64 first, as this is lossless. Values that are either too small or too
	// large to be represented as int64 can be represented as float64, but this can be lossy.
	if i, err := num.Int64(); err == nil {
		obj.SetInt(i)
		return
	}

	if f, err := num.Float64(); err == nil {
		obj.SetFloat(f)
		return
	}

	// Could not store as int64 nor float, so we'll store it as a string...
	encoder.encodeString(num.String(), obj)
}

func (encoder *encoder) encodeString(str string, obj *bindings.WAFObject) {
	size := len(str)
	if size > encoder.config.MaxStringSize {
		str = str[:encoder.config.MaxStringSize]
		encoder.addTruncation(StringTooLong, size)
	}
	obj.SetString(encoder.config.Pinner, str)
}

var xmlNameType = reflect.TypeFor[xml.Name]()

func getFieldNameFromType(field reflect.StructField) (string, bool) {
	fieldName := field.Name

	// Private and synthetics fields
	if !field.IsExported() {
		return "", false
	}

	// This is the XML namespace/name pair, this isn't technically part of the data.
	if field.Type == xmlNameType {
		return "", false
	}

	// Use the encoding tag name as field name if present
	var contentTypeTag bool
	for _, tagName := range []string{"json", "yaml", "xml", "toml"} {
		tag, ok := field.Tag.Lookup(tagName)
		if !ok {
			continue
		}
		if tag == "-" {
			// Explicitly ignored, note that only "-" causes the field to be ignored,
			// any qualifier ("-,omitempty" or event "-,") will cause the field to be
			// actually named "-" instead of being ignored.
			return "", false
		}
		contentTypeTag = true
		tag, _, _ = strings.Cut(tag, ",")
		switch tag {
		case "":
			// Nothing to do
			continue
		default:
			return tag, true
		}
	}

	// If none of the content-type tags are set, the field name is used; but we
	// specifically exclude those fields tagged as coming from a header, path
	// parameter or query parameter (this is used by labstack/echo.v4, see
	// https://echo.labstack.com/docs/binding).
	if !contentTypeTag {
		for _, tagName := range []string{"header", "path", "query"} {
			if _, ok := field.Tag.Lookup(tagName); ok {
				return "", false
			}
		}
	}

	return fieldName, true
}

// encodeStruct takes a reflect.Value and a wafObject pointer and iterates on the struct field to build
// a wafObject map of type wafMapType. The specificities are the following:
// - It will only take the first encoder.ContainerMaxSize elements of the struct
// - If the field has a json tag it will become the field name
// - Private fields and also values producing an error at encoding will be skipped
// - Even if the element values are invalid or null we still keep them to report the field name
func (encoder *encoder) encodeStruct(value reflect.Value, obj *bindings.WAFObject, depth int) {
	if encoder.config.Timer.Exhausted() {
		return
	}

	typ := value.Type()
	nbFields := typ.NumField()

	capacity := nbFields
	length := 0
	if capacity > encoder.config.MaxContainerSize {
		capacity = encoder.config.MaxContainerSize
	}

	// v2: Maps use WAFObjectKV pairs
	kvArray := obj.SetMap(encoder.config.Pinner, uint64(capacity))
	for i := 0; i < nbFields; i++ {
		if encoder.config.Timer.Exhausted() {
			return
		}

		if length == capacity {
			encoder.addTruncation(ContainerTooLarge, nbFields)
			break
		}

		fieldType := typ.Field(i)
		fieldName, usable := getFieldNameFromType(fieldType)
		if tag, ok := fieldType.Tag.Lookup(AppsecFieldTag); !usable || ok && tag == AppsecFieldTagValueIgnore {
			// Either the struct field is ignored by json marshaling so can we,
			// 		or the field was explicitly set with `ddwaf:ignore`
			continue
		}

		kv := &kvArray[length]
		// Set the key as a string
		encoder.encodeMapKeyString(fieldName, &kv.Key)

		if err := encoder.encode(value.Field(i), &kv.Val, depth); err != nil {
			// We still need to keep the map key, so we can't discard the full object, instead, we make the value a noop
			kv.Val.SetInvalid()
		}

		length++
	}

	// Set the length to the final number of successfully encoded elements
	obj.SetMapSize(uint16(length))
}

// encodeMap takes a reflect.Value and a wafObject pointer and iterates on the map elements and returns
// a wafObject map of type wafMapType. The specificities are the following:
// - It will only take the first encoder.ContainerMaxSize elements of the map
// - Even if the element values are invalid or null we still keep them to report the map key
func (encoder *encoder) encodeMap(value reflect.Value, obj *bindings.WAFObject, depth int) {
	capacity := value.Len()
	if capacity > encoder.config.MaxContainerSize {
		capacity = encoder.config.MaxContainerSize
	}

	// v2: Maps use WAFObjectKV pairs
	kvArray := obj.SetMap(encoder.config.Pinner, uint64(capacity))

	length := 0
	for iter := value.MapRange(); iter.Next(); {
		if encoder.config.Timer.Exhausted() {
			return
		}

		if length == capacity {
			encoder.addTruncation(ContainerTooLarge, value.Len())
			break
		}

		kv := &kvArray[length]
		if err := encoder.encodeMapKey(iter.Key(), &kv.Key); err != nil {
			continue
		}

		if err := encoder.encode(iter.Value(), &kv.Val, depth); err != nil {
			// We still need to keep the map key, so we can't discard the full object, instead, we make the value a noop
			kv.Val.SetInvalid()
		}

		length++
	}

	// Fix the size because we skipped map entries
	obj.SetMapSize(uint16(length))
}

// encodeMapKey takes a reflect.Value and encodes it as a map key WAFObject.
// v2: Keys are now full WAFObjects (typically strings).
func (encoder *encoder) encodeMapKey(value reflect.Value, keyObj *bindings.WAFObject) error {
	value, kind := resolvePointer(value)

	var keyStr string
	switch {
	case kind == reflect.Invalid:
		return waferrors.ErrInvalidMapKey
	case kind == reflect.String:
		keyStr = value.String()
	case value.Type() == byteArrayType:
		keyStr = string(value.Bytes())
	default:
		return waferrors.ErrInvalidMapKey
	}

	encoder.encodeMapKeyString(keyStr, keyObj)
	return nil
}

// encodeMapKeyString encodes a string as a map key WAFObject.
// v2: Keys are full WAFObjects, so we set it as a string.
func (encoder *encoder) encodeMapKeyString(keyStr string, keyObj *bindings.WAFObject) {
	size := len(keyStr)
	if size > encoder.config.MaxStringSize {
		keyStr = keyStr[:encoder.config.MaxStringSize]
		encoder.addTruncation(StringTooLong, size)
	}

	keyObj.SetString(encoder.config.Pinner, keyStr)
}

// encodeArray takes a reflect.Value and a wafObject pointer and iterates on the elements and returns
// a wafObject array of type wafArrayType. The specificities are the following:
// - It will only take the first encoder.ContainerMaxSize elements of the array
// - Elements producing an error at encoding or null values will be skipped
func (encoder *encoder) encodeArray(value reflect.Value, obj *bindings.WAFObject, depth int) {
	length := value.Len()

	capacity := length
	if capacity > encoder.config.MaxContainerSize {
		capacity = encoder.config.MaxContainerSize
	}

	currIndex := 0

	objArray := obj.SetArray(encoder.config.Pinner, uint64(capacity))

	for i := 0; i < length; i++ {
		if encoder.config.Timer.Exhausted() {
			return
		}
		if currIndex == capacity {
			encoder.addTruncation(ContainerTooLarge, length)
			break
		}

		objElem := &objArray[currIndex]
		if err := encoder.encode(value.Index(i), objElem, depth); err != nil {
			continue
		}

		// If the element is null or invalid it has no impact on the waf execution, therefore we can skip its
		// encoding. In this specific case we just overwrite it at the next loop iteration.
		if objElem.IsUnusable() {
			continue
		}

		currIndex++
	}

	// Fix the size because we skipped entries
	obj.SetArraySize(uint16(currIndex))
}

func (encoder *encoder) addTruncation(reason TruncationReason, size int) {
	if encoder.truncations == nil {
		encoder.truncations = make(map[TruncationReason][]int, 3)
	}
	encoder.truncations[reason] = append(encoder.truncations[reason], size)
}

// depthOf returns the depth of the provided object. This is 0 for scalar values,
// such as strings.
func depthOf(ctx context.Context, obj reflect.Value) (depth int, err error) {
	if err = ctx.Err(); err != nil {
		// Timed out, won't go any deeper
		return 0, err
	}

	obj, kind := resolvePointer(obj)

	var itemDepth int
	switch kind {
	case reflect.Array, reflect.Slice:
		if obj.Type() == byteArrayType {
			// We treat byte slices as strings
			return 0, nil
		}
		for i := 0; i < obj.Len(); i++ {
			itemDepth, err = depthOf(ctx, obj.Index(i))
			depth = max(depth, itemDepth)
			if err != nil {
				break
			}
		}
		return depth + 1, err
	case reflect.Map:
		for iter := obj.MapRange(); iter.Next(); {
			itemDepth, err = depthOf(ctx, iter.Value())
			depth = max(depth, itemDepth)
			if err != nil {
				break
			}
		}
		return depth + 1, err
	case reflect.Struct:
		typ := obj.Type()
		for i := 0; i < obj.NumField(); i++ {
			fieldType := typ.Field(i)
			_, usable := getFieldNameFromType(fieldType)
			if !usable {
				continue
			}

			itemDepth, err = depthOf(ctx, obj.Field(i))
			depth = max(depth, itemDepth)
			if err != nil {
				break
			}
		}
		return depth + 1, err
	default:
		return 0, nil
	}
}

// resolvePointer attempts to resolve a pointer while limiting the pointer depth
// to be traversed, so that this is not susceptible to an infinite loop when
// provided a self-referencing pointer.
func resolvePointer(obj reflect.Value) (reflect.Value, reflect.Kind) {
	kind := obj.Kind()
	for limit := 8; limit > 0 && (kind == reflect.Pointer || kind == reflect.Interface); limit-- {
		if obj.IsNil() {
			return obj, kind
		}
		obj = obj.Elem()
		kind = obj.Kind()
	}
	return obj, kind
}
