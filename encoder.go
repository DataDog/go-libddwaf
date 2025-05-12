// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"unicode"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/pin"
	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
)

type EncoderConfig struct {
	// Pinner is used to pin the data referenced by the encoded wafObjects.
	Pinner pin.Pinner
	// Timer makes sure the encoder doesn't spend too much time doing its job.
	Timer timer.Timer
	// ContainerMaxSize is the maximum number of elements in a container (list, map, struct) that will be encoded.
	ContainerMaxSize int
	// StringMaxSize is the maximum length of a string that will be encoded.
	StringMaxSize int
	// ObjectMaxDepth is the maximum depth of the object that will be encoded.
	ObjectMaxDepth int
}

// encoder encodes Go values into wafObjects. Only the subset of Go types representable into wafObjects
// will be encoded while ignoring the rest of it.
// The encoder allocates the memory required for new wafObjects into the Go memory, which must be kept
// referenced for their lifetime in the C world. This lifetime depends on the ddwaf function being used with.
// the encoded result. The Go references of the allocated wafObjects, along with every Go pointer they may
// reference now or in the future, are stored and referenced in the `cgoRefs` field. The user MUST leverage
// `keepAlive()` with it according to its ddwaf use-case.
type encoder struct {
	EncoderConfig

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

// Encodable represent a type that can encode itself into a WAFObject.
// The encodable is responsible for using the [pin.Pinner]
// object passed in the [EncoderConfig] to pin the data referenced by the encoded [bindings.WAFObject].
// The encoder must also use the [timer.Timer] passed in the [EncoderConfig] to
// make sure it doesn't spend too much time doing its job.
// The encoder must also respect the [EncoderConfig] limits and report truncations.
type Encodable interface {
	// Encode encodes itself as the WAFObject obj using the provided EncoderConfig and remaining depth allowed.
	// It returns a map of truncation reasons and their respective actual sizes. If the error returned is not nil
	// It is greatly advised to return errors from the waferrors package error when it matters.
	// Outside of encoding the value, it is expected to check for truncations sizes as advised in the EncoderConfig
	// and to regularly call the EncoderConfig.Timer.Exhausted() method to check if the encoding is still allowed
	// and return waferrors.ErrTimeout if it is not.
	// This method is NOT thread-safe.
	Encode(config EncoderConfig, obj *bindings.WAFObject, depth int) (map[TruncationReason][]int, error)
}

func newDefaultEncoder(config EncoderConfig) (*encoder, error) {
	if config.Pinner == nil {
		return nil, fmt.Errorf("pinner cannot be nil")
	}
	if config.Timer == nil {
		config.Timer, _ = timer.NewTimer(timer.WithUnlimitedBudget())
	}
	if config.ContainerMaxSize < 0 {
		return nil, fmt.Errorf("container max size must be greater than 0")
	}
	if config.StringMaxSize < 0 {
		return nil, fmt.Errorf("string max size must be greater than 0")
	}
	if config.ObjectMaxDepth < 0 {
		return nil, fmt.Errorf("object max depth must be greater than 0")
	}

	return &encoder{
		EncoderConfig: config,
	}, nil
}

func newLimitedEncoderConfig(pinner pin.Pinner, timer timer.Timer) EncoderConfig {
	return EncoderConfig{
		Pinner:           pinner,
		Timer:            timer,
		ContainerMaxSize: bindings.MaxContainerSize,
		StringMaxSize:    bindings.MaxStringLength,
		ObjectMaxDepth:   bindings.MaxContainerDepth,
	}
}

func newMaxEncoderConfig(pinner pin.Pinner) EncoderConfig {
	return EncoderConfig{
		Pinner:           pinner,
		ContainerMaxSize: math.MaxInt,
		StringMaxSize:    math.MaxInt,
		ObjectMaxDepth:   math.MaxInt,
	}
}

// Encode takes a Go value and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of nested wafObjects representing the Go value.
// The only error case is if the top-level object is "Unusable" which means that the data is nil or a non-data type
// like a function or a channel.
func (encoder *encoder) Encode(data any) (*bindings.WAFObject, error) {
	value := reflect.ValueOf(data)
	wo := &bindings.WAFObject{}

	err := encoder.encode(value, wo, encoder.ObjectMaxDepth)

	if _, ok := encoder.truncations[ObjectTooDeep]; ok && !encoder.Timer.Exhausted() {
		ctx, cancelCtx := context.WithTimeout(context.Background(), encoder.Timer.Remaining())
		defer cancelCtx()

		depth, _ := depthOf(ctx, value)
		encoder.truncations[ObjectTooDeep] = []int{depth}
	}

	return wo, err
}

// Truncations returns all truncations that happened during the encoder lifetime
func (encoder *encoder) Truncations() map[TruncationReason][]int {
	return encoder.truncations
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

var (
	jsonNumberType = reflect.TypeFor[json.Number]()
	byteArrayType  = reflect.TypeFor[[]byte]()
)

// isValueNil check if the value is nullable and if it is actually nil
// we cannot directly use value.IsNil() because it panics on non-pointer values
func isValueNil(value reflect.Value) bool {
	_, nullable := nullableTypeKinds[value.Kind()]
	return nullable && value.IsNil()
}

func (encoder *encoder) encode(value reflect.Value, obj *bindings.WAFObject, depth int) error {
	if encoder.Timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	if value.IsValid() && value.CanInterface() {
		if encodable, ok := value.Interface().(Encodable); ok {
			truncations, err := encodable.Encode(encoder.EncoderConfig, obj, depth)
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
	if size > encoder.StringMaxSize {
		str = str[:encoder.StringMaxSize]
		encoder.addTruncation(StringTooLong, size)
	}
	obj.SetString(encoder.Pinner, str)
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
// - It will only take the first encoder.ContainerMaxSize elements of the struct
// - If the field has a json tag it will become the field name
// - Private fields and also values producing an error at encoding will be skipped
// - Even if the element values are invalid or null we still keep them to report the field name
func (encoder *encoder) encodeStruct(value reflect.Value, obj *bindings.WAFObject, depth int) {
	if encoder.Timer.Exhausted() {
		return
	}

	typ := value.Type()
	nbFields := typ.NumField()

	capacity := nbFields
	length := 0
	if capacity > encoder.ContainerMaxSize {
		capacity = encoder.ContainerMaxSize
	}

	objArray := obj.SetMap(encoder.Pinner, uint64(capacity))
	for i := 0; i < nbFields; i++ {
		if encoder.Timer.Exhausted() {
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

		objElem := &objArray[length]
		// If the Map key is of unsupported type, skip it
		encoder.encodeMapKeyFromString(fieldName, objElem)

		if err := encoder.encode(value.Field(i), objElem, depth); err != nil {
			// We still need to keep the map key, so we can't discard the full object, instead, we make the value a noop
			objElem.SetInvalid()
		}

		length++
	}

	// Set the length to the final number of successfully encoded elements
	obj.NbEntries = uint64(length)
}

// encodeMap takes a reflect.Value and a wafObject pointer and iterates on the map elements and returns
// a wafObject map of type wafMapType. The specificities are the following:
// - It will only take the first encoder.ContainerMaxSize elements of the map
// - Even if the element values are invalid or null we still keep them to report the map key
func (encoder *encoder) encodeMap(value reflect.Value, obj *bindings.WAFObject, depth int) {
	capacity := value.Len()
	if capacity > encoder.ContainerMaxSize {
		capacity = encoder.ContainerMaxSize
	}

	objArray := obj.SetMap(encoder.Pinner, uint64(capacity))

	length := 0
	for iter := value.MapRange(); iter.Next(); {
		if encoder.Timer.Exhausted() {
			return
		}

		if length == capacity {
			encoder.addTruncation(ContainerTooLarge, value.Len())
			break
		}

		objElem := &objArray[length]
		if err := encoder.encodeMapKey(iter.Key(), objElem); err != nil {
			continue
		}

		if err := encoder.encode(iter.Value(), objElem, depth); err != nil {
			// We still need to keep the map key, so we can't discard the full object, instead, we make the value a noop
			objElem.SetInvalid()
		}

		length++
	}

	// Fix the size because we skipped map entries
	obj.NbEntries = uint64(length)
}

// encodeMapKey takes a reflect.Value and a wafObject and returns a wafObject ready to be considered a map entry. We use
// the function cgoRefPool.AllocWafMapKey to store the key in the wafObject. But first we need to grab the real
// underlying value by recursing through the pointer and interface values.
func (encoder *encoder) encodeMapKey(value reflect.Value, obj *bindings.WAFObject) error {
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

	encoder.encodeMapKeyFromString(keyStr, obj)
	return nil
}

// encodeMapKeyFromString takes a string and a wafObject and sets the map key attribute on the wafObject to the supplied
// string. The key may be truncated if it exceeds the maximum string size allowed by the encoder.
func (encoder *encoder) encodeMapKeyFromString(keyStr string, obj *bindings.WAFObject) {
	size := len(keyStr)
	if size > encoder.StringMaxSize {
		keyStr = keyStr[:encoder.StringMaxSize]
		encoder.addTruncation(StringTooLong, size)
	}

	obj.SetMapKey(encoder.Pinner, keyStr)
}

// encodeArray takes a reflect.Value and a wafObject pointer and iterates on the elements and returns
// a wafObject array of type wafArrayType. The specificities are the following:
// - It will only take the first encoder.ContainerMaxSize elements of the array
// - Elements producing an error at encoding or null values will be skipped
func (encoder *encoder) encodeArray(value reflect.Value, obj *bindings.WAFObject, depth int) {
	length := value.Len()

	capacity := length
	if capacity > encoder.ContainerMaxSize {
		capacity = encoder.ContainerMaxSize
	}

	currIndex := 0

	objArray := obj.SetArray(encoder.Pinner, uint64(capacity))

	for i := 0; i < length; i++ {
		if encoder.Timer.Exhausted() {
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

	// Fix the size because we skipped map entries
	obj.NbEntries = uint64(currIndex)
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
	for limit := 8; limit > 0 && kind == reflect.Pointer || kind == reflect.Interface; limit-- {
		if obj.IsNil() {
			return obj, kind
		}
		obj = obj.Elem()
		kind = obj.Kind()
	}
	return obj, kind
}
