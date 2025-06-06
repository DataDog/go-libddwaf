// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package reflect

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/object"
	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
)

// Encoder encodes Go values into wafObjects. Only the subset of Go types representable into wafObjects
// will be encoded while ignoring the rest of it.
// The Encoder allocates the memory required for new wafObjects into the Go memory, which must be kept
// referenced for their lifetime in the C world. This lifetime depends on the ddwaf function being used with.
// the encoded result. The Go references of the allocated wafObjects, along with every Go pointer they may
// reference now or in the future, are stored and referenced in the `cgoRefs` field. The user MUST leverage
// `keepAlive()` with it according to its ddwaf use-case.
type Encoder struct {
	config object.EncoderConfig

	// For each TruncationReason, holds the size that is required to avoid truncation for each truncation that happened.
	truncations map[object.TruncationReason][]int
}

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
	Encode(config object.EncoderConfig, obj *bindings.WAFObject, depth int) (map[object.TruncationReason][]int, error)
}

const (
	// FieldTag is the key for the struct tag that indicates a field as a custom behavior
	FieldTag = "ddwaf"
	// IgnoreFieldTagValueIgnore is the value for the struct tag that indicates a field should be ignored
	IgnoreFieldTagValueIgnore = "ignore"
)

func NewEncoder(config object.EncoderConfig) (object.Encoder, error) {
	if config.Pinner == nil {
		return nil, fmt.Errorf("pinner cannot be nil")
	}
	if config.Timer == nil {
		config.Timer, _ = timer.NewTimer(timer.WithUnlimitedBudget())
	}
	if config.MaxContainerSize < 0 {
		return nil, fmt.Errorf("container max size must be greater than 0")
	}
	if config.MaxStringLength < 0 {
		return nil, fmt.Errorf("string max size must be greater than 0")
	}
	if config.MaxContainerDepth < 0 {
		return nil, fmt.Errorf("object max depth must be greater than 0")
	}

	return &Encoder{config: config}, nil
}

// Encode takes a Go value and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of nested wafObjects representing the Go value.
// The only error case is if the top-level object is "Unusable" which means that the data is nil or a non-data type
// like a function or a channel.
func (encoder *Encoder) Encode(data any) (*bindings.WAFObject, error) {
	value := reflect.ValueOf(data)
	wo := &bindings.WAFObject{}

	err := encoder.encode(value, wo, encoder.config.MaxContainerDepth)

	if _, ok := encoder.truncations[object.ContainerDepth]; ok && !encoder.config.Timer.Exhausted() {
		ctx, cancelCtx := context.WithTimeout(context.Background(), encoder.config.Timer.Remaining())
		defer cancelCtx()

		depth, _ := depthOf(ctx, value)
		encoder.truncations[object.ContainerDepth] = []int{depth}
	}

	return wo, err
}

func (encoder *Encoder) Truncations() map[object.TruncationReason][]int {
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
	xmlNameType    = reflect.TypeFor[xml.Name]()
	byteArrayType  = reflect.TypeFor[[]byte]()
)

// isValueNil check if the value is nullable and if it is actually nil
// we cannot directly use value.IsNil() because it panics on non-pointer values
func isValueNil(value reflect.Value) bool {
	_, nullable := nullableTypeKinds[value.Kind()]
	return nullable && value.IsNil()
}

func (encoder *Encoder) encode(value reflect.Value, obj *bindings.WAFObject, depth int) error {
	if encoder.config.Timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	if value.IsValid() && value.CanInterface() {
		if encodable, ok := value.Interface().(Encodable); ok {
			truncations, err := encodable.Encode(encoder.config, obj, depth)
			for reason, sizes := range truncations {
				if encoder.truncations == nil {
					encoder.truncations = make(map[object.TruncationReason][]int, 3)
				}
				encoder.truncations[reason] = append(encoder.truncations[reason], sizes...)
			}
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
		encoder.addTruncation(object.ContainerDepth, -1)
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

func (encoder *Encoder) encodeJSONNumber(num json.Number, obj *bindings.WAFObject) {
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

func (encoder *Encoder) encodeString(str string, obj *bindings.WAFObject) {
	size := len(str)
	if size > encoder.config.MaxStringLength {
		str = str[:encoder.config.MaxStringLength]
		encoder.addTruncation(object.StringLength, size)
	}
	obj.SetString(encoder.config.Pinner, str)
}

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
		contentTypeTag = true
		tag, _, _ = strings.Cut(tag, ",")
		switch tag {
		case "":
			// Nothing to do
			continue
		case "-":
			// Explicitly ignored
			return "", false
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
// - It will only take the first Encoder.ContainerMaxSize elements of the struct
// - If the field has a json tag it will become the field name
// - Private fields and also values producing an error at encoding will be skipped
// - Even if the element values are invalid or null we still keep them to report the field name
func (encoder *Encoder) encodeStruct(value reflect.Value, obj *bindings.WAFObject, depth int) {
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

	objArray := obj.SetMap(encoder.config.Pinner, uint64(capacity))
	for i := 0; i < nbFields; i++ {
		if encoder.config.Timer.Exhausted() {
			return
		}

		if length == capacity {
			encoder.addTruncation(object.ContainerSize, nbFields)
			break
		}

		fieldType := typ.Field(i)
		fieldName, usable := getFieldNameFromType(fieldType)
		if tag, ok := fieldType.Tag.Lookup(FieldTag); !usable || ok && tag == IgnoreFieldTagValueIgnore {
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
// - It will only take the first Encoder.ContainerMaxSize elements of the map
// - Even if the element values are invalid or null we still keep them to report the map key
func (encoder *Encoder) encodeMap(value reflect.Value, obj *bindings.WAFObject, depth int) {
	capacity := value.Len()
	if capacity > encoder.config.MaxContainerSize {
		capacity = encoder.config.MaxContainerSize
	}

	objArray := obj.SetMap(encoder.config.Pinner, uint64(capacity))

	length := 0
	for iter := value.MapRange(); iter.Next(); {
		if encoder.config.Timer.Exhausted() {
			return
		}

		if length == capacity {
			encoder.addTruncation(object.ContainerSize, value.Len())
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
func (encoder *Encoder) encodeMapKey(value reflect.Value, obj *bindings.WAFObject) error {
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
// string. The key may be truncated if it exceeds the maximum string size allowed by the Encoder.
func (encoder *Encoder) encodeMapKeyFromString(keyStr string, obj *bindings.WAFObject) {
	size := len(keyStr)
	if size > encoder.config.MaxStringLength {
		keyStr = keyStr[:encoder.config.MaxStringLength]
		encoder.addTruncation(object.StringLength, size)
	}

	obj.SetMapKey(encoder.config.Pinner, keyStr)
}

// encodeArray takes a reflect.Value and a wafObject pointer and iterates on the elements and returns
// a wafObject array of type wafArrayType. The specificities are the following:
// - It will only take the first Encoder.ContainerMaxSize elements of the array
// - Elements producing an error at encoding or null values will be skipped
func (encoder *Encoder) encodeArray(value reflect.Value, obj *bindings.WAFObject, depth int) {
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
			encoder.addTruncation(object.ContainerSize, length)
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

func (encoder *Encoder) addTruncation(reason object.TruncationReason, size int) {
	if encoder.truncations == nil {
		encoder.truncations = make(map[object.TruncationReason][]int, 3)
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
