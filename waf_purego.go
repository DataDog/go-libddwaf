// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && !windows && (amd64 || arm64) && (linux || darwin)

package waf

import (
	"errors"
	"fmt"
	"go.uber.org/atomic"
	"math"
	"os"
	"reflect"
	"strconv"
	"sync"
	"unicode"
	"unsafe"

	"github.com/ebitengine/purego"

	vendor "github.com/DataDog/go-libddwaf/lib/linux-amd64"
)

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
}

var dlState = struct {
	symbolCache map[string]uintptr
	libddwaf    uintptr
	opened      bool
}{
	symbolCache: make(map[string]uintptr),
	libddwaf:    0,
	opened:      false,
}

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
	return string(unsafe.Slice((*byte)(ptr), length))
}

// cstring converts a go string to *byte that can be passed to C code.
func cstring(name string) *byte {
	// Has suffix
	if len(name) >= len("\x00") && name[len(name)-len("\x00"):] == "\x00" {
		return &(*(*[]byte)(unsafe.Pointer(&name)))[0]
	}
	var b = make([]byte, len(name)+1)
	copy(b, name)
	return &b[0]
}

// Using the embeded shared library file, we dump it into a file and load it using dlopen
func loadLib() (uintptr, error) {

	file, err := os.CreateTemp("", "libddwaf-*.so")
	if err != nil {
		return uintptr(0), fmt.Errorf("Error creating temp file: %w", err)
	}

	if err := os.WriteFile(file.Name(), vendor.Libddwaf, 0400); err != nil {
		return uintptr(0), fmt.Errorf("Error writing file: %w", err)
	}

	lib, err := purego.Dlopen(file.Name(), purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return uintptr(0), fmt.Errorf("Error opening shared library at path '%s'. Reason: %s", file.Name(), err)
	}

	return lib, nil
}

// Main utility load library and symbols, also maintains a symbols cache
// TODO(eliott.bouhana): make it thread safe
func getSymbol(symbolName string) uintptr {
	if !dlState.opened {
		lib, err := loadLib()
		if err != nil {
			panic(err)
		}

		dlState.libddwaf = lib
		dlState.opened = true
	}

	if symbol, ok := dlState.symbolCache[symbolName]; ok {
		return symbol
	}

	symbol, err := purego.Dlsym(dlState.libddwaf, symbolName)
	if err != nil {
		panic(err)
	}

	dlState.symbolCache[symbolName] = symbol
	return symbol
}

func Health() error {
	return nil
}

func Version() string {
	symbol := getSymbol("ddwaf_get_version")
	r1, _, _ := purego.SyscallN(symbol)
	return gostring(r1)
}

// Handle represents an instance of the WAF for a given ruleset.
type Handle struct {
	// Instance of the WAF
	handle uintptr

	// Lock-less reference counter avoiding blocking calls to the Close() method
	// while WAF contexts are still using the WAF handle. Instead, we let the
	// release actually happen only when the reference counter reaches 0.
	// This can happen either from a request handler calling its WAF context's
	// Close() method, or either from the appsec instance calling the WAF
	// handle's Close() method when creating a new WAF handle with new rules.
	// Note that this means several instances of the WAF can exist at the same
	// time with their own set of rules. This choice was done to be able to
	// efficiently update the security rules concurrently, without having to
	// block the request handlers for the time of the security rules update.
	refCounter *atomic.Uint32

	// RWMutex protecting the R/W accesses to the internal rules data (stored
	// in the handle).
	mu sync.RWMutex

	// encoder of Go values into ddwaf objects.
	encoder encoder
	// addresses the WAF rule is expecting.
	addresses []string
	// rulesetInfo holds information about rules initialization
	rulesetInfo RulesetInfo
}

// encoder is allows to encode a Go value to a WAF object
type encoder struct {
	// Maximum depth a WAF object can have. Every Go value further this depth is
	// ignored and not encoded into a WAF object.
	maxDepth int
	// Maximum string length. A string longer than this length is truncated to
	// this length.
	maxStringLength int
	// Maximum string length. Everything further this length is ignored.
	maxArrayLength int
	// Maximum map length. Everything further this length is ignored. Given the
	// fact Go maps are unordered, it means WAF map objects created from Go maps
	// larger than this length will have random keys.
	maxMapLength int
}

func (e *encoder) encode(v interface{}) (object *wafObject, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("waf panic: %v", v)
		}
	}()
	wo := &wafObject{}
	err = e.encodeValue(reflect.ValueOf(v), wo, e.maxDepth)
	if err != nil {
		return nil, err
	}
	return wo, nil
}

func (e *encoder) encodeValue(v reflect.Value, wo *wafObject, depth int) error {
	switch kind := v.Kind(); kind {
	default:
		return errUnsupportedValue

	case reflect.Bool:
		var b string
		if v.Bool() {
			b = "true"
		} else {
			b = "false"
		}
		return e.encodeString(b, wo)

	case reflect.Ptr, reflect.Interface:
		// The traversal of pointer and interfaces is not accounted in the depth
		// as it has no impact on the WAF object depth
		return e.encodeValue(v.Elem(), wo, depth)

	case reflect.String:
		return e.encodeString(v.String(), wo)

	case reflect.Struct:
		if depth < 0 {
			return errMaxDepth
		}
		return e.encodeStruct(v, wo, depth-1)

	case reflect.Map:
		if depth < 0 {
			return errMaxDepth
		}
		return e.encodeMap(v, wo, depth-1)

	case reflect.Array, reflect.Slice:
		if depth < 0 {
			return errMaxDepth
		}
		if v.Type() == reflect.TypeOf([]byte(nil)) {
			return e.encodeString(string(v.Bytes()), wo)
		}
		return e.encodeArray(v, wo, depth-1)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.encodeInt64(v.Int(), wo)

	case reflect.Float32, reflect.Float64:
		return e.encodeInt64(int64(math.Round(v.Float())), wo)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.encodeUint64(v.Uint(), wo)
	}
}

func (e *encoder) encodeStruct(v reflect.Value, wo *wafObject, depth int) error {
	// Consider the number of struct fields as the WAF map capacity as some
	// struct fields might not be supported and ignored.
	typ := v.Type()
	nbFields := typ.NumField()
	capacity := nbFields
	if capacity > e.maxMapLength {
		capacity = e.maxMapLength
	}
	wo.setMapContainer(uint64(capacity))
	// Encode struct fields
	length := 0
	for i := 0; length < capacity && i < nbFields; i++ {
		field := typ.Field(i)
		// Skip private fields
		fieldName := field.Name
		if len(fieldName) < 1 || unicode.IsLower(rune(fieldName[0])) {
			continue
		}

		mapEntry := wo.index(uint64(length))
		if err := e.encodeMapKey(reflect.ValueOf(fieldName), mapEntry); !isIgnoredValueError(err) {
			return err
		}

		if err := e.encodeValue(v.Field(i), mapEntry, depth); !isIgnoredValueError(err) {
			return err
		}
		length++
	}
	// Update the map length to the actual one
	if length != capacity {
		wo.setLength(uint64(length))
	}
	return nil
}

func (e *encoder) encodeMap(v reflect.Value, wo *wafObject, depth int) error {
	// Consider the Go map value length the WAF map capacity as some map entries
	// might not be supported and ignored.
	// In this case, the actual map length will be lesser than the Go map value
	// length.
	capacity := v.Len()
	if capacity > e.maxMapLength {
		capacity = e.maxMapLength
	}
	wo.setMapContainer(uint64(capacity))
	// Encode map entries
	length := 0
	for iter := v.MapRange(); iter.Next(); {
		if length == capacity {
			break
		}
		mapEntry := wo.index(uint64(length))
		if err := e.encodeMapKey(iter.Key(), mapEntry); !isIgnoredValueError(err) {
			return err
		}
		if err := e.encodeValue(iter.Value(), mapEntry, depth); !isIgnoredValueError(err) {
			return err
		}
		length++
	}
	// Update the map length to the actual one
	if length != capacity {
		wo.setLength(uint64(length))
	}
	return nil
}

func isIgnoredValueError(err error) bool {
	return err == nil || err == errUnsupportedValue || err == errMaxDepth
}

func (e *encoder) encodeMapKey(v reflect.Value, wo *wafObject) error {
	for {
		switch v.Kind() {
		default:
			return errUnsupportedValue

		case reflect.Ptr, reflect.Interface:
			if v.IsNil() {
				return errUnsupportedValue
			}
			v = v.Elem()

		case reflect.String:
			wo.setMapKey(v.String())
			return nil
		}
	}
}

func (e *encoder) encodeArray(v reflect.Value, wo *wafObject, depth int) error {
	// Consider the array length as a capacity as some array values might not be supported and ignored. In this case,
	// the actual length will be lesser than the Go value length.
	length := v.Len()
	capacity := length
	if capacity > e.maxArrayLength {
		capacity = e.maxArrayLength
	}

	wo.setArrayContainer(uint64(capacity))

	// Walk the array until we successfully added up to "cap" elements or the Go array length was reached
	currIndex := 0
	for i := 0; currIndex < capacity && i < length; i++ {
		if err := e.encodeValue(v.Index(i), wo.index(uint64(currIndex)), depth); err != nil {
			if isIgnoredValueError(err) {
				continue
			}
			return err
		}
		// The value has been successfully encoded and added to the array
		currIndex++
	}
	// Update the array length to its actual value in case some array values where ignored
	if currIndex != capacity {
		wo.setLength(uint64(currIndex))
	}
	return nil
}

func (e *encoder) encodeString(str string, wo *wafObject) error {
	if len(str) >= e.maxStringLength {
		return errMaxDepth
	}

	wo.setString(str)
	return nil
}

func (e *encoder) encodeInt64(n int64, wo *wafObject) error {
	// As of libddwaf v1.0.16, it currently expects numbers as strings
	// TODO(Julio-Guerra): clarify with libddwaf when should it be an actual
	//   int64
	return e.encodeString(strconv.FormatInt(n, 10), wo)
}

func (e *encoder) encodeUint64(n uint64, wo *wafObject) error {
	// As of libddwaf v1.0.16, it currently expects numbers as strings
	// TODO(Julio-Guerra): clarify with libddwaf when should it be an actual
	//   uint64
	return e.encodeString(strconv.FormatUint(n, 10), wo)
}

// Return the pointer to the union field. It can be cast to the union type that needs to be accessed.
func (v *wafObject) valuePtr() unsafe.Pointer   { return unsafe.Pointer(v.value) }
func (v *wafObject) arrayValuePtr() **wafObject { return (**wafObject)(v.valuePtr()) }
func (v *wafObject) int64ValuePtr() *int64      { return (*int64)(v.valuePtr()) }
func (v *wafObject) uint64ValuePtr() *uint64    { return (*uint64)(v.valuePtr()) }

func (v *wafObject) setUint64(n uint64) {
	v._type = wafUintType
	*v.uint64ValuePtr() = n
}

func (v *wafObject) setInt64(n int64) {
	v._type = wafIntType
	*v.int64ValuePtr() = n
}

func (v *wafObject) setString(str string) {
	v._type = wafStringType
	v.nbEntries = uint64(len(str))

	// Has suffix
	if len(str) >= len("\x00") && str[len(str)-len("\x00"):] == "\x00" {
		v.value = uintptr(unsafe.Pointer(&(*(*[]byte)(unsafe.Pointer(&str)))[0]))
	}
	var b = make([]byte, len(str)+1)
	copy(b, str)
	v.value = uintptr(unsafe.Pointer(&b[0]))
}

func (v *wafObject) setInvalid() {
	*v = wafObject{}
}

func (v *wafObject) setContainer(typ wafObjectType, length uint64) {
	if length == 0 {
		return
	}

	var array []wafObject
	for i := uint64(0); i < length; i++ {
		array = append(array, wafObject{})
	}

	v.value = uintptr(unsafe.Pointer(&array))
	v._type = typ
}

func (v *wafObject) setArrayContainer(length uint64) {
	v.setContainer(wafArrayType, length)
}

func (v *wafObject) setMapContainer(length uint64) {
	v.setContainer(wafMapType, length)
}

func (v *wafObject) setMapKey(key string) {
	v.parameterName = uintptr(unsafe.Pointer(cstring(key)))
	v.parameterNameLength = uint64(len(key))
}

func (v *wafObject) mapKey() string {
	return gostring(v.parameterName)
}

func (v *wafObject) setLength(length uint64) {
	v.nbEntries = length
}

func (v *wafObject) length() uint64 {
	return v.nbEntries
}

func (v *wafObject) index(i uint64) *wafObject {
	if i >= v.nbEntries {
		panic(errors.New("out of bounds access to waf array"))
	}
	// Go pointer arithmetic equivalent to the C expression `a->value.array[i]`
	base := uintptr(unsafe.Pointer(*v.arrayValuePtr()))
	return (*wafObject)(unsafe.Pointer(base + unsafe.Sizeof(wafObject{})*uintptr(i))) //nolint:govet
}
