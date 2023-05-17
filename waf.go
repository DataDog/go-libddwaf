// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows && (amd64 || arm64) && (linux || darwin)

package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"

	"go.uber.org/atomic"

	// Do not remove the following imports which allow supporting package
	// vendoring by properly copying all the files needed by CGO: the libddwaf
	// header file and the static libraries.
	_ "github.com/DataDog/go-libddwaf/include"
	_ "github.com/DataDog/go-libddwaf/lib/darwin-amd64"
	_ "github.com/DataDog/go-libddwaf/lib/darwin-arm64"
	_ "github.com/DataDog/go-libddwaf/lib/linux-amd64"
	_ "github.com/DataDog/go-libddwaf/lib/linux-arm64"
)

//go:linkname cgoCheckPointer runtime.cgoCheckPointer
func cgoCheckPointer(any, any)

var libcWrapper *libcDl
var wafWrapper *wafDl
var wafInitErr error
var wafVersion string

func init() {
	//TODO(eliott.bouhana): move at runtime instead of static init for remote activation
	//	if _, ok := os.LookupEnv("DD_APPSEC_ENABLED"); !ok {
	//		wafInitErr = errors.New("DD_APPSEC_ENABLED env var is not set, not starting the WAF")
	//		return
	//	}

	wafWrapper, wafInitErr = newWafDl()
	if wafInitErr != nil {
		return
	}

	libcWrapper, wafInitErr = newLibcDl()
	if wafInitErr != nil {
		return
	}

	wafVersion = wafWrapper.wafGetVersion()
}

// Health allows knowing if the WAF can be used. It returns a nil error when the WAF library is healthy.
// Otherwise, it returns an error describing the issue.
func Health() error {
	return wafInitErr
}

// Version returns the current version of the WAF
func Version() string {
	return wafVersion
}

// Handle represents an instance of the WAF for a given ruleset.
type Handle struct {
	// Instance of the WAF
	handle wafHandle

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
	refCounter *atomicRefCounter

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

// NewHandle creates a new instance of the WAF with the given JSON rule and key/value regexps for obfuscation.
func NewHandle(jsonRule []byte, keyRegex, valueRegex string) (*Handle, error) {
	var rule interface{}
	if err := json.Unmarshal(jsonRule, &rule); err != nil {
		return nil, fmt.Errorf("could not parse the WAF rule: %v", err)
	}
	return NewHandleFromRuleSet(rule, keyRegex, valueRegex)
}

// NewHandleFromRuleSet creates a new instance of the WAF with the given ruleset and key/value regexps for obfuscation.
func NewHandleFromRuleSet(ruleset interface{}, keyRegex, valueRegex string) (*Handle, error) {
	// Create a temporary unlimited encoder for the rules
	ruleEncoder := newMaxEncoder()
	wafRule, err := ruleEncoder.encode(ruleset)
	if err != nil {
		return nil, fmt.Errorf("could not encode the WAF ruleset into a WAF object: %v", err)
	}
	defer freeWO(wafRule)

	// Run-time encoder limiting the size of the encoded values
	encoder := encoder{
		maxDepth:        wafMaxContainerDepth,
		maxStringLength: wafMaxStringLength,
		maxArrayLength:  wafMaxContainerSize,
		maxMapLength:    wafMaxContainerSize,
	}
	var wafRInfo wafRulesetInfo
	keyRegexC, _, err := cstringLimited(keyRegex, encoder.maxStringLength)
	if err != nil {
		return nil, fmt.Errorf("could not convert the obfuscator key regexp string to a C string: %v", err)
	}
	defer cFree(uintptr(unsafe.Pointer(keyRegexC)))
	valueRegexC, _, err := cstringLimited(valueRegex, encoder.maxStringLength)
	if err != nil {
		return nil, fmt.Errorf("could not convert the obfuscator value regexp to a C string: %v", err)
	}
	defer cFree(uintptr(unsafe.Pointer(valueRegexC)))
	wafCfg := wafConfig{
		limits: wafConfigLimits{
			maxContainerSize:  uint32(encoder.maxArrayLength),
			maxContainerDepth: uint32(encoder.maxDepth),
			maxStringLength:   uint32(encoder.maxStringLength),
		},
		obfuscator: wafConfigObfuscator{
			keyRegex:   uintptr(unsafe.Pointer(keyRegexC)),
			valueRegex: uintptr(unsafe.Pointer(valueRegexC)),
		},
		freeFn: 0,
	}
	defer wafWrapper.wafRulesetInfoFree(&wafRInfo)

	handle := wafWrapper.wafInit(wafRule, &wafCfg, &wafRInfo)
	if handle == 0 {
		return nil, errors.New("could not instantiate the waf rule")
	}

	// Decode the ruleset information returned by the WAF
	errors, err := decodeErrors((*wafObject)(&wafRInfo.errors))
	if err != nil {
		wafWrapper.wafDestroy(handle)
		return nil, err
	}
	rInfo := RulesetInfo{
		Failed:  uint16(wafRInfo.failed),
		Loaded:  uint16(wafRInfo.loaded),
		Version: gostring(wafRInfo.version),
		Errors:  errors,
	}
	// Get the addresses the rule listens to
	addresses := wafWrapper.wafRequiredAddresses(handle)
	if addresses == nil {
		wafWrapper.wafDestroy(handle)
		return nil, ErrEmptyRuleAddresses
	}
	return &Handle{
		handle:      handle,
		refCounter:  (*atomicRefCounter)(atomic.NewUint32(1)),
		encoder:     encoder,
		addresses:   addresses,
		rulesetInfo: rInfo,
	}, nil
}

// Increment the ref counter and return true if the handle can be used, false
// otherwise.
func (h *Handle) incrementReferences() bool {
	return h.refCounter.increment() != 0
}

// Decrement the ref counter and release the memory when 0 is reached.
func (h *Handle) decrementReferences() {
	if h.refCounter.decrement() == 0 {
		h.release()
	}
}

// Actual memory release of the WAF handle.
func (h *Handle) release() {
	if h.handle == 0 {
		return // already released - only happens if Close() is called more than once
	}
	wafWrapper.wafDestroy(h.handle)
	h.handle = 0
}

// Addresses returns the list of addresses the WAF rule is expecting.
func (h *Handle) Addresses() []string {
	return h.addresses
}

// RulesetInfo returns the rules initialization metrics for the current WAF handle
func (h *Handle) RulesetInfo() RulesetInfo {
	return h.rulesetInfo
}

// Close the WAF handle. Note that this call doesn't block until the handle gets
// released but instead let WAF contexts still use it until there's no more (eg.
// when swapping the WAF handle with a new one).
func (h *Handle) Close() {
	h.decrementReferences()
}

// Context is a WAF execution context. It allows to run the WAF incrementally
// by calling it multiple times to run its rules every time new addresses
// become available. Each request must have its own Context.
type Context struct {
	// Instance of the WAF
	handle *Handle
	// Cumulated internal WAF run time - in nanoseconds - for this context.
	totalRuntimeNs AtomicU64
	// Cumulated overall run time - in nanoseconds - for this context.
	totalOverallRuntimeNs AtomicU64
	// Cumulated timeout count for this context.
	timeoutCount AtomicU64

	context wafContext
	// Mutex protecting the use of context which is not thread-safe.
	mu sync.Mutex
	// wafObjects objects generated by ddwaf_run need to be alive during all the context duration
	wafObjects []*wafObject
}

// NewContext creates a new WAF context and increases the number of references
// to the WAF handle.
// A nil value is returned when the WAF handle can no longer be used or the
// WAF context couldn't be created.
func NewContext(handle *Handle) *Context {
	if !handle.incrementReferences() {
		return nil // The WAF handle got released
	}
	context := wafWrapper.wafContextInit(handle.handle)
	if context == 0 {
		handle.decrementReferences()
		return nil
	}
	return &Context{
		handle:  handle,
		context: context,
	}
}

// Run the WAF with the given Go values and timeout.
func (c *Context) Run(values map[string]interface{}, timeout time.Duration) (matches []byte, actions []string, err error) {
	now := time.Now()
	defer func() {
		dt := time.Since(now)
		c.totalOverallRuntimeNs.Add(uint64(dt.Nanoseconds()))
	}()

	if len(values) == 0 {
		return
	}

	wafValue, err := c.handle.encoder.encode(values)
	defer runtime.KeepAlive(wafValue)
	if err != nil {
		return nil, nil, err
	}

	c.wafObjects = append(c.wafObjects, wafValue)
	return c.run(wafValue, timeout)
}

// run is the critical section of Run
func (c *Context) run(data *wafObject, timeout time.Duration) (matches []byte, actions []string, err error) {
	// Exclusively lock this WAF context for the time of this run
	c.mu.Lock()
	defer c.mu.Unlock()
	// RLock the handle to safely get read access to the WAF handle and prevent concurrent changes of it
	// such as a rules-data update.

	c.handle.mu.RLock()
	defer c.handle.mu.RUnlock()

	var result wafResult
	defer freeWAFResult(&result)

	rc := wafWrapper.wafRun(c.context, data, &result, uint64(timeout/time.Microsecond))

	c.totalRuntimeNs.Add(uint64(result.total_runtime))

	matches, actions, err = goReturnValues(rc, &result)
	if err == ErrTimeout {
		c.timeoutCount.Inc()
	}

	return matches, actions, err
}

// Close the WAF context by releasing its C memory and decreasing the number of
// references to the WAF handle.
func (c *Context) Close() {
	// RUnlock the WAF RWMutex to decrease the count of WAF Contexts using it.
	defer c.handle.decrementReferences()
	wafWrapper.wafContextDestroy(c.context)

	// The recursive way to free a wafObject is to use freeWO
	// But ddwaf_context_destroy has already destroyed all the wafObjects except the top level ones
	// so we only need to free the top-level objects
	for _, obj := range c.wafObjects {
		cFree(uintptr(unsafe.Pointer(obj)))
	}
}

// TotalRuntime returns the cumulated WAF runtime across various run calls within the same WAF context.
// Returned time is in nanoseconds.
func (c *Context) TotalRuntime() (overallRuntimeNs, internalRuntimeNs uint64) {
	return c.totalOverallRuntimeNs.Load(), c.totalRuntimeNs.Load()
}

// TotalTimeouts returns the cumulated amount of WAF timeouts across various run calls within the same WAF context.
func (c *Context) TotalTimeouts() uint64 {
	return c.timeoutCount.Load()
}

// Translate libddwaf return values into return values suitable to a Go program.
// Note that it is possible to have matches or actions even if err is not nil in
// case of a timeout during the WAF call.
func goReturnValues(rc wafReturnCode, result *wafResult) (matches []byte, actions []string, err error) {
	if result.timeout != 0 {
		err = ErrTimeout
	}

	switch rc {
	case wafOK:
		return nil, nil, err

	case wafMatch:
		if result.data != 0 {
			strlen := libcWrapper.strlen(uintptr(unsafe.Pointer(result.data)))
			matches = make([]byte, strlen)
			copy(matches, unsafe.Slice((*byte)(unsafe.Pointer(result.data)), strlen))
		}
		if size := result.actions.size; size > 0 {
			cactions := result.actions.array
			actions = make([]string, size)
			for i := 0; i < int(size); i++ {
				actions[i] = gostring(uintptr(unsafe.Pointer(cindexCharPtrArray(cactions, i))))
			}
		}
		return matches, actions, err

	default:
		return nil, nil, goRunError(rc)
	}
}

func goRunError(rc wafReturnCode) error {
	switch rc {
	case wafErrInternal:
		return ErrInternal
	case wafErrInvalidObject:
		return ErrInvalidObject
	case wafErrInvalidArgument:
		return ErrInvalidArgument
	default:
		return fmt.Errorf("unknown waf return code %d", int(rc))
	}
}

// Errors the encoder and decoder can return.
var (
	errMaxDepth         = errors.New("max depth reached")
	errUnsupportedValue = errors.New("unsupported Go value")
	errOutOfMemory      = errors.New("out of memory")
	errInvalidMapKey    = errors.New("invalid WAF object map key")
	errNilObjectPtr     = errors.New("nil WAF object pointer")
)

// isIgnoredValueError returns true if the error is only about ignored Go values
// (errUnsupportedValue or errMaxDepth).
func isIgnoredValueError(err error) bool {
	return err == errUnsupportedValue || err == errMaxDepth
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

func newMaxEncoder() *encoder {
	const intSize = 32 << (^uint(0) >> 63) // copied from recent versions of math.MaxInt
	const maxInt = 1<<(intSize-1) - 1      // copied from recent versions of math.MaxInt
	return &encoder{
		maxDepth:        maxInt,
		maxStringLength: maxInt,
		maxArrayLength:  maxInt,
		maxMapLength:    maxInt,
	}
}

func (e *encoder) encode(v interface{}) (object *wafObject, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("waf panic: %v", v)
		}
		if err != nil && object != nil {
			freeWO(object)
		}
	}()

	wo := (*wafObject)(unsafe.Pointer(libcWrapper.calloc(1, uint64(unsafe.Sizeof(wafObject{})))))
	if wo == nil {
		return nil, ErrOutOfMemory
	}

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
	if err := wo.setMapContainer(uint64(capacity)); err != nil {
		return err
	}
	// Encode struct fields
	length := 0
	for i := 0; length < capacity && i < nbFields; i++ {
		field := typ.Field(i)
		// Skip private fields
		fieldName := field.Name
		if len(fieldName) < 1 || unicode.IsLower(rune(fieldName[0])) {
			continue
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

		mapEntry := wo.index(uint64(length))
		if err := e.encodeMapKey(reflect.ValueOf(fieldName), mapEntry); isIgnoredValueError(err) {
			continue
		}

		if err := e.encodeValue(v.Field(i), mapEntry, depth); err != nil {
			// Free the map entry in order to free the previously allocated map key
			freeWO(mapEntry)
			if isIgnoredValueError(err) {
				continue
			}
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
	if err := wo.setMapContainer(uint64(capacity)); err != nil {
		return err
	}
	// Encode map entries
	length := 0
	for iter := v.MapRange(); iter.Next(); {
		if length == capacity {
			break
		}
		mapEntry := wo.index(uint64(length))
		if err := e.encodeMapKey(iter.Key(), mapEntry); isIgnoredValueError(err) {
			continue
		}
		if err := e.encodeValue(iter.Value(), mapEntry, depth); err != nil {
			// Free the previously allocated map key
			freeWO(mapEntry)
			if isIgnoredValueError(err) {
				continue
			}
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
			ckey, length, err := cstringLimited(v.String(), e.maxStringLength)
			if err != nil {
				return err
			}
			wo.setMapKey(ckey, uint64(length))
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
	if err := wo.setArrayContainer(uint64(capacity)); err != nil {
		return err
	}
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
	cstr, length, err := cstringLimited(str, e.maxStringLength)
	if err != nil {
		return err
	}
	wo.setString(cstr, uint64(length))
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

func decodeErrors(wo *wafObject) (map[string]interface{}, error) {
	v, err := decodeMap(wo)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		v = nil // enforce a nil map when the ddwaf map was empty
	}
	return v, nil
}

func decodeObject(wo *wafObject) (v interface{}, err error) {
	if wo == nil {
		return nil, errNilObjectPtr
	}
	switch wo._type {
	case wafUintType:
		return uint64(*wo.uint64ValuePtr()), nil
	case wafIntType:
		return int64(*wo.int64ValuePtr()), nil
	case wafStringType:
		return gostringSized(*wo.stringValuePtr(), wo.length()), nil
	case wafArrayType:
		return decodeArray(wo)
	case wafMapType: // could be a map or a struct, no way to differentiate
		return decodeMap(wo)
	default:
		return nil, errUnsupportedValue
	}
}

func decodeArray(wo *wafObject) ([]interface{}, error) {
	if wo == nil {
		return nil, errNilObjectPtr
	}
	var err error
	len := wo.length()
	arr := make([]interface{}, len)
	for i := uint64(0); i < len && err == nil; i++ {
		arr[i], err = decodeObject(wo.index(i))
	}
	return arr, err
}

func decodeMap(wo *wafObject) (map[string]interface{}, error) {
	if wo == nil || (wo.value == 0 && wo.length() > 0) {
		return nil, errNilObjectPtr
	}
	length := wo.length()
	decodedMap := make(map[string]interface{}, length)
	for i := uint64(0); i < length; i++ {
		obj := wo.index(i)
		key, err := decodeMapKey(obj)
		if err != nil {
			return nil, err
		}
		val, err := decodeObject(obj)
		if err != nil {
			return nil, err
		}
		decodedMap[key] = val
	}
	return decodedMap, nil
}

func decodeMapKey(wo *wafObject) (string, error) {
	if wo == nil {
		return "", errNilObjectPtr
	}
	if wo.parameterNameLength == 0 || wo.mapKey() == nil {
		return "", errInvalidMapKey
	}
	return gostringSized(wo.mapKey(), wo.parameterNameLength), nil
}

// Return the pointer to the union field. It can be cast to the union type that needs to be accessed.
func (v *wafObject) valuePtr() unsafe.Pointer   { return unsafe.Pointer(&v.value) }
func (v *wafObject) arrayValuePtr() **wafObject { return (**wafObject)(v.valuePtr()) }
func (v *wafObject) int64ValuePtr() *int64      { return (*int64)(v.valuePtr()) }
func (v *wafObject) uint64ValuePtr() *uint64    { return (*uint64)(v.valuePtr()) }
func (v *wafObject) stringValuePtr() **byte     { return (**byte)(v.valuePtr()) }

func (v *wafObject) setUint64(n uint64) {
	v._type = wafUintType
	*v.uint64ValuePtr() = n
}

func (v *wafObject) setInt64(n int64) {
	v._type = wafIntType
	*v.int64ValuePtr() = n
}

func (v *wafObject) setString(str *byte, length uint64) {
	v._type = wafStringType
	v.nbEntries = length
	*v.stringValuePtr() = str
}

func (v *wafObject) string() *byte {
	return *v.stringValuePtr()
}

func (v *wafObject) setInvalid() {
	*v = wafObject{}
}

func (v *wafObject) setContainer(typ wafObjectType, length uint64) error {
	// Allocate the zero'd array.
	var a *wafObject
	if length > 0 {
		a = (*wafObject)(unsafe.Pointer(libcWrapper.calloc(length, uint64(unsafe.Sizeof(*a)))))
		if a == nil {
			return ErrOutOfMemory
		}
		*v.arrayValuePtr() = a
		v.setLength(length)
	}
	v._type = typ
	return nil
}

func (v *wafObject) setArrayContainer(length uint64) error {
	return v.setContainer(wafArrayType, length)
}

func (v *wafObject) setMapContainer(length uint64) error {
	return v.setContainer(wafMapType, length)
}

func (v *wafObject) setMapKey(key *byte, length uint64) {
	v.parameterName = uintptr(unsafe.Pointer(key))
	v.parameterNameLength = length
}

func (v *wafObject) mapKey() *byte {
	return (*byte)(unsafe.Pointer(v.parameterName))
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
	return (*wafObject)(unsafe.Add(unsafe.Pointer(*v.arrayValuePtr()), unsafe.Sizeof(*v)*uintptr(i)))
	//base := uintptr(unsafe.Pointer(*v.arrayValuePtr()))
	//return (*wafObject)(unsafe.Pointer(base + unsafe.Sizeof(*v)*uintptr(i))) //nolint:govet
}

// Helper functions for testing, where direct cgo import is not allowed
func toCInt64(v int) int64 {
	return int64(v)
}
func toCUint64(v uint) uint64 {
	return uint64(v)
}

// cstring returns the C string of the given Go string `str` with up to maxWAFStringSize bytes, along with the string
// size that was allocated and copied.
func cstringLimited(str string, maxLength int) (*byte, int, error) {
	// Limit the maximum string size to copy
	l := uint64(len(str))
	if l > uint64(maxLength) {
		l = uint64(maxLength)
	}

	// Copy the string up to l.
	// The copy is required as the pointer will be stored into the C structures,
	// so using a Go pointer is impossible.
	cstr := (*byte)(unsafe.Pointer(libcWrapper.calloc(l+1, 1)))
	if cstr == nil {
		return nil, 0, errOutOfMemory
	}
	cstrSlice := unsafe.Slice(cstr, l)
	copy(cstrSlice, str[:])
	return cstr, int(l), nil
}

func freeWO(v *wafObject) {
	if v == nil {
		return
	}
	// Free the map key if any
	if key := v.mapKey(); key != nil {
		cFree(v.parameterName)
	}
	// Free allocated values
	switch v._type {
	case wafInvalidType:
		return
	case wafStringType:
		cFree(uintptr(unsafe.Pointer(v.string())))
	case wafMapType, wafArrayType:
		freeWOContainer(v)
	}
	// Make the value invalid to make it unusable
	v.setInvalid()
}

func freeWOContainer(v *wafObject) {
	length := v.length()
	for i := uint64(0); i < length; i++ {
		freeWO(v.index(i))
	}
	if a := *v.arrayValuePtr(); a != nil {
		cFree(uintptr(unsafe.Pointer(a)))
	}
}

func cFree(ptr uintptr) {
	libcWrapper.free(ptr)
}

// Go reimplementation of ddwaf_result_free to avoid yet another CGO call in the
// request hot-path and avoiding it when there are no results to free.
func freeWAFResult(result *wafResult) {
	if data := result.data; data != 0 {
		libcWrapper.free(data)
	}

	if array := result.actions.array; array != nil {
		for i := 0; i < int(result.actions.size); i++ {
			libcWrapper.free(uintptr(unsafe.Pointer(cindexCharPtrArray(array, i))))
		}
		libcWrapper.free(uintptr(unsafe.Pointer(array)))
	}
}

// Helper function to access to i-th element of the given **C.char array.
func cindexCharPtrArray(array *uintptr, i int) *byte {
	// Go pointer arithmetic equivalent to the C expression `array[i]`
	base := uintptr(unsafe.Pointer(array))
	return *(**byte)(unsafe.Pointer(base + unsafe.Sizeof((*byte)(nil))*uintptr(i))) //nolint:govet
}

// Atomic reference counter helper initialized at 1 so that 0 is the special
// value meaning that the object was released and is no longer usable.
type atomicRefCounter atomic.Uint32

func (c *atomicRefCounter) unwrap() *atomic.Uint32 {
	return (*atomic.Uint32)(c)
}

// Add delta to reference counter.
// It relies on a CAS spin-loop implementation in order to avoid changing the
// counter when 0 has been reached.
func (c *atomicRefCounter) add(delta uint32) uint32 {
	addr := c.unwrap()
	for {
		current := addr.Load()
		if current == 0 {
			// The object was released
			return 0
		}
		new := current + delta
		if swapped := addr.CompareAndSwap(current, new); swapped {
			return new
		}
	}
}

// Increment the reference counter.
// CAS spin-loop implementation in order to enforce +1 cannot happen when 0 has
// been reached.
func (c *atomicRefCounter) increment() uint32 {
	return c.add(1)
}

// Decrement the reference counter.
// CAS spin-loop implementation in order to enforce +1 cannot happen when 0 has
// been reached.
func (c *atomicRefCounter) decrement() uint32 {
	const d = ^uint32(0)
	return c.add(d)
}
