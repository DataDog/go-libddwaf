// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && !windows && (amd64 || arm64) && (linux || darwin)

package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unsafe"

	"go.uber.org/atomic"

	"github.com/ebitengine/purego"

	vendor "github.com/DataDog/go-libddwaf/lib/darwin-arm64"
)

const (
	wafMaxStringLength = 4096
	wafMaxContainerDepth = 20
	wafMaxContainerSize = 256
	wafRunTimeout = 5000

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
	_                   [4]byte
}

type wafConfig struct {
	limits     wafConfigLimits
	obfuscator wafConfigObfuscator
	free_fn    uintptr
}

type wafConfigLimits struct {
	max_container_size  uint32
	max_container_depth uint32
	max_string_length   uint32
}

type wafConfigObfuscator struct {
	key_regex   uintptr
	value_regex uintptr
}

type wafResult struct {
	timeout       byte
	data          uintptr
	actions       wafResultActions
	total_runtime uint64
}

type wafResultActions struct {
	array *uintptr
	size  uint32
	_     [4]byte
}

type wafRulesetInfo struct {
	loaded  uint16
	failed  uint16
	errors  wafObject
	version uintptr
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

	// Create a temporary unlimited encoder for the rules
	ruleEncoder := encoder{
		maxDepth:        math.MaxInt32,
		maxStringLength: math.MaxInt32,
		maxArrayLength:  math.MaxInt32,
		maxMapLength:    math.MaxInt32,
	}
	wafRule, err := ruleEncoder.encode(rule)
	if err != nil {
		return nil, fmt.Errorf("could not encode the JSON WAF rule into a WAF object: %v", err)
	}

	// Run-time encoder limiting the size of the encoded values
	encoder := encoder{
		maxDepth:        wafMaxContainerDepth,
		maxStringLength: wafMaxStringLength,
		maxArrayLength:  wafMaxContainerSize,
		maxMapLength:    wafMaxContainerSize,
	}
	var wafRInfo wafRulesetInfo
	wafCfg := wafConfig{
		limits: struct{ max_container_size, max_container_depth, max_string_length uint32 }{
			max_container_size:  encoder.maxArrayLength,
			max_container_depth: encoder.maxMapLength,
			max_string_length:   encoder.maxStringLength,
		},
		obfuscator: wafConfigObfuscator{
			key_regex:   uintptr(unsafe.Pointer(cstring(keyRegex))),
			value_regex: uintptr(unsafe.Pointer(cstring(valueRegex))),
		},
		free_fn: 0,
	}

	defer func() {
		ddwaf_ruleset_info_free := getSymbol("ddwaf_ruleset_info_free")
		purego.SyscallN(ddwaf_ruleset_info_free, uintptr(unsafe.Pointer(&wafRInfo)))
	}()
	
	ddwaf_init := getSymbol("ddwaf_init")
	handle, _, _ := purego.SyscallN(ddwaf_init, uintptr(unsafe.Pointer(wafRule)), uintptr(unsafe.Pointer(&wafCfg)), uintptr(unsafe.Pointer(&wafRInfo)))
	if handle == 0 {
		return nil, errors.New("could not instantiate the waf rule")
	}

	// Decode the ruleset information returned by the WAF
	errors, err := decodeErrors((*wafObject)(&wafRInfo.errors))
	if err != nil {
		ddwaf_destroy := getSymbol("ddwaf_destroy")
		purego.SyscallN(ddwaf_destroy, handle)
		return nil, err
	}

	rInfo := RulesetInfo{
		Failed:  uint16(wafRInfo.failed),
		Loaded:  uint16(wafRInfo.loaded),
		Version: gostring(wafRInfo.version),
		Errors:  errors,
	}
	// Get the addresses the rule listens to
	addresses, err := ruleAddresses(handle)
	if err != nil {
		ddwaf_destroy := getSymbol("ddwaf_destroy")
		purego.SyscallN(ddwaf_destroy, handle)
		return nil, err
	}

	return &Handle{
		handle:      handle,
		refCounter:  (*atomicRefCounter)(atomic.NewUint32(1)),
		encoder:     encoder,
		addresses:   addresses,
		rulesetInfo: rInfo,
	}, nil
}

// Actual memory release of the WAF handle.
func (h *Handle) release() {
	if h.handle == 0 {
		return // already released - only happens if Close() is called more than once
	}
	ddwaf_destroy := getSymbol("ddwaf_destroy")
	purego.SyscallN(ddwaf_destroy, h.handle)
	h.handle = 0
}

func ruleAddresses(handle uintptr) ([]string, error) {
	var nbAddresses uint32
	ddwaf_required_addresses := getSymbol("ddwaf_required_addresses")
	caddresses, _, _ := purego.SyscallN(ddwaf_required_addresses, handle, uintptr(unsafe.Pointer(&nbAddresses)))
	if nbAddresses == 0 {
		return nil, ErrEmptyRuleAddresses
	}
	addresses := make([]string, int(nbAddresses))
	for i := 0; i < len(addresses); i++ {
		addresses[i] = gostring(cindexCharPtrArray((*uintptr)(unsafe.Pointer(caddresses)), i))
	}
	return addresses, nil
}

// Addresses returns the list of addresses the WAF rule is expecting.
func (h *Handle) Addresses() []string {
	return h.addresses
}

// RulesetInfo returns the rules initialization metrics for the current WAF handle
func (h *Handle) RulesetInfo() RulesetInfo {
	return h.rulesetInfo
}

// UpdateRuleData updates the data that some rules reference to.
// The given rule data must be a raw JSON string of the form
// [ {rule data #1}, ... {rule data #2} ]
func (h *Handle) UpdateRuleData(jsonData []byte) error {
	var data []interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("could not parse the WAF rule data: %v", err)
	}

	encoded, err := h.encoder.encode(data) // FIXME: double-check with Anil that we are good with the current conversion of integers into strings here
	if err != nil {
		return fmt.Errorf("could not encode the JSON WAF rule data into a WAF object: %v", err)
	}

	return h.updateRuleData(encoded)
}

// updateRuleData is the critical section of UpdateRuleData
func (h *Handle) updateRuleData(data *wafObject) error {
	// Note about this lock: ddwaf_update_rule_data already is thread-safe to
	// use, but we chose to lock at the goroutine-level instead in order to
	// avoid locking OS threads and therefore prevent many other goroutines from
	// executing during that OS lock. If a goroutine locks due to this handle's
	// RWMutex, another goroutine gets executed on its OS thread.
	h.mu.Lock()
	defer h.mu.Unlock()

	ddwaf_update_rule_data := getSymbol("ddwaf_update_rule_data")
	rc, _, _ := purego.SyscallN(ddwaf_update_rule_data, h.handle, uintptr(unsafe.Pointer(data)))
	if rc != OK {
		return fmt.Errorf("unexpected error number `%d` while updating the WAF rule data", rc)
	}
	return nil
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

	context uintptr
	// Mutex protecting the use of context which is not thread-safe.
	mu sync.Mutex
}

// NewContext creates a new WAF context and increases the number of references
// to the WAF handle.
// A nil value is returned when the WAF handle can no longer be used or the
// WAF context couldn't be created.
func NewContext(handle *Handle) *Context {
	if !handle.incrementReferences() {
		return nil // The WAF handle got released
	}

	ddwaf_context_init := getSymbol("ddwaf_context_init")

	context, _, _ := purego.SyscallN(ddwaf_context_init, handle.handle)
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
	if err != nil {
		return nil, nil, err
	}

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
	ddwaf_run := getSymbol("ddwaf_run")
	rc, _, _ := purego.SyscallN(ddwaf_run, c.context, uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(&result)), uintptr(uint64(timeout/time.Microsecond)))

	c.totalRuntimeNs.Add(uint64(result.total_runtime))

	matches, actions, err = goReturnValues(int(rc), &result)
	if err == ErrTimeout {
		c.timeoutCount.Inc()
	}

	return matches, actions, err
}

// Translate libddwaf return values into return values suitable to a Go program.
// Note that it is possible to have matches or actions even if err is not nil in
// case of a timeout during the WAF call.
func goReturnValues(rc int, result *wafResult) (matches []byte, actions []string, err error) {
	if result.timeout != 0 {
		err = ErrTimeout
	}

	if rc != OK && rc != Match {
		return nil, nil, goRunError(rc)
	}

	switch rc {
	case OK:
		return nil, nil, err

	case Match:
		if result.data != 0 {
			matches = []byte(gostring(result.data))
		}
		if size := result.actions.size; size > 0 {
			cactions := result.actions.array
			actions = make([]string, size)
			for i := 0; i < int(size); i++ {
				actions[i] = gostring(cindexCharPtrArray(cactions, i))
			}
		}
		return matches, actions, err

	default:
		return nil, nil, goRunError(rc)
	}
}

func goRunError(rc int) error {
	switch rc {
	case int(ErrInternal):
		return ErrInternal
	case int(ErrInvalidObject):
		return ErrInvalidObject
	case int(ErrInvalidArgument):
		return ErrInvalidArgument
	default:
		return fmt.Errorf("unknown waf return code %d", int(rc))
	}
}

// Close the WAF context by releasing its C memory and decreasing the number of
// references to the WAF handle.
func (c *Context) Close() {
	// RUnlock the WAF RWMutex to decrease the count of WAF Contexts using it.
	defer c.handle.decrementReferences()
	ddwaf_context_destroy := getSymbol("ddwaf_context_destroy")
	purego.SyscallN(ddwaf_context_destroy, c.context)
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

// encoder is allows to encode a Go value to a WAF object
type encoder struct {
	// Maximum depth a WAF object can have. Every Go value further this depth is
	// ignored and not encoded into a WAF object.
	maxDepth uint32
	// Maximum string length. A string longer than this length is truncated to
	// this length.
	maxStringLength uint32
	// Maximum string length. Everything further this length is ignored.
	maxArrayLength uint32
	// Maximum map length. Everything further this length is ignored. Given the
	// fact Go maps are unordered, it means WAF map objects created from Go maps
	// larger than this length will have random keys.
	maxMapLength uint32
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

func (e *encoder) encodeValue(v reflect.Value, wo *wafObject, depth uint32) error {
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

func (e *encoder) encodeStruct(v reflect.Value, wo *wafObject, depth uint32) error {
	// Consider the number of struct fields as the WAF map capacity as some
	// struct fields might not be supported and ignored.
	typ := v.Type()
	nbFields := typ.NumField()
	capacity := nbFields
	if uint32(capacity) > e.maxMapLength {
		capacity = int(e.maxMapLength)
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

func (e *encoder) encodeMap(v reflect.Value, wo *wafObject, depth uint32) error {
	// Consider the Go map value length the WAF map capacity as some map entries
	// might not be supported and ignored.
	// In this case, the actual map length will be lesser than the Go map value
	// length.
	capacity := v.Len()
	if uint32(capacity) > e.maxMapLength {
		capacity = int(e.maxMapLength)
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

func (e *encoder) encodeArray(v reflect.Value, wo *wafObject, depth uint32) error {
	// Consider the array length as a capacity as some array values might not be supported and ignored. In this case,
	// the actual length will be lesser than the Go value length.
	length := v.Len()
	capacity := length
	if uint32(capacity) > e.maxArrayLength {
		capacity = int(e.maxArrayLength)
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
	if uint32(len(str)) >= e.maxStringLength {
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
		return gostring(wo.value), nil
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
	if wo == nil {
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
	if wo.parameterNameLength == 0 {
		return "", errInvalidMapKey
	}

	return wo.mapKey(), nil
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

// Helper function to access to i-th element of the given **C.char array.
func cindexCharPtrArray(array *uintptr, i int) uintptr {
	// Go pointer arithmetic equivalent to the C expression `array[i]`
	base := uintptr(unsafe.Pointer(array))
	return *(*uintptr)(unsafe.Pointer(base + unsafe.Sizeof((uintptr)(0))*uintptr(i))) //nolint:govet
}
