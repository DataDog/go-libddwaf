package libddwaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/unsafe"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
	jsoniter "github.com/json-iterator/go"
)

func createJsonIterator(data []byte) (*jsoniter.Iterator, jsoniter.API) {
	cfg := jsoniter.ConfigCompatibleWithStandardLibrary
	iter := cfg.BorrowIterator(data)
	return iter, cfg
}

// parse json
func (e *jsonEncoder) parse(jsonData []byte) (*bindings.WAFObject, error) {
	iter, cfg := createJsonIterator(jsonData)
	defer cfg.ReturnIterator(iter)

	rootObj := &bindings.WAFObject{}
	err := e.parseValue(iter, rootObj, e.objectMaxDepth)
	if err != nil {
		// When an error is present, the waf object is discarded, this won't be passed to the WAF
		// An error can occur in the following cases:
		// - A timeout: we discard everything as it won't be passed to the WAF
		// - A malformed JSON that:
		//     - Parsing error if the initial JSON is **not** truncated
		//     - Parsing error (unrelated to the initial truncation) if there is still more byte in the buffer

		if (errors.Is(err, waferrors.ErrTimeout) || !e.initiallyTruncated) || rootObj.Type == bindings.WAFInvalidType {
			return nil, err
		}
	}

	if rootObj.Type == bindings.WAFInvalidType {
		// If the root object is invalid, we need to return an error
		return nil, fmt.Errorf("invalid json at root")
	}

	return rootObj, nil
}

// returns skip, error
// already do the skip part
func (e *jsonEncoder) parseValue(iter *jsoniter.Iterator, obj *bindings.WAFObject, depth int) error {
	if e.timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	// todo: is it really called?
	if depth < 0 {
		e.addTruncation(ObjectTooDeep, e.objectMaxDepth-depth)
		iter.Skip()
		return nil
	}

	var err error

	switch iter.WhatIsNext() {
	case jsoniter.ObjectValue:
		err = e.parseObject(iter.SkipAndReturnBytes(), obj, depth-1)
	case jsoniter.ArrayValue:
		err = e.parseArray(iter.SkipAndReturnBytes(), obj, depth-1)
	case jsoniter.StringValue:
		s := iter.ReadString()
		if err = iter.Error; err == nil || err == io.EOF {
			e.encodeString(s, obj)
		}
	case jsoniter.NumberValue:
		jsonNbr := iter.ReadNumber()
		if err = iter.Error; err == nil || err == io.EOF {
			err = nil
			e.encodeJSONNumber(jsonNbr, obj)
		}
	case jsoniter.BoolValue:
		b := iter.ReadBool()
		if err = iter.Error; err == nil || err == io.EOF {
			err = nil
			encodeNative(unsafe.NativeToUintptr(b), bindings.WAFBoolType, obj)
		}
	case jsoniter.NilValue:
		iter.ReadNil()
		if err = iter.Error; err == nil || err == io.EOF {
			err = nil
			encodeNative[uintptr](0, bindings.WAFNilType, obj)
		}
	default:
		err = fmt.Errorf("unexpected JSON token: %v", iter.WhatIsNext())
	}

	return err
}

func (e *jsonEncoder) parseObject(data []byte, parentObj *bindings.WAFObject, depth int) error {
	if e.timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	if depth < 0 {
		e.addTruncation(ObjectTooDeep, e.objectMaxDepth-depth)
		return nil
	}

	length, err := e.getContainerLength(data, true)
	if err != nil && (errors.Is(err, waferrors.ErrTimeout) || !e.initiallyTruncated) {
		// Return error only for timeout or if JSON was not initially truncated
		// The error would still be propagated at the end of the function when partially parsed
		return err
	}

	objMap := parentObj.SetMap(e.pinner, uint64(length))
	if length == 0 {
		// Still correctly set a map with 0 entries
		return nil
	}

	iter, cfg := createJsonIterator(data)
	defer cfg.ReturnIterator(iter)

	count := 0
	var errRec error

	iter.ReadObjectCB(func(i *jsoniter.Iterator, field string) bool {
		if e.timer.Exhausted() {
			errRec = waferrors.ErrTimeout
			return false
		}

		if count >= length {
			return false
		}

		entryObj := &objMap[count]
		errParseValue := e.parseValue(i, entryObj, depth)
		if errParseValue != nil {
			errRec = errParseValue
			return false
		}

		e.encodeMapKeyFromString(field, entryObj)
		count++
		return true
	})

	parentObj.NbEntries = uint64(length)

	if errRec != nil {
		return errRec
	}
	return iter.Error
}

func (e *jsonEncoder) parseArray(data []byte, parentObj *bindings.WAFObject, depth int) error {
	if e.timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	if depth < 0 {
		e.addTruncation(ObjectTooDeep, e.objectMaxDepth-depth)
		return nil
	}

	length, err := e.getContainerLength(data, false)
	if err != nil && (errors.Is(err, waferrors.ErrTimeout) || !e.initiallyTruncated) {
		// Return error only for timeout or if JSON was not initially truncated
		return err
	}

	objArray := parentObj.SetArray(e.pinner, uint64(length))
	if length == 0 {
		return nil
	}

	iter, cfg := createJsonIterator(data)
	defer cfg.ReturnIterator(iter)

	count := 0
	var errRec error

	iter.ReadArrayCB(func(i *jsoniter.Iterator) bool {
		if e.timer.Exhausted() {
			errRec = waferrors.ErrTimeout
			return false
		}

		if count >= length {
			return false
		}

		objElem := &objArray[count]
		errParseValue := e.parseValue(i, objElem, depth)
		if errParseValue != nil {
			errRec = errParseValue
			return false
		}

		if !objElem.IsUnusable() {
			count++
		}

		return true
	})

	parentObj.NbEntries = uint64(count)

	if errRec != nil {
		return errRec
	}
	return iter.Error
}

func (e *jsonEncoder) encodeJSONNumber(num json.Number, obj *bindings.WAFObject) {
	// Important to attempt int64 first, as this is lossless. Values that are either too small or too
	// large to be represented as int64 can be represented as float64, but this can be lossy.
	if i, err := num.Int64(); err == nil {
		encodeNative(uintptr(i), bindings.WAFIntType, obj)
		return
	}

	if f, err := num.Float64(); err == nil {
		encodeNative(unsafe.NativeToUintptr(f), bindings.WAFFloatType, obj)
		return
	}

	// Could not store as int64 nor float, so we'll store it as a string...
	e.encodeString(num.String(), obj)
}

func (e *jsonEncoder) encodeString(str string, obj *bindings.WAFObject) {
	strLen := len(str)
	if strLen > e.stringMaxSize {
		str = str[:e.stringMaxSize]
		e.addTruncation(StringTooLong, strLen)
	}

	obj.SetString(e.pinner, str)
}

// getContainerLength is a helper function to get the length of a JSON container (object or array).
// An error is returned only when the parsing needs to be ended.
func (e *jsonEncoder) getContainerLength(data []byte, isObject bool) (int, error) {
	iter, cfg := createJsonIterator(data)
	defer cfg.ReturnIterator(iter)

	var errRec error
	count := 0

	// our shared callback body
	elemCB := func() bool {
		if e.timer.Exhausted() {
			errRec = waferrors.ErrTimeout
			return false
		}

		if iter.Error != nil {
			errRec = iter.Error
			return false
		}

		count++ // not sure if need to ++ before or after the skip

		iter.Skip()
		if iter.Error != nil {
			errRec = iter.Error
			return false
		}

		return true
	}

	if isObject {
		// key is ignored here, but you can inspect it if needed
		iter.ReadObjectCB(func(it *jsoniter.Iterator, _ string) bool {
			return elemCB()
		})
	} else {
		iter.ReadArrayCB(func(it *jsoniter.Iterator) bool {
			return elemCB()
		})
	}

	if count > e.containerMaxSize {
		e.addTruncation(ContainerTooLarge, count)
		count = e.containerMaxSize
	}

	return count, errRec
}

// encodeMapKeyFromString takes a string and a wafObject and sets the map key attribute on the wafObject to the supplied
// string. The key may be truncated if it exceeds the maximum string size allowed by the jsonEncoder.
func (e *jsonEncoder) encodeMapKeyFromString(keyStr string, obj *bindings.WAFObject) {
	size := len(keyStr)
	if size > e.stringMaxSize {
		keyStr = keyStr[:e.stringMaxSize]
		e.addTruncation(StringTooLong, size)
	}

	obj.SetMapKey(e.pinner, keyStr)
}
