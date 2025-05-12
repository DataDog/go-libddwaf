package libddwaf

import (
	"encoding/json"
	"errors"
	"fmt"

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
		//     - Parsing error (unrelated to the initial truncation) when invalid token or structure
		//     - Parsing limit reached (ex: custom limit on the number of elements in a container that directly affects the root)
		return nil, err
	}

	return rootObj, nil
}

func (e *jsonEncoder) parseValue(iter *jsoniter.Iterator, obj *bindings.WAFObject, depth int) error {
	if e.timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	iter.WhatIsNext()

	if depth < 0 {
		e.addTruncation(ObjectTooDeep, e.objectMaxDepth)
		iter.Skip()
		return waferrors.ErrMaxDepthExceeded // The WAF Object will have a default value of WAFInvalidType as it's not set
	}

	switch iter.WhatIsNext() {
	case jsoniter.ObjectValue:
		depth -= 1
		data := iter.SkipAndReturnBytes()
		length, err := e.getObjectMapLength(data, depth)
		if err != nil {
			return err
		}
		return e.parseObject(data, length, obj, depth)
	case jsoniter.ArrayValue:
		depth -= 1
		data := iter.SkipAndReturnBytes()
		length, err := e.getArrayLength(data, depth)
		if err != nil {
			return err
		}
		return e.parseArray(data, length, obj, depth)
	case jsoniter.StringValue:
		s := iter.ReadString()
		e.encodeString(s, obj)
		return iter.Error
	case jsoniter.NumberValue:
		jsonNbr := iter.ReadNumber()
		e.encodeJSONNumber(jsonNbr, obj)
		return iter.Error
	case jsoniter.BoolValue:
		b := iter.ReadBool()
		encodeNative(unsafe.NativeToUintptr(b), bindings.WAFBoolType, obj)
		return iter.Error
	case jsoniter.NilValue:
		iter.ReadNil()
		encodeNative[uintptr](0, bindings.WAFNilType, obj)
		return iter.Error
	default:
		// InvalidValue: this case implies an invalid JSON token or structure
		// WAFObject remains as WAFInvalidType by default
		return fmt.Errorf("unexpected JSON token: %v", iter.WhatIsNext())
	}
}

func (e *jsonEncoder) parseObject(data []byte, length int, parentObj *bindings.WAFObject, depth int) error {
	if e.timer.Exhausted() {
		return waferrors.ErrTimeout
	}

	objMap := parentObj.SetMap(e.pinner, uint64(length))
	if length == 0 {
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
		if errRec != nil { // An error occurred in a previous iteration
			return false
		}

		if count >= length {
			// Skip further elements for this object by returning true but not processing
			// We need to consume the value to advance the iterator
			i.Skip()
			return true // Continue to allow iterator to finish object, but don't add more
		}

		entryObj := &objMap[count]
		err := e.parseValue(i, entryObj, depth)
		if err != nil {
			if errors.Is(err, waferrors.ErrMaxDepthExceeded) {
				// Do not encode the object (skip it) but still set the field key in the map
				e.encodeMapKeyFromString(field, entryObj)
				return true // Skip it
			}
			errRec = err
			return false
		}

		// Todo: check if this error check is really relevant
		if i.Error != nil {
			errRec = i.Error
			return false
		}

		// Map key
		e.encodeMapKeyFromString(field, entryObj)

		count++
		return true
	})

	// Todo: if json malformed (with a truncated value at start) return directly
	if errRec != nil {
		return errRec
	}

	parentObj.NbEntries = uint64(length)

	// Todo: check?
	if iter.Error != nil {
		return iter.Error
	}
	return errRec
}

func (e *jsonEncoder) parseArray(data []byte, length int, parentObj *bindings.WAFObject, depth int) error {
	if e.timer.Exhausted() {
		return waferrors.ErrTimeout
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
		if errRec != nil { // An error occurred in a previous iteration
			return false
		}

		if count >= length {
			// Skip further elements for this object by returning true but not processing
			// We need to consume the value to advance the iterator
			i.Skip()
			return true // Continue to allow iterator to finish object, but don't add more
		}

		objElem := &objArray[count]
		err := e.parseValue(i, objElem, depth)
		if err != nil {
			if errors.Is(err, waferrors.ErrMaxDepthExceeded) {
				return true // Skip it
			}
			errRec = err
			return false
		}

		if !objElem.IsUnusable() {
			count++
		}

		// Todo: check if this error check is really relevant
		// maybe when the parseValue is called
		if i.Error != nil {
			errRec = i.Error
			return false
		}

		return true
	})

	// Todo: if json malformed (with a truncated value at start) return directly
	if errRec != nil {
		return errRec
	}

	parentObj.NbEntries = uint64(count)

	// Todo: check?
	if iter.Error != nil {
		return iter.Error
	}
	return errRec
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

func (e *jsonEncoder) getObjectMapLength(object []byte, depth int) (int, error) {
	if depth < 0 {
		e.addTruncation(ObjectTooDeep, e.objectMaxDepth-depth)
		return 0, waferrors.ErrMaxDepthExceeded
	}

	// Todo: get default json-iterator config
	cfg := jsoniter.ConfigCompatibleWithStandardLibrary
	iter := cfg.BorrowIterator(object)
	defer cfg.ReturnIterator(iter)
	var errRec error
	count := 0

	iter.ReadObjectCB(func(iter *jsoniter.Iterator, _ string) bool {
		if e.timer.Exhausted() {
			errRec = waferrors.ErrTimeout
			return false
		}
		if iter.Error != nil {
			return false
		}

		iter.Skip()
		if iter.Error != nil {
			errRec = iter.Error
			return false
		}

		count++
		return true
	})

	// Don't check the iterator error here
	// If the json we want to pare has been initially truncated, we want to partially parse it
	// So don't bubble up the error as we want to parse the part of the array that is valid
	if ((errRec != nil && !errors.Is(errRec, waferrors.ErrTimeout)) || iter.Error != nil) && !e.initiallyTruncated {
		return 0, errRec
	}

	if count > e.containerMaxSize {
		e.addTruncation(ContainerTooLarge, count)
		return e.containerMaxSize, nil
	}

	return count, nil
}

func (e *jsonEncoder) getArrayLength(object []byte, depth int) (int, error) {
	if depth < 0 {
		e.addTruncation(ObjectTooDeep, e.objectMaxDepth-depth)
		return 0, waferrors.ErrMaxDepthExceeded
	}

	cfg := jsoniter.ConfigCompatibleWithStandardLibrary
	iter := cfg.BorrowIterator(object)
	defer cfg.ReturnIterator(iter)
	var errRec error
	count := 0

	iter.ReadArrayCB(func(iter *jsoniter.Iterator) bool {
		if e.timer.Exhausted() {
			errRec = waferrors.ErrTimeout
			return false
		}
		if iter.Error != nil {
			errRec = iter.Error
			return false
		}

		iter.Skip()
		if iter.Error != nil {
			errRec = iter.Error
			return false
		}

		count++
		return true
	})

	// Don't check the iterator error here
	// If the json we want to pare has been initially truncated, we want to partially parse it
	// So don't bubble up the error as we want to parse the part of the array that is valid
	if errRec != nil && !errors.Is(errRec, waferrors.ErrTimeout) && !e.initiallyTruncated {
		return 0, errRec
	}

	if count > e.containerMaxSize {
		e.addTruncation(ContainerTooLarge, count)
		return e.containerMaxSize, nil
	}

	return count, nil
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
