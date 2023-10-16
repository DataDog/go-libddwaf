// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

// decodeErrors transforms the wafObject received by the wafRulesetInfo after the call to wafDl.wafInit to a map where
// keys are the error message and the value is a array of all the rule ids which triggered this specific error
func decodeErrors(obj *wafObject) (map[string][]string, error) {
	if obj._type != wafMapType {
		return nil, errInvalidObjectType
	}

	if obj.value == 0 && obj.nbEntries > 0 {
		return nil, errNilObjectPtr
	}

	wafErrors := map[string][]string{}
	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := castWithOffset[wafObject](obj.value, i)
		if objElem._type != wafArrayType {
			return nil, errInvalidObjectType
		}

		errorMessage := gostringSized(cast[byte](objElem.parameterName), objElem.parameterNameLength)
		ruleIds, err := decodeRuleIdArray(objElem)
		if err != nil {
			return nil, err
		}

		wafErrors[errorMessage] = ruleIds
	}

	return wafErrors, nil
}

func decodeRuleIdArray(obj *wafObject) ([]string, error) {
	if obj._type != wafArrayType {
		return nil, errInvalidObjectType
	}

	if obj.value == 0 && obj.nbEntries > 0 {
		return nil, errNilObjectPtr
	}

	var ruleIds []string
	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := castWithOffset[wafObject](obj.value, i)
		if objElem._type != wafStringType {
			return nil, errInvalidObjectType
		}

		ruleIds = append(ruleIds, gostringSized(cast[byte](objElem.value), objElem.nbEntries))
	}

	return ruleIds, nil
}

func decodeObject(obj *wafObject) (interface{}, error) {
	switch obj._type {
	case wafMapType:
		return decodeMap(obj)
	case wafArrayType:
		return decodeArray(obj)
	case wafStringType:
		return gostringSized(cast[byte](obj.value), obj.nbEntries), nil
	case wafIntType:
		return int64(obj.value), nil
	case wafUintType:
		return uint64(obj.value), nil
	default:
		return nil, errUnsupportedValue
	}
}

func decodeArray(obj *wafObject) ([]interface{}, error) {
	if obj._type != wafArrayType {
		return nil, errInvalidObjectType
	}

	var events []interface{}

	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := castWithOffset[wafObject](obj.value, i)
		val, err := decodeObject(objElem)
		if err != nil {
			return nil, err
		}
		events = append(events, val)
	}

	return events, nil
}

func decodeMap(obj *wafObject) (map[string]interface{}, error) {
	if obj._type != wafMapType {
		return nil, errInvalidObjectType
	}

	result := map[string]interface{}{}
	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := castWithOffset[wafObject](obj.value, i)
		key := gostringSized(cast[byte](objElem.parameterName), objElem.parameterNameLength)
		val, err := decodeObject(objElem)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}

	return result, nil
}
