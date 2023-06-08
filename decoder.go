// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"fmt"
	"unsafe"
)

// decodeErrors tranform the wafObject received by the wafRulesetInfo after the call to wafDl.wafInit, to a map where
// keys are the error message and the value is a array of all the rule ids which triggered this specific error
func decodeErrors(obj *wafObject) (map[string][]string, error) {
	if obj._type != wafMapType {
		return nil, fmt.Errorf("top-level error object is not a map but %v", obj._type)
	}

	if obj.value == 0 && obj.nbEntries > 0 {
		return nil, fmt.Errorf("top-level error map is malformed")
	}

	wafErrors := map[string][]string{}
	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := toWafobject(obj.value + uintptr(i)*unsafe.Sizeof(wafObject{}))
		if objElem._type != wafArrayType {
			return nil, fmt.Errorf("mid-level error object is not a array but %v", obj._type)
		}

		errorMessage := gostringSized(objElem.parameterName, objElem.parameterNameLength)
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
		return nil, fmt.Errorf("mid-level error object is not a array but %v", obj._type)
	}

	if obj.value == 0 && obj.nbEntries > 0 {
		return nil, fmt.Errorf("mid-level error array is malformed")
	}

	var ruleIds []string
	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := toWafobject(obj.value + uintptr(i)*unsafe.Sizeof(wafObject{}))
		if objElem._type != wafStringType {
			return nil, fmt.Errorf("error object is not a string but %v", obj._type)
		}

		ruleIds = append(ruleIds, gostringSized(objElem.value, objElem.nbEntries))
	}

	return ruleIds, nil
}

func decodeActions(cActions uintptr, size uint32) []string {
	actions := make([]string, size)
	for i := 0; i < int(size); i++ {
		actions[i] = gostring(uintptr(unsafe.Pointer(*(**byte)(unsafe.Pointer(cActions + unsafe.Sizeof((*byte)(nil))*uintptr(i))))))
	}

	return actions
}
