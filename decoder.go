// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"unsafe"
)

// decodeErrors tranform the wafObject received by the wafRulesetInfo after the call to wafDl.wafInit, to a map where
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
		objElem := toWafobject(obj.value + uintptr(i)*unsafe.Sizeof(wafObject{}))
		if objElem._type != wafArrayType {
			return nil, errInvalidObjectType
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
		return nil, errInvalidObjectType
	}

	if obj.value == 0 && obj.nbEntries > 0 {
		return nil, errNilObjectPtr
	}

	var ruleIds []string
	for i := uint64(0); i < obj.nbEntries; i++ {
		objElem := toWafobject(obj.value + uintptr(i)*unsafe.Sizeof(wafObject{}))
		if objElem._type != wafStringType {
			return nil, errInvalidObjectType
		}

		ruleIds = append(ruleIds, gostringSized(objElem.value, objElem.nbEntries))
	}

	return ruleIds, nil
}

func decodeActions(cActions uintptr, size uint32) []string {
	if size == 0 {
		return nil
	}

	actions := make([]string, size)
	for i := 0; i < int(size); i++ {
		actions[i] = gostring(uintptr(unsafe.Pointer(*(**byte)(unsafe.Pointer(cActions + unsafe.Sizeof((*byte)(nil))*uintptr(i))))))
	}

	return actions
}
