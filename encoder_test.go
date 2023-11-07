// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64)) || (windows && (amd64 || 386))) && !go1.22

package waf

import (
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestEncoder(t *testing.T) {
	for _, tc := range []struct {
		Name                   string
		PermanentData          interface{}
		EphemeralData          interface{} // Strive to have different values than PermanentData, to steer constant grouping away
		ExpectedError          error
		ExpectedWAFValueType   int
		ExpectedWAFValueLength int
		ExpectedWAFString      string
		ExpectedWafValueInt    int64
		ExpectedWafValueUint   uint64
		ExpectedWafValueFloat  float64
		ExpectedWafValueBool   bool
		MaxValueDepth          interface{}
		MaxContainerLength     interface{}
		MaxStringLength        interface{}
	}{
		{
			Name:          "unsupported type",
			PermanentData: make(chan struct{}),
			EphemeralData: make(chan struct{}),
			ExpectedError: errUnsupportedValue,
		},
		{
			Name:                 "string-hekki",
			PermanentData:        "hello, waf",
			EphemeralData:        "hello, waf!",
			ExpectedWAFValueType: wafStringType,
			ExpectedWAFString:    "hello, waf",
		},
		{
			Name:                   "string-empty",
			PermanentData:          "",
			EphemeralData:          "",
			ExpectedWAFValueType:   wafStringType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:                 "byte-slice",
			PermanentData:        []byte("hello, waf"),
			EphemeralData:        []byte("hello, waf!"),
			ExpectedWAFValueType: wafStringType,
			ExpectedWAFString:    "hello, waf",
		},
		{
			Name:                   "nil-byte-slice",
			PermanentData:          []byte(nil),
			EphemeralData:          []byte(nil),
			ExpectedWAFValueType:   wafStringType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:                   "nil-map",
			PermanentData:          map[string]any(nil),
			EphemeralData:          map[string]any(nil),
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:                   "map-with-empty-key-string",
			PermanentData:          map[string]int{"": 1},
			EphemeralData:          map[string]int{"": 2},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "empty-struct",
			PermanentData:          struct{}{},
			EphemeralData:          struct{}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name: "empty-struct-with-private-fields",
			PermanentData: struct {
				a string
				b int
				c bool
			}{},
			EphemeralData: struct {
				a2 string
				b2 int
				c2 bool
			}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:          "nil-interface-value",
			PermanentData: nil,
			EphemeralData: nil,
			ExpectedError: errUnsupportedValue,
		},
		{
			Name:          "nil-pointer-value",
			PermanentData: (*string)(nil),
			EphemeralData: (*string)(nil),
			ExpectedError: errUnsupportedValue,
		},
		{
			Name:          "nil-pointer-value",
			PermanentData: (*int)(nil),
			EphemeralData: (*int)(nil),
			ExpectedError: errUnsupportedValue,
		},
		{
			Name:                 "non-nil-pointer-value",
			PermanentData:        new(int),
			EphemeralData:        new(int),
			ExpectedWAFValueType: wafIntType,
			ExpectedWafValueInt:  0,
		},
		{
			Name:                   "non-nil-pointer-value",
			PermanentData:          new(string),
			EphemeralData:          new(string),
			ExpectedWAFValueType:   wafStringType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:                   "having-an-empty-map",
			PermanentData:          map[string]interface{}{},
			EphemeralData:          map[string]interface{}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:          "unsupported",
			PermanentData: func() {},
			EphemeralData: func() {},
			ExpectedError: errUnsupportedValue,
		},
		{
			Name:                 "int",
			PermanentData:        int(1234),
			EphemeralData:        int(12345),
			ExpectedWAFValueType: wafIntType,
			ExpectedWafValueInt:  1234,
		},
		{
			Name:                 "uint",
			PermanentData:        uint(9876),
			EphemeralData:        uint(98765),
			ExpectedWAFValueType: wafUintType,
			ExpectedWafValueUint: 9876,
		},
		{
			Name:                 "bool",
			PermanentData:        true,
			EphemeralData:        false,
			ExpectedWAFValueType: wafBoolType,
			ExpectedWafValueBool: true,
		},
		{
			Name:                 "bool",
			PermanentData:        false,
			EphemeralData:        true,
			ExpectedWAFValueType: wafBoolType,
			ExpectedWafValueBool: false,
		},
		{
			Name:                  "float",
			PermanentData:         33.12345,
			EphemeralData:         33.123456,
			ExpectedWAFValueType:  wafFloatType,
			ExpectedWafValueFloat: 33.12345,
		},
		{
			Name:                  "float",
			PermanentData:         33.62345,
			EphemeralData:         33.623456,
			ExpectedWAFValueType:  wafFloatType,
			ExpectedWafValueFloat: 33.62345,
		},
		{
			Name:                   "slice",
			PermanentData:          []interface{}{33.12345, "ok", 27},
			EphemeralData:          []interface{}{33.123456, "ko", 72},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "slice-having-unsupported-values",
			PermanentData:          []interface{}{33.12345, func() {}, "ok", 27, nil},
			EphemeralData:          []interface{}{33.123456, func() {}, "ko", 72, nil},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "array",
			PermanentData:          [...]interface{}{func() {}, 33.12345, "ok", 27},
			EphemeralData:          [...]interface{}{func() {}, 33.123456, "ko", 72},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "map",
			PermanentData:          map[string]interface{}{"k1": 1, "k2": "2"},
			EphemeralData:          map[string]interface{}{"k3": 3, "k4": "4"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                   "map-with-unsupported-key-values",
			PermanentData:          map[interface{}]interface{}{"k1": 1, 27: "int key", "k2": "2"},
			EphemeralData:          map[interface{}]interface{}{"k3": 2, 72: "int key!", "k4": "5"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                   "map-with-indirect-key-string-values",
			PermanentData:          map[interface{}]interface{}{"k1": 1, new(string): "string pointer key", "k2": "2"},
			EphemeralData:          map[interface{}]interface{}{"k3": 2, new(string): "string pointer key!", "k4": "5"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name: "struct",
			PermanentData: struct {
				Public  string
				private string
				a       string
				A       string
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       "A",
			},
			EphemeralData: struct {
				Public2  string
				private2 string
				a2       string
				A2       string
			}{
				Public2:  "Public!",
				private2: "private!",
				a2:       "a!",
				A2:       "A!",
			},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2, // public fields only
		},
		{
			Name: "struct-with-unsupported-values",
			PermanentData: struct {
				Public  string
				private string
				a       string
				A       func()
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       nil,
			},
			EphemeralData: struct {
				Public2  string
				private2 string
				a2       string
				A2       func()
			}{
				Public2:  "Public!",
				private2: "private!",
				a2:       "a!",
				A2:       nil,
			},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 1, // public fields of supported types
		},
		{
			Name:                   "array-max-depth",
			MaxValueDepth:          0,
			PermanentData:          []interface{}{1, 2, 3, 4, []int{1, 2, 3, 4}},
			EphemeralData:          []interface{}{5, 6, 7, 8, []int{9, 10, 11, 12}},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 4,
		},
		{
			Name:                   "array-max-depth",
			MaxValueDepth:          1,
			PermanentData:          []interface{}{1, 2, 3, 4, []int{1, 2, 3, 4}},
			EphemeralData:          []interface{}{5, 6, 7, 8, []int{9, 10, 11, 12}},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 5,
		},
		{
			Name:                   "array-max-depth",
			MaxValueDepth:          0,
			PermanentData:          []interface{}{},
			EphemeralData:          []interface{}{},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:                   "map-max-depth",
			MaxValueDepth:          0,
			PermanentData:          map[string]interface{}{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": map[string]string{}},
			EphemeralData:          map[string]interface{}{"k6": "v6", "k7": "v7", "k8": "v8", "k9": "v9", "k10": map[string]string{}},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 4,
		},
		{
			Name:                   "map-max-depth",
			MaxValueDepth:          1,
			PermanentData:          map[string]interface{}{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": map[string]string{}},
			EphemeralData:          map[string]interface{}{"k6": "v6", "k7": "v7", "k8": "v8", "k9": "v9", "k10": map[string]string{}},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 5,
		},
		{
			Name:                   "map-max-depth",
			MaxValueDepth:          0,
			PermanentData:          map[string]interface{}{},
			EphemeralData:          map[string]interface{}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:                   "struct-max-depth",
			MaxValueDepth:          0,
			PermanentData:          struct{}{},
			EphemeralData:          struct{}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:          "struct-max-depth",
			MaxValueDepth: 0,
			PermanentData: struct {
				F0 string
				F1 struct{}
			}{},
			EphemeralData: struct {
				F2 string
				F3 struct{}
			}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:          "struct-max-depth",
			MaxValueDepth: 1,
			PermanentData: struct {
				F0 string
				F1 struct{}
			}{},
			EphemeralData: struct {
				F2 string
				F3 struct{}
			}{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                 "scalar-values-max-depth-not-accounted",
			MaxValueDepth:        0,
			PermanentData:        -1234,
			EphemeralData:        -12345,
			ExpectedWafValueInt:  -1234,
			ExpectedWAFValueType: wafIntType,
		},
		{
			Name:                 "scalar-values-max-depth-not-accounted",
			MaxValueDepth:        0,
			PermanentData:        uint(1234),
			EphemeralData:        uint(12345),
			ExpectedWafValueUint: 1234,
			ExpectedWAFValueType: wafUintType,
		},
		{
			Name:                 "scalar-values-max-depth-not-accounted",
			MaxValueDepth:        0,
			PermanentData:        false,
			EphemeralData:        true,
			ExpectedWAFValueType: wafBoolType,
			ExpectedWafValueBool: false,
		},
		{
			Name:                   "array-max-length",
			MaxContainerLength:     3,
			PermanentData:          []interface{}{1, 2, 3, 4, 5},
			EphemeralData:          []interface{}{6, 7, 8, 9, 10},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "map-max-length",
			MaxContainerLength:     3,
			PermanentData:          map[string]string{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5"},
			EphemeralData:          map[string]string{"k6": "v6", "k7": "v7", "k8": "v8", "k9": "v9", "k10": "v10"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                 "string-max-length",
			MaxStringLength:      3,
			PermanentData:        "123456789",
			EphemeralData:        "1234567890",
			ExpectedWAFString:    "123",
			ExpectedWAFValueType: wafStringType,
		},
		{
			Name:                   "string-max-length-truncation-leading-to-same-map-keys",
			MaxStringLength:        1,
			PermanentData:          map[string]string{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5"},
			EphemeralData:          map[string]string{"k6": "v6", "k7": "v7", "k8": "v8", "k9": "v9", "k10": "v10"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 5,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     1,
			PermanentData:          []interface{}{"supported", func() {}, "supported", make(chan struct{})},
			EphemeralData:          []interface{}{"supported!", func() {}, "supported!", make(chan struct{})},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     2,
			PermanentData:          []interface{}{"supported", func() {}, "supported", make(chan struct{})},
			EphemeralData:          []interface{}{"supported!", func() {}, "supported!", make(chan struct{})},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     1,
			PermanentData:          []interface{}{func() {}, "supported", make(chan struct{}), "supported"},
			EphemeralData:          []interface{}{func() {}, "supported!", make(chan struct{}), "supported!"},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     2,
			PermanentData:          []interface{}{func() {}, "supported", make(chan struct{}), "supported"},
			EphemeralData:          []interface{}{func() {}, "supported!", make(chan struct{}), "supported!"},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     1,
			PermanentData:          []interface{}{func() {}, make(chan struct{}), "supported"},
			EphemeralData:          []interface{}{func() {}, make(chan struct{}), "supported!"},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     3,
			PermanentData:          []interface{}{"supported", func() {}, make(chan struct{})},
			EphemeralData:          []interface{}{"supported!", func() {}, make(chan struct{})},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     3,
			PermanentData:          []interface{}{func() {}, "supported", make(chan struct{})},
			EphemeralData:          []interface{}{func() {}, "supported!", make(chan struct{})},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     3,
			PermanentData:          []interface{}{func() {}, make(chan struct{}), "supported"},
			EphemeralData:          []interface{}{func() {}, make(chan struct{}), "supported!"},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name:                   "unsupported-array-values",
			MaxContainerLength:     2,
			PermanentData:          []interface{}{func() {}, make(chan struct{}), "supported", "supported"},
			EphemeralData:          []interface{}{func() {}, make(chan struct{}), "supported!", "supported!"},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name: "unsupported-map-key-types",
			PermanentData: map[interface{}]int{
				"supported":           1,
				interface{ m() }(nil): 1,
				nil:                   1,
				(*int)(nil):           1,
				(*string)(nil):        1,
				make(chan struct{}):   1,
			},
			EphemeralData: map[interface{}]int{
				"supported":           2,
				interface{ m() }(nil): 2,
				nil:                   2,
				(*int)(nil):           2,
				(*string)(nil):        2,
				make(chan struct{}):   2,
			},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 1,
		},
		{
			Name: "unsupported-map-key-types",
			PermanentData: map[interface{}]int{
				interface{ m() }(nil): 1,
				nil:                   1,
				(*int)(nil):           1,
				(*string)(nil):        1,
				make(chan struct{}):   1,
			},
			EphemeralData: map[interface{}]int{
				interface{ m() }(nil): 2,
				nil:                   2,
				(*int)(nil):           2,
				(*string)(nil):        2,
				make(chan struct{}):   2,
			},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name: "unsupported-map-values",
			PermanentData: map[string]interface{}{
				"k0": "supported",
				"k1": func() {},
				"k2": make(chan struct{}),
			},
			EphemeralData: map[string]interface{}{
				"k3": "supported!",
				"k4": func() {},
				"k5": make(chan struct{}),
			},
			MaxContainerLength:     3,
			ExpectedWAFValueLength: 1,
			ExpectedWAFValueType:   wafMapType,
		},
		{
			Name: "unsupported-map-values",
			PermanentData: map[string]interface{}{
				"k0": "supported",
				"k1": "supported",
				"k2": make(chan struct{}),
			},
			EphemeralData: map[string]interface{}{
				"k3": "supported!",
				"k4": "supported!",
				"k5": make(chan struct{}),
			},
			MaxContainerLength:     3,
			ExpectedWAFValueLength: 2,
			ExpectedWAFValueType:   wafMapType,
		},
		{
			Name: "unsupported-map-values",
			PermanentData: map[string]interface{}{
				"k0": "supported",
				"k1": "supported",
				"k2": make(chan struct{}),
			},
			EphemeralData: map[string]interface{}{
				"k3": "supported!",
				"k4": "supported!",
				"k5": make(chan struct{}),
			},
			MaxContainerLength:     1,
			ExpectedWAFValueLength: 1,
			ExpectedWAFValueType:   wafMapType,
		},
		{
			Name: "unsupported-struct-values",
			PermanentData: struct {
				F0 string
				F1 func()
				F2 chan struct{}
			}{
				F0: "supported",
				F1: func() {},
				F2: make(chan struct{}),
			},
			EphemeralData: struct {
				F3 string
				F4 func()
				F5 chan struct{}
			}{
				F3: "supported!",
				F4: func() {},
				F5: make(chan struct{}),
			},
			MaxContainerLength:     3,
			ExpectedWAFValueLength: 1,
			ExpectedWAFValueType:   wafMapType,
		},
		{
			Name: "unsupported-map-values",
			PermanentData: struct {
				F0 string
				F1 string
				F2 chan struct{}
			}{
				F0: "supported",
				F1: "supported",
				F2: make(chan struct{}),
			},
			EphemeralData: struct {
				F3 string
				F4 string
				F5 chan struct{}
			}{
				F3: "supported!",
				F4: "supported!",
				F5: make(chan struct{}),
			},
			MaxContainerLength:     3,
			ExpectedWAFValueLength: 2,
			ExpectedWAFValueType:   wafMapType,
		},
		{
			Name: "unsupported-map-values",
			PermanentData: struct {
				F0 string
				F1 string
				F2 chan struct{}
			}{
				F0: "supported",
				F1: "supported",
				F2: make(chan struct{}),
			},
			EphemeralData: struct {
				F3 string
				F4 string
				F5 chan struct{}
			}{
				F3: "supported!",
				F4: "supported!",
				F5: make(chan struct{}),
			},
			MaxContainerLength:     1,
			ExpectedWAFValueLength: 1,
			ExpectedWAFValueType:   wafMapType,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			maxValueDepth := 10
			if max := tc.MaxValueDepth; max != nil {
				maxValueDepth = max.(int)
			}
			maxContainerLength := 1000
			if max := tc.MaxContainerLength; max != nil {
				maxContainerLength = max.(int)
			}
			maxStringLength := 4096
			if max := tc.MaxStringLength; max != nil {
				maxStringLength = max.(int)
			}
			e := encoder{
				objectMaxDepth:   maxValueDepth,
				stringMaxSize:    maxStringLength,
				containerMaxSize: maxContainerLength,
			}
			wo, err := e.Encode(tc.PermanentData)
			if tc.ExpectedError != nil {
				require.Error(t, err)
				require.Equal(t, tc.ExpectedError, err)
				require.Nil(t, wo)
				return
			}

			require.NoError(t, err)
			require.NotEqual(t, &wafObject{}, wo)

			if tc.ExpectedWAFValueType != 0 {
				require.Equal(t, tc.ExpectedWAFValueType, int(wo._type), "bad waf value type")
			}
			if tc.ExpectedWAFValueLength != 0 {
				require.Equal(t, tc.ExpectedWAFValueLength, int(wo.nbEntries), "bad waf value length")
			}
			require.Equal(t, tc.ExpectedWAFValueType, int(wo._type), "bad waf string value type")

			switch tc.ExpectedWAFValueType {
			case wafIntType:
				require.Equal(t, tc.ExpectedWafValueInt, int64(wo.value))
			case wafUintType:
				require.Equal(t, tc.ExpectedWafValueUint, uint64(wo.value))
			case wafFloatType:
				require.Equal(t, tc.ExpectedWafValueFloat, uintptrToNative[float64](wo.value))
			case wafBoolType:
				require.Equal(t, tc.ExpectedWafValueBool, uintptrToNative[bool](wo.value))
			}

			if expectedStr := tc.ExpectedWAFString; expectedStr != "" {
				cbuf := wo.value
				gobuf := []byte(expectedStr)
				require.Equal(t, len(gobuf), int(wo.nbEntries), "bad waf value length")
				for i, gobyte := range gobuf {
					// Go pointer arithmetic for cbyte := cbuf[i]
					cbyte := *(*uint8)(unsafe.Pointer(cbuf + uintptr(i))) //nolint:govet
					if cbyte != gobyte {
						t.Fatalf("bad waf string value content: i=%d cbyte=%d gobyte=%d", i, cbyte, gobyte)
					}
				}
			}

			// Pass the encoded value to the WAF to make sure it doesn't return an error
			waf, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
			require.NoError(t, err)
			defer waf.Close()
			wafCtx := NewContext(waf)
			require.NotNil(t, wafCtx)
			defer wafCtx.Close()
			_, err = wafCtx.Run(RunAddressData{
				Persistent: map[string]interface{}{"my.input": tc.PermanentData},
				Ephemeral:  map[string]interface{}{"my.other.input": tc.EphemeralData},
			}, time.Second)
			require.NoError(t, err)
		})
	}
}
