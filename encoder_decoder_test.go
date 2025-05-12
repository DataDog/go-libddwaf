// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.25 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/unsafe"
	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/DataDog/go-libddwaf/v4/waferrors"

	"github.com/stretchr/testify/require"
)

func wafTest(t *testing.T, obj *bindings.WAFObject) {
	// Pass the encoded value to the WAF to make sure it doesn't return an error
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}, {Address: "my.other.input"}}, nil))
	require.NoError(t, err)
	defer waf.Close()
	wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, wafCtx)
	defer wafCtx.Close()
	_, err = wafCtx.Run(RunAddressData{
		Persistent: map[string]any{"my.input": obj},
		Ephemeral:  map[string]any{"my.other.input": obj},
	})
	require.NoError(t, err)
}

type abs int64

func (p abs) Encode(config EncoderConfig, obj *bindings.WAFObject, depth int) (map[TruncationReason][]int, error) {
	i := p
	if i < 0 {
		i = -i
	}

	obj.SetInt(int64(i))
	return nil, nil
}

type truncator struct{}

func (t *truncator) Encode(_ EncoderConfig, _ *bindings.WAFObject, _ int) (map[TruncationReason][]int, error) {
	return map[TruncationReason][]int{StringTooLong: {1}}, nil
}

type errorer struct{}

func (t *errorer) Encode(_ EncoderConfig, _ *bindings.WAFObject, _ int) (map[TruncationReason][]int, error) {
	return nil, waferrors.ErrUnsupportedValue
}

func TestEncodable(t *testing.T) {
	t.Run("abs", func(t *testing.T) {
		input := abs(-4)
		output := int64(4)

		var pinner runtime.Pinner
		defer pinner.Unpin()

		encoder, _ := NewDefaultEncoder(newMaxEncoderConfig(&pinner))
		encoded, err := encoder.Encode(&input)

		require.NoError(t, err, "unexpected error when encoding: %v", err)
		val, err := decodeObject(encoded)
		require.NoError(t, err, "unexpected error when decoding: %v", err)
		require.True(t, reflect.DeepEqual(output, val), "expected %#v, got %#v", output, val)
	})

	t.Run("truncator", func(t *testing.T) {
		input := truncator{}

		var pinner runtime.Pinner
		defer pinner.Unpin()

		encoder, _ := NewDefaultEncoder(newMaxEncoderConfig(&pinner))
		_, err := encoder.Encode(&input)
		require.NoError(t, err, "unexpected error when encoding: %v", err)

		require.Equal(t, map[TruncationReason][]int{StringTooLong: {1}}, encoder.Truncations())
	})

	t.Run("errorer", func(t *testing.T) {
		input := errorer{}

		var pinner runtime.Pinner
		defer pinner.Unpin()

		encoder, _ := NewDefaultEncoder(newMaxEncoderConfig(&pinner))
		_, err := encoder.Encode(&input)
		require.Error(t, err, "expected an error when encoding: %v", err)
		require.ErrorIs(t, err, waferrors.ErrUnsupportedValue)
	})
}

func TestEncodeDecode(t *testing.T) {

	// Nil value as Output as a special meaning: the output should be the same as the input
	// So we use this value in case we need a real nil output value
	nilOutput := make(chan any, 1)

	for _, tc := range []struct {
		Name        string
		Input       any
		Output      any
		DecodeError error
		EncodeError error
	}{
		{
			Name:  "int64",
			Input: int64(-4),
		},
		{
			Name:  "uint64",
			Input: uint64(4),
		},
		{
			Name:  "float64",
			Input: 4.4444,
		},
		{
			Name:  "bool",
			Input: true,
		},
		{
			Name:  "bool",
			Input: false,
		},
		{
			Name:  "string",
			Input: "",
		},
		{
			Name:  "string",
			Input: "EliottAndFrancoisLoveDecoding",
		},
		{
			Name:  "string",
			Input: "123",
		},
		{
			Name:  "slice",
			Input: []any{int64(1), int64(2), int64(3), int64(4)},
		},
		{
			Name:  "slice",
			Input: []any{"1", "2", "3", "4"},
		},
		{
			Name:   "slice",
			Input:  []string{"1", "2", "3", "4"},
			Output: []any{"1", "2", "3", "4"},
		},
		{
			Name:  "slice",
			Input: []any{true, false, false, true, true, true},
		},
		{
			Name:  "slice-nested",
			Input: []any{[]any{true, false}, []any{false, false}, []any{true, true, true}},
		},
		{
			Name:  "map",
			Input: map[string]any{"1": int64(1), "2": int64(2), "3": int64(3)},
		},
		{
			Name:  "map",
			Input: map[string]any{"1": uint64(1), "2": uint64(2), "3": uint64(3)},
		},
		{
			Name:   "map",
			Input:  map[string]int64{"1": 1, "2": 2, "3": 3},
			Output: map[string]any{"1": int64(1), "2": int64(2), "3": int64(3)},
		},
		{
			Name:  "map",
			Input: map[string]any{"1": 1.111, "2": 2.222, "3": 3.333},
		},
		{
			Name:  "map",
			Input: map[string]any{"1": "1", "2": "2", "3": "3"},
		},
		{
			Name:  "map-nested",
			Input: map[string]any{"1": map[string]any{"1": int64(1), "2": int64(2)}, "2": map[string]any{"3": int64(3), "4": int64(4)}},
		},
		{
			Name:  "string-hekki",
			Input: "hello, waf",
		},
		{
			Name:        "byte-slice",
			Input:       []byte("hello, waf"),
			DecodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:        "json-raw",
			Input:       json.RawMessage("hello, waf"),
			DecodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:   "nil-byte-slice",
			Input:  []byte(nil),
			Output: nilOutput,
		},
		{
			Name:   "nil-slice-slice",
			Input:  [][]int{nil, nil, nil},
			Output: []any{},
		},
		{
			Name:   "nil-slice-slice-slice",
			Input:  [][][]int{nil, nil, nil},
			Output: []any{},
		},
		{
			Name:   "map-map-nil",
			Input:  map[string]map[string]any{"toto": nil, "tata": nil},
			Output: map[string]any{"toto": nil, "tata": nil},
		},
		{
			Name:   "map-map-map-nil",
			Input:  map[string]map[string]map[string]any{"toto": nil, "tata": nil},
			Output: map[string]any{"toto": nil, "tata": nil},
		},
		{
			Name:   "nil-map",
			Input:  map[string]any(nil),
			Output: nilOutput,
		},
		{
			Name:  "map-with-empty-key-string",
			Input: map[string]any{"": uint64(1)},
		},
		{
			Name:   "empty-struct",
			Input:  struct{}{},
			Output: map[string]any{},
		},
		{
			Name: "empty-struct-with-private-fields",
			Input: struct {
				a string
				b int
				c bool
			}{},
			Output: map[string]any{},
		},
		{
			Name:        "invalid-interface-value",
			Input:       nil,
			EncodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:   "nil-str-pointer-value",
			Input:  (*string)(nil),
			Output: nilOutput,
		},
		{
			Name:   "nil-int-pointer-value",
			Input:  (*int)(nil),
			Output: nilOutput,
		},
		{
			Name:   "empty-map",
			Input:  map[string]any{},
			Output: map[string]any{},
		},
		{
			Name:        "unsupported",
			Input:       func() {},
			Output:      func() {},
			EncodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:        "map-nested-unsupported",
			Input:       map[string]any{"1": func() {}},
			DecodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:  "slice",
			Input: []any{float64(33.12345), "ok", int64(27)},
		},
		{
			Name:   "slice-having-unsupported-values",
			Input:  []any{float64(33.12345), func() {}, "ok", uint64(27)},
			Output: []any{float64(33.12345), "ok", uint64(27)},
		},
		{
			Name:   "slice-having-nil-values",
			Input:  []any{float64(33.12345), "ok", uint64(27), nil},
			Output: []any{float64(33.12345), "ok", uint64(27)},
		},
		{
			Name:   "map-with-unsupported-key-values",
			Input:  map[any]any{"k1": uint64(1), 27: "int key", "k2": "2"},
			Output: map[string]any{"k1": uint64(1), "k2": "2"},
		},
		{
			Name:   "map-with-indirect-key-string-values",
			Input:  map[any]any{"k1": uint64(1), new(string): "string pointer key", "k2": "2"},
			Output: map[string]any{"k1": uint64(1), "": "string pointer key", "k2": "2"},
		},
		{
			Name:   "json-number.int",
			Input:  json.Number("1234567890"),
			Output: int64(1234567890),
		},
		{
			Name:   "json-number.bigint",
			Input:  json.Number(strconv.FormatUint(math.MaxUint64, 10) + "999"),
			Output: math.MaxUint64*1000.0 + 999, // Gets represented as a float64
		},
		{
			Name:   "json-number.float",
			Input:  json.Number("1234567890.42"),
			Output: 1234567890.42,
		},
		{
			Name:   "json-number.bogus",
			Input:  json.Number("bogus"),
			Output: "bogus",
		},
		{
			Name: "struct",
			Input: struct {
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
			Output: map[string]any{
				"Public": "Public",
				"A":      "A",
			},
		},
		{
			Name: "struct-with-ignored-values",
			Input: struct {
				Public  string `ddwaf:"ignore"`
				private string
				a       string
				A       string
				partial json.RawMessage
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       "A",
				partial: json.RawMessage("test"),
			},
			Output: map[string]any{
				"A": "A",
			},
		},
		{
			Name: "struct-with-unsupported-values",
			Input: struct {
				Public  string
				private string
				a       string
				A       chan any
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       make(chan any),
			},
			DecodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name: "struct-with-unsupported-ignored-values",
			Input: struct {
				Public string
				A      chan any `ddwaf:"ignore"`
			}{
				Public: "Public",
				A:      make(chan any),
			},
			Output: map[string]any{
				"Public": "Public",
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Output == nil {
				tc.Output = tc.Input
			}

			if tc.Output == nilOutput {
				tc.Output = nil
			}

			var pinner runtime.Pinner
			defer pinner.Unpin()

			encoder, _ := NewDefaultEncoder(newMaxEncoderConfig(&pinner))
			encoded, err := encoder.Encode(tc.Input)

			t.Run("equal", func(t *testing.T) {
				if tc.EncodeError != nil {
					require.Error(t, err, "expected an encoding error when encoding %v", tc.Input)
					require.ErrorIs(t, err, tc.EncodeError)
					return
				}

				require.NoError(t, err, "unexpected error when encoding: %v", err)
				val, err := decodeObject(encoded)

				if tc.DecodeError != nil {
					require.Error(t, err, "expected a decoding error when decoding %v", tc.Input)
					require.ErrorIs(t, err, tc.DecodeError)
					return
				}

				require.NoError(t, err, "unexpected error when decoding: %v", err)
				require.True(t, reflect.DeepEqual(tc.Output, val), "expected %#v, got %#v", tc.Output, val)
			})

			t.Run("run", func(t *testing.T) {
				wafTest(t, encoded)
			})
		})
	}
}

func TestEncoderLimits(t *testing.T) {
	var selfPointer any
	selfPointer = &selfPointer // This now points to itself!

	for _, tc := range []struct {
		Name               string
		Input              any
		Output             any
		MaxValueDepth      any
		MaxContainerLength any
		MaxStringLength    any
		Truncations        map[TruncationReason][]int
		EncodeError        error
		DecodeError        error
	}{
		{
			Name:          "array-depth",
			MaxValueDepth: 1,
			Input:         []any{uint64(1), uint64(2), uint64(3), uint64(4), []any{uint64(1), uint64(2), uint64(3), uint64(4)}},
			Output:        []any{uint64(1), uint64(2), uint64(3), uint64(4)},
			Truncations:   map[TruncationReason][]int{ObjectTooDeep: {2}},
		},
		{
			Name:          "array-depth",
			MaxValueDepth: 2,
			Input:         []any{uint64(1), uint64(2), uint64(3), uint64(4), []any{uint64(1), uint64(2), uint64(3), uint64(4)}},
			Output:        []any{uint64(1), uint64(2), uint64(3), uint64(4), []any{uint64(1), uint64(2), uint64(3), uint64(4)}},
		},
		{
			Name:          "array-depth",
			MaxValueDepth: 0,
			Input:         []any{uint64(1), uint64(2), uint64(3), uint64(4), []any{uint64(1), uint64(2), uint64(3), uint64(4)}},
			EncodeError:   waferrors.ErrMaxDepthExceeded,
			Truncations:   map[TruncationReason][]int{ObjectTooDeep: {2}},
		},
		{
			Name:          "key-map-depth",
			MaxValueDepth: 1,
			Input:         map[any]any{new(string): "x"},
			Output:        map[string]any{"": "x"},
		},
		{
			Name:          "map-depth",
			MaxValueDepth: 1,
			Input:         map[string]any{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": map[string]string{}},
			Output:        map[string]any{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": nil},
			Truncations:   map[TruncationReason][]int{ObjectTooDeep: {2}},
			DecodeError:   waferrors.ErrUnsupportedValue,
		},
		{
			Name:          "map-depth",
			MaxValueDepth: 2,
			Input:         map[string]any{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": map[string]string{}},
			Output:        map[string]any{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": map[string]any{}},
		},
		{
			Name:          "map-depth",
			MaxValueDepth: 0,
			Input:         map[string]any{},
			EncodeError:   waferrors.ErrMaxDepthExceeded,
			Truncations:   map[TruncationReason][]int{ObjectTooDeep: {1}},
		},
		{
			Name:          "struct-depth",
			MaxValueDepth: 0,
			Input:         struct{}{},
			EncodeError:   waferrors.ErrMaxDepthExceeded,
			Truncations:   map[TruncationReason][]int{ObjectTooDeep: {1}},
		},
		{
			Name:          "struct-depth",
			MaxValueDepth: 1,
			Input: struct {
				F0 string
				F1 struct{}
			}{F0: "F0", F1: struct{}{}},
			Output: map[string]any{
				"F0": "F0",
				"F1": nil,
			},
			Truncations: map[TruncationReason][]int{ObjectTooDeep: {2}},
			DecodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:          "struct-max-depth",
			MaxValueDepth: 1,
			Input: struct {
				F0 string
				F1 struct{}
			}{F0: "F0", F1: struct{}{}},
			Output: map[string]any{
				"F0": "F0",
				"F1": nil,
			},
			Truncations: map[TruncationReason][]int{ObjectTooDeep: {2}},
			DecodeError: waferrors.ErrUnsupportedValue,
		},
		{
			Name:               "array-max-length",
			MaxContainerLength: 3,
			Input:              []any{uint64(1), uint64(2), uint64(3), uint64(4), uint64(5)},
			Output:             []any{uint64(1), uint64(2), uint64(3)},
			Truncations:        map[TruncationReason][]int{ContainerTooLarge: {5}},
		},
		{
			Name:               "array-max-length-with-invalid",
			MaxContainerLength: 3,
			Input:              []any{make(chan any), uint64(1), uint64(2), uint64(3), uint64(4), uint64(5)},
			Output:             []any{uint64(1), uint64(2), uint64(3)},
			Truncations:        map[TruncationReason][]int{ContainerTooLarge: {6}},
		},
		{
			Name:               "array-max-length-with-invalid",
			MaxContainerLength: 3,
			Input:              []any{uint64(1), uint64(2), uint64(3), uint64(4), uint64(5), make(chan any)},
			Output:             []any{uint64(1), uint64(2), uint64(3)},
			Truncations:        map[TruncationReason][]int{ContainerTooLarge: {6}},
		},
		{
			Name:               "struct-max-length",
			MaxContainerLength: 2,
			Input: struct {
				F0 string
				F1 string
				F2 string
			}{F0: "", F1: "", F2: ""},
			Output:      map[string]any{"F0": "", "F1": ""},
			Truncations: map[TruncationReason][]int{ContainerTooLarge: {3}},
		},
		{
			Name:               "struct-max-length-with-invalid",
			MaxContainerLength: 2,
			Input: struct {
				F0 string
				F1 string
				F2 chan any
			}{F0: "", F1: "", F2: make(chan any)},
			Output:      map[string]any{"F0": "", "F1": ""},
			Truncations: map[TruncationReason][]int{ContainerTooLarge: {3}},
		},
		{
			Name:            "string-max-length",
			MaxStringLength: 3,
			Input:           "123456789",
			Output:          "123",
			Truncations:     map[TruncationReason][]int{StringTooLong: {9}},
		},
		{
			Name:            "string-max-length-truncation-leading-to-same-map-keys",
			MaxStringLength: 1,
			Input:           map[string]string{"k1": "v11", "k222": "v2222", "k33333": "v333333", "k4444444": "v44444444", "k555555555": "v5555555555"},
			Output:          map[string]any{"k": "v"},
			Truncations: map[TruncationReason][]int{
				StringTooLong: {2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			},
		},
		{
			Name:   "self-recursive-map-key",
			Input:  map[any]any{selfPointer: ":bomb:"},
			Output: map[string]any{},
		},
		{
			Name:        "self-recursive-map-value",
			Input:       map[string]any{"bomb": selfPointer},
			DecodeError: waferrors.ErrUnsupportedValue,
		},
	} {
		maxValueDepth := 99999
		if maxVal := tc.MaxValueDepth; maxVal != nil {
			maxValueDepth = maxVal.(int)
		}
		maxContainerLength := 99999
		if maxVal := tc.MaxContainerLength; maxVal != nil {
			maxContainerLength = maxVal.(int)
		}
		maxStringLength := 99999
		if maxVal := tc.MaxStringLength; maxVal != nil {
			maxStringLength = maxVal.(int)
		}
		var pinner runtime.Pinner
		defer pinner.Unpin()
		encodeTimer, _ := timer.NewTimer(timer.WithUnlimitedBudget())
		encoder, err := NewDefaultEncoder(EncoderConfig{
			Pinner:           &pinner,
			Timer:            encodeTimer,
			ObjectMaxDepth:   maxValueDepth,
			StringMaxSize:    maxStringLength,
			ContainerMaxSize: maxContainerLength,
		})

		require.NoError(t, err)

		encoded := &bindings.WAFObject{}
		encoded, err = encoder.Encode(tc.Input)
		t.Run(tc.Name+"/assert", func(t *testing.T) {
			require.Equal(t, tc.Truncations, sortValues(encoder.Truncations()))

			if tc.EncodeError != nil {
				require.Error(t, err, "expected an encoding error when encoding %v", tc.EncodeError)
				require.ErrorIs(t, err, tc.EncodeError)
				return
			}

			require.NoError(t, err, "unexpected error when encoding: %v", err)

			val, err := decodeObject(encoded)
			if tc.DecodeError != nil {
				require.Error(t, err, "expected a decoding error when decoding %v", tc.DecodeError)
				require.ErrorIs(t, err, tc.DecodeError)
				return
			}

			require.NoError(t, err, "unexpected error when decoding: %v", err)
			require.True(t, reflect.DeepEqual(tc.Output, val), "expected %v, got %v", tc.Output, val)
		})

		t.Run(tc.Name+"/run", func(t *testing.T) {
			wafTest(t, encoded)
		})
	}
}

type typeTree struct {
	_type    bindings.WAFObjectType
	children []typeTree
}

func assertEqualType(t *testing.T, expected typeTree, actual *bindings.WAFObject) {
	require.Equal(t, expected._type, actual.Type, "expected type %v, got type %v", expected._type, actual.Type)

	if expected._type != bindings.WAFMapType && expected._type != bindings.WAFArrayType {
		return
	}

	if uint64(len(expected.children)) != actual.NbEntries {
		t.Fatalf("expected len %v, got len %v", len(expected.children), actual.NbEntries)
	}

	for i := range expected.children {
		assertEqualType(t, expected.children[i], unsafe.CastWithOffset[bindings.WAFObject](actual.Value, uint64(i)))
	}
}

func sortValues[K comparable](m map[K][]int) map[K][]int {
	if m == nil {
		return nil
	}

	for _, ints := range m {
		sort.Ints(ints)
	}

	return m
}

func TestEncoderTypeTree(t *testing.T) {

	for _, tc := range []struct {
		Name   string
		Input  any
		Output typeTree
		Error  error
	}{
		{
			Name:  "unsupported type",
			Input: make(chan struct{}),
			Error: waferrors.ErrUnsupportedValue,
		},
		{
			Name:   "nil-byte-slice",
			Input:  []byte(nil),
			Output: typeTree{_type: bindings.WAFNilType},
		},
		{
			Name:   "nil-map",
			Input:  map[string]any(nil),
			Output: typeTree{_type: bindings.WAFNilType},
		},
		{
			Name:  "invalid-interface-value",
			Input: nil,
			Error: waferrors.ErrUnsupportedValue,
		},
		{
			Name:   "nil-str-pointer-value",
			Input:  (*string)(nil),
			Output: typeTree{_type: bindings.WAFNilType},
		},
		{
			Name:   "nil-int-pointer-value",
			Input:  (*int)(nil),
			Output: typeTree{_type: bindings.WAFNilType},
		},
		{
			Name:  "unsupported",
			Input: func() {},
			Error: waferrors.ErrUnsupportedValue,
		},
		{
			Name:  "unsupported",
			Input: make(chan struct{}),
			Error: waferrors.ErrUnsupportedValue,
		},
		{
			Name:   "slice-having-unsupported-values",
			Input:  []any{33.12345, func() {}, "ok", 27, nil},
			Output: typeTree{_type: bindings.WAFArrayType, children: []typeTree{{_type: bindings.WAFFloatType}, {_type: bindings.WAFStringType}, {_type: bindings.WAFIntType}}},
		},
		{
			Name: "struct-with-nil-values",
			Input: struct {
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
			Output: typeTree{_type: bindings.WAFMapType, children: []typeTree{{_type: bindings.WAFStringType}, {_type: bindings.WAFNilType}}},
		},
		{
			Name: "struct-with-invalid-values",
			Input: struct {
				Public  string
				private string
				a       string
				A       chan any
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       make(chan any),
			},
			Output: typeTree{_type: bindings.WAFMapType, children: []typeTree{{_type: bindings.WAFStringType}, {_type: bindings.WAFInvalidType}}},
		},
		{
			Name:   "unsupported-array-values",
			Input:  []any{"supported", func() {}, "supported", make(chan struct{})},
			Output: typeTree{_type: bindings.WAFArrayType, children: []typeTree{{_type: bindings.WAFStringType}, {_type: bindings.WAFStringType}}},
		},
		{
			Name:   "unsupported-array-values",
			Input:  []any{"supported", func() {}, "supported", make(chan struct{})},
			Output: typeTree{_type: bindings.WAFArrayType, children: []typeTree{{_type: bindings.WAFStringType}, {_type: bindings.WAFStringType}}},
		},
		{
			Name:   "unsupported-array-values",
			Input:  []any{func() {}, "supported", make(chan struct{}), "supported"},
			Output: typeTree{_type: bindings.WAFArrayType, children: []typeTree{{_type: bindings.WAFStringType}, {_type: bindings.WAFStringType}}},
		},
		{
			Name:   "unsupported-array-values",
			Input:  []any{func() {}, "supported", make(chan struct{}), "supported"},
			Output: typeTree{_type: bindings.WAFArrayType, children: []typeTree{{_type: bindings.WAFStringType}, {_type: bindings.WAFStringType}}},
		},
		{
			Name:   "unsupported-array-values",
			Input:  []any{func() {}, make(chan struct{}), "supported"},
			Output: typeTree{_type: bindings.WAFArrayType, children: []typeTree{{_type: bindings.WAFStringType}}},
		},
		{
			Name: "unsupported-map-key-types",
			Input: map[any]int{
				"supported":           1,
				interface{ m() }(nil): 1,
				nil:                   1,
				(*int)(nil):           1,
				(*string)(nil):        1,
				make(chan struct{}):   1,
			},
			Output: typeTree{_type: bindings.WAFMapType, children: []typeTree{{_type: bindings.WAFIntType}}},
		},
		{
			Name: "unsupported-map-key-types",
			Input: map[any]int{
				interface{ m() }(nil): 1,
				nil:                   1,
				(*int)(nil):           1,
				(*string)(nil):        1,
				make(chan struct{}):   1,
			},
			Output: typeTree{_type: bindings.WAFMapType},
		},
		{
			Name: "unsupported-map-values",
			Input: map[string]any{
				"k0": func() {},
				"k2": make(chan struct{}),
			},
			Output: typeTree{_type: bindings.WAFMapType, children: []typeTree{{_type: bindings.WAFInvalidType}, {_type: bindings.WAFInvalidType}}},
		},
		{
			Name: "nil-map-values",
			Input: map[string]any{
				"k0": (*struct{ a int })(nil),
				"k1": (*string)(nil),
				"k2": (*int)(nil),
			},
			Output: typeTree{_type: bindings.WAFMapType, children: []typeTree{{_type: bindings.WAFNilType}, {_type: bindings.WAFNilType}, {_type: bindings.WAFNilType}}},
		},
	} {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		encoder, _ := NewDefaultEncoder(newMaxEncoderConfig(&pinner))
		encoded, err := encoder.Encode(tc.Input)
		t.Run(tc.Name+"/assert", func(t *testing.T) {
			if tc.Error != nil {
				require.Error(t, err, "expected an encoding error when encoding %v", tc.Input)
				require.Equal(t, tc.Error, err)
				return
			}

			require.NoError(t, err, "unexpected error when encoding: %v", err)
			assertEqualType(t, tc.Output, encoded)
		})

		t.Run(tc.Name+"/run", func(t *testing.T) {
			wafTest(t, encoded)
		})
	}
}

// This test needs a working encoder to function properly, as it first encodes the objects before decoding them
func TestDecoder(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		encoder, _ := NewDefaultEncoder(newMaxEncoderConfig(&pinner))
		objBuilder := func(value any) *bindings.WAFObject {
			encoded, err := encoder.Encode(value)
			require.NoError(t, err, "Encoding object failed")
			return encoded
		}

		for _, tc := range []struct {
			Name          string
			ExpectedValue map[string][]string
		}{
			{
				Name:          "empty",
				ExpectedValue: nil,
			},
			{
				Name: "one-empty-entry",
				ExpectedValue: map[string][]string{
					"afasdfafs": nil,
				},
			},
			{
				Name: "one-filled-entry",
				ExpectedValue: map[string][]string{
					"afasdfafs": {"rule1", "rule2"},
				},
			},
			{
				Name: "multiple-entries",
				ExpectedValue: map[string][]string{
					"afasdfafs": {"rule1", "rule2"},
					"sfdsafdsa": {"rule3", "rule4"},
				},
			},
		} {
			t.Run(tc.Name, func(t *testing.T) {
				input := tc.ExpectedValue
				if input == nil {
					input = map[string][]string{} // So it encodes to an empty map, not nil.
				}
				val, err := decodeErrors(objBuilder(input))
				require.NoErrorf(t, err, "Error decoding the object: %v", err)
				require.Equal(t, tc.ExpectedValue, val)
			})
		}
	})
}

func TestResolvePointer(t *testing.T) {
	t.Run("is nil-safe", func(t *testing.T) {
		val := reflect.ValueOf((*string)(nil))
		res, kind := resolvePointer(val)
		require.Equal(t, reflect.Pointer, kind)
		require.Equal(t, val, res)
	})

	t.Run("is safe with recursive pointers", func(t *testing.T) {
		var s any
		s = &s // Now s points to itself!

		res, kind := resolvePointer(reflect.ValueOf(s))
		require.True(t, kind == reflect.Pointer || kind == reflect.Interface)
		require.True(t, res == reflect.ValueOf(s) || res == reflect.ValueOf(s).Elem())
	})
}

func TestDepthOf(t *testing.T) {
	t.Run("is safe with self-referecing structs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
		defer cancel()

		type selfReferencing struct {
			Array []any
		}
		obj := selfReferencing{Array: make([]any, 1)}
		obj.Array[0] = &obj // Obj now has a field that indirectly references itself

		depth, err := depthOf(ctx, reflect.ValueOf(obj))
		require.Greater(t, depth, 0)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}
