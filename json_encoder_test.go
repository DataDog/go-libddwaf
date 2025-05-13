// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.25 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/waferrors"

	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/stretchr/testify/require"
)

// decodeObject, decodeArray, decodeMap are assumed to exist elsewhere in the package
// (e.g., from encoder_decoder_test.go or a test utility file)
// and will be used directly.

// Helper to create a jsonEncoder with default test settings
func newTestJSONEncoder(pinner *runtime.Pinner, initiallyTruncated bool) *jsonEncoder {
	// Corrected timer usage: timer.WithUnlimitedBudget() is an option itself.
	// If timer.UnlimitedBudget is a duration, it should be timer.WithBudget(timer.UnlimitedBudget).
	// Assuming WithUnlimitedBudget() is the intended option based on common patterns.
	tm, err := timer.NewTimer(timer.WithUnlimitedBudget())
	if err != nil {
		panic(err) // Should not happen with unlimited budget
	}
	return newJSONEncoder(pinner, tm, initiallyTruncated)
}

// Helper to sort truncation values for consistent comparison
func sortTruncations(truncations map[TruncationReason][]int) map[TruncationReason][]int {
	if truncations == nil {
		return nil
	}
	for k := range truncations {
		sort.Ints(truncations[k])
	}
	return truncations
}

func TestJSONEncode_SimpleTypes(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	testCases := []struct {
		name           string
		jsonInput      string
		expectedOutput any
		expectedError  error
		expectedTruncs map[TruncationReason][]int
	}{
		{
			name:           "null",
			jsonInput:      `null`,
			expectedOutput: nil,
		},
		{
			name:           "boolean true",
			jsonInput:      `true`,
			expectedOutput: true,
		},
		{
			name:           "boolean false",
			jsonInput:      `false`,
			expectedOutput: false,
		},
		{
			name:           "simple string",
			jsonInput:      `"hello world"`,
			expectedOutput: "hello world",
		},
		{
			name:           "empty string",
			jsonInput:      `""`,
			expectedOutput: "",
		},
		{
			name:           "integer zero",
			jsonInput:      `0`,
			expectedOutput: int64(0),
		},
		{
			name:           "positive integer",
			jsonInput:      `12345`,
			expectedOutput: int64(12345),
		},
		{
			name:           "negative integer",
			jsonInput:      `-67890`,
			expectedOutput: int64(-67890),
		},
		{
			name:           "float zero",
			jsonInput:      `0.0`,
			expectedOutput: float64(0.0),
		},
		{
			name:           "positive float",
			jsonInput:      `123.456`,
			expectedOutput: float64(123.456),
		},
		{
			name:           "negative float",
			jsonInput:      `-78.901`,
			expectedOutput: float64(-78.901),
		},
		{
			name:           "float scientific",
			jsonInput:      `1.23e4`, // 12300
			expectedOutput: float64(12300),
		},
		{
			name:           "large integer (fits int64)",
			jsonInput:      `9223372036854775807`, // MaxInt64
			expectedOutput: int64(9223372036854775807),
		},
		{
			name:           "very large integer (becomes float64)",
			jsonInput:      `9223372036854775808`, // MaxInt64 + 1
			expectedOutput: float64(9223372036854775808),
		},
		{
			name:           "very large negative integer (becomes float64)",
			jsonInput:      `-9223372036854775809`, // MinInt64 - 1
			expectedOutput: float64(-9223372036854775809),
		},
		{
			name:      "number too large for float64 (becomes string)",
			jsonInput: `1e400`, // Too large for float64
			// Expected to be stored as string by our number parsing logic
			expectedOutput: "1e400",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoder := newTestJSONEncoder(&pinner, false)
			wafObj, err := encoder.Encode([]byte(tc.jsonInput))

			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedError, "unexpected error type")
				// If an error is expected, WAF object might be nil or partially formed.
				// Further assertions on wafObj might be needed depending on expected behavior.
				return
			}

			if err != nil && err.Error() == "EOF" {
				err = nil
			}

			require.NoError(t, err, "Encode failed unexpectedly")
			require.NotNil(t, wafObj, "WAFObject is nil")

			decoded, decodeErr := decodeObject(wafObj)
			require.NoError(t, decodeErr, "decodeObject failed")

			require.True(t, reflect.DeepEqual(tc.expectedOutput, decoded), fmt.Sprintf("Decoded object mismatch.\nExpected: %v\nGot:      %v", tc.expectedOutput, decoded))

			actualTruncs := encoder.Truncations()
			// Sort values in actualTruncs for consistent comparison, if needed
			// For these simple types, expecting no truncations.
			if len(tc.expectedTruncs) == 0 {
				require.Empty(t, actualTruncs, "Expected no truncations")
			} else {
				require.Equal(t, sortTruncations(tc.expectedTruncs), sortTruncations(actualTruncs), "Truncations mismatch")
			}
		})
	}
}

func TestJSONEncode_Arrays(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	testCases := []struct {
		name           string
		jsonInput      string
		expectedOutput any
		encoderSetup   func(e *jsonEncoder) // For configuring limits
		expectedError  error
		expectedTruncs map[TruncationReason][]int
	}{
		{
			name:           "empty array",
			jsonInput:      `[]`,
			expectedOutput: []any{},
		},
		{
			name:           "simple array of numbers",
			jsonInput:      `[1, 2, 3]`,
			expectedOutput: []any{int64(1), int64(2), int64(3)},
		},
		{
			name:           "array of mixed types",
			jsonInput:      `[1, "two", true, null, 3.14]`,
			expectedOutput: []any{int64(1), "two", true, float64(3.14)},
		},
		{
			name:      "nested arrays",
			jsonInput: `[[1, 2], ["three"], [], [true, null]]`,
			expectedOutput: []any{
				[]any{int64(1), int64(2)},
				[]any{"three"},
				[]any{},
				[]any{true},
			},
		},
		{
			name:      "array container too large",
			jsonInput: `[1, 2, 3, 4, 5, 6]`,
			encoderSetup: func(e *jsonEncoder) {
				e.containerMaxSize = 3
			},
			expectedOutput: []any{int64(1), int64(2), int64(3)},
			expectedTruncs: map[TruncationReason][]int{ContainerTooLarge: {6}},
		},
		{
			name:      "array depth",
			jsonInput: `[1, 2, [4, 5]]`, // Depth 3 for the innermost array containing 1
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 1
			},
			expectedOutput: []any{int64(1), int64(2)},
			expectedTruncs: map[TruncationReason][]int{ObjectTooDeep: {2}},
		},
		{
			name:      "array object too deep",
			jsonInput: `[[[1]]]`, // Depth 3 for the innermost array containing 1
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 2
			},
			expectedOutput: []any{[]any{}},
			expectedTruncs: map[TruncationReason][]int{ObjectTooDeep: {3}},
		},
		{
			name:      "array object too deep - complex",
			jsonInput: `[1, [2, [3, "deep"]]]`,
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 3 // Allows [1], [2, ...], [3, "deep"]. "deep" string is at depth 3 with its array.
			},
			expectedOutput: []any{int64(1), []any{int64(2), []any{int64(3), "deep"}}},
		},
		{
			name:      "array object too deep - at limit",
			jsonInput: `[1, [2, [3, "deep"]]]`,
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 2 // Allows [1], [2, ...]. The array [3, "deep"] is at depth 3.
			},
			expectedOutput: []any{int64(1), []any{int64(2)}},
			expectedTruncs: map[TruncationReason][]int{ObjectTooDeep: {3}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoder := newTestJSONEncoder(&pinner, false)
			if tc.encoderSetup != nil {
				tc.encoderSetup(encoder)
			}

			wafObj, err := encoder.Encode([]byte(tc.jsonInput))

			if tc.expectedError != nil {
				// For MaxDepthExceeded, the error is returned by Encode if the top-level object itself is too deep,
				// or if a nested parseValue fails and that error propagates up.
				require.Error(t, err, "Expected an error during Encode")
				require.ErrorIs(t, err, tc.expectedError, fmt.Sprintf("Error mismatch. Expected %v, got %v", tc.expectedError, err))
				// We might still have a partially formed object if the error didn't occur at the root
				if wafObj != nil && tc.expectedOutput != nil {
					decoded, decodeErr := decodeObject(wafObj)
					require.NoError(t, decodeErr, "decodeObject failed on partially formed object")
					require.True(t, reflect.DeepEqual(tc.expectedOutput, decoded), fmt.Sprintf("Partially decoded object mismatch.\nExpected: %v\nGot:      %v", tc.expectedOutput, decoded))
				}
				actualTruncs := encoder.Truncations()
				require.Equal(t, sortTruncations(tc.expectedTruncs), sortTruncations(actualTruncs), "Truncations mismatch on error path")
				return
			}

			require.NoError(t, err, "Encode failed unexpectedly")
			require.NotNil(t, wafObj, "WAFObject is nil")

			decoded, decodeErr := decodeObject(wafObj)
			require.NoError(t, decodeErr, "decodeObject failed")

			require.True(t, reflect.DeepEqual(tc.expectedOutput, decoded), fmt.Sprintf("Decoded object mismatch.\nExpected: %v\nGot:      %v", tc.expectedOutput, decoded))

			actualTruncs := encoder.Truncations()
			if len(tc.expectedTruncs) == 0 {
				require.Empty(t, actualTruncs, "Expected no truncations")
			} else {
				require.Equal(t, sortTruncations(tc.expectedTruncs), sortTruncations(actualTruncs), "Truncations mismatch")
			}
		})
	}
}

func TestJSONEncode_Objects(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	testCases := []struct {
		name                string
		jsonInput           string
		expectedOutput      any
		encoderSetup        func(e *jsonEncoder) // For configuring limits
		expectedError       error
		expectedDecodeError error
		expectedTruncs      map[TruncationReason][]int
	}{
		{
			name:           "empty object",
			jsonInput:      `{}`,
			expectedOutput: map[string]any{},
		},
		{
			name:           "simple object",
			jsonInput:      `{"key1": "value1", "key2": 123, "key3": true, "key4": null, "key5": 3.14}`,
			expectedOutput: map[string]any{"key1": "value1", "key2": int64(123), "key3": true, "key4": nil, "key5": float64(3.14)},
		},
		{
			name:      "nested object",
			jsonInput: `{"level1_key1": "value1", "level1_key2": {"level2_key1": 456, "level2_key2": {"level3_key1": "deep_value"}}}`,
			expectedOutput: map[string]any{
				"level1_key1": "value1",
				"level1_key2": map[string]any{
					"level2_key1": int64(456),
					"level2_key2": map[string]any{
						"level3_key1": "deep_value",
					},
				},
			},
		},
		{
			name:      "object container too large",
			jsonInput: `{"a":1, "b":2, "c":3, "d":4, "e":5}`,
			encoderSetup: func(e *jsonEncoder) {
				e.containerMaxSize = 3
			},
			expectedOutput: map[string]any{"a": int64(1), "b": int64(2), "c": int64(3)},
			expectedTruncs: map[TruncationReason][]int{ContainerTooLarge: {5}},
		},
		{
			name:      "object key string too long",
			jsonInput: `{"verylongkeyname": 1, "shortkey": 2}`,
			encoderSetup: func(e *jsonEncoder) {
				e.stringMaxSize = 5
			},
			expectedOutput: map[string]any{"veryl": int64(1), "short": int64(2)},
			expectedTruncs: map[TruncationReason][]int{StringTooLong: {15, 8}}, // Lengths of "verylongkeyname" and "shortkey"
		},
		{
			name:      "object value string too long",
			jsonInput: `{"key1": "verylongstringvalue", "key2": "short"}`,
			encoderSetup: func(e *jsonEncoder) {
				e.stringMaxSize = 5
			},
			expectedOutput: map[string]any{"key1": "veryl", "key2": "short"},
			expectedTruncs: map[TruncationReason][]int{StringTooLong: {19}}, // Length of "verylongstringvalue"
		},
		{
			name:      "object object too deep",
			jsonInput: `{"a": {"b": {"c": 1}}}`, // c:1 is at depth 3 (obj a, obj b, obj c)
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 2 // Allows obj a and obj b. obj c is too deep.
			},
			// As the map is truncated, the "c" object value is replaced by an invalid wAF object
			// thus returning a decoding error
			expectedDecodeError: waferrors.ErrUnsupportedValue,
			expectedOutput:      nil,
			expectedTruncs:      map[TruncationReason][]int{ObjectTooDeep: {3}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoder := newTestJSONEncoder(&pinner, false)
			if tc.encoderSetup != nil {
				tc.encoderSetup(encoder)
			}

			wafObj, err := encoder.Encode([]byte(tc.jsonInput))

			if tc.expectedError != nil {
				require.Error(t, err, "Expected an error during Encode")
				require.ErrorIs(t, err, tc.expectedError, fmt.Sprintf("Error mismatch. Expected %v, got %v", tc.expectedError, err))
				if wafObj != nil && tc.expectedOutput != nil {
					decoded, decodeErr := decodeObject(wafObj)
					require.NoError(t, decodeErr, "decodeObject failed on partially formed object")
					// For objects, especially with key truncation or container truncation, exact match of tc.expectedOutput might be tricky
					// if iteration order isn't guaranteed. Consider alternative checks if DeepEqual fails.
					require.True(t, reflect.DeepEqual(tc.expectedOutput, decoded), fmt.Sprintf("Partially decoded object mismatch.\nExpected: %v\nGot:      %v", tc.expectedOutput, decoded))
				}
				actualTruncs := encoder.Truncations()
				require.Equal(t, sortTruncations(tc.expectedTruncs), sortTruncations(actualTruncs), "Truncations mismatch on error path")
				return
			}

			require.NoError(t, err, "Encode failed unexpectedly")
			require.NotNil(t, wafObj, "WAFObject is nil")

			decoded, decodeErr := decodeObject(wafObj)

			if tc.expectedDecodeError != nil {
				require.Error(t, decodeErr, "Expected an error during Decode")
			} else {
				require.NoError(t, decodeErr, "decodeObject failed")
			}

			// Special handling for map container too large due to unpredictable key order
			if tc.name == "object container too large" {
				decodedMap, ok := decoded.(map[string]any)
				require.True(t, ok, "Decoded output is not a map for 'object container too large' test")
				require.Len(t, decodedMap, encoder.containerMaxSize, "Map size after truncation is incorrect")
			} else if tc.expectedDecodeError == nil {
				require.True(t, reflect.DeepEqual(tc.expectedOutput, decoded), fmt.Sprintf("Decoded object mismatch.\nExpected: %v\nGot:      %v", tc.expectedOutput, decoded))
			}

			actualTruncs := encoder.Truncations()
			if len(tc.expectedTruncs) == 0 {
				require.Empty(t, actualTruncs, "Expected no truncations")
			} else {
				require.Equal(t, sortTruncations(tc.expectedTruncs), sortTruncations(actualTruncs), "Truncations mismatch")
			}
		})
	}
}

func TestJSONEncode_InvalidInput(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	type expectation struct {
		truncations         map[TruncationReason][]int
		expectedOutput      any
		expectEncodingError bool
	}

	testCases := []struct {
		name                    string
		jsonInput               string
		encoderSetup            func(e *jsonEncoder)
		truncatedExpectation    expectation
		notTruncatedExpectation expectation
		truncatedBytesLimit     int
	}{
		{
			name:      "malformed json - unclosed object",
			jsonInput: `{"key": "value"`,
			truncatedExpectation: expectation{
				expectedOutput: map[string]any{"key": "value"},
			},
			notTruncatedExpectation: expectation{
				expectedOutput:      nil,
				expectEncodingError: true,
			},
		},
		{
			// malformed json - full discard
			name:      "malformed json - trailing comma in array",
			jsonInput: `[1, 2, ]`,
			truncatedExpectation: expectation{
				expectedOutput: []any{int64(1), int64(2)}, // Might change
			},
			notTruncatedExpectation: expectation{
				expectEncodingError: true,
			},
		},
		{
			name:      "malformed json - trailing comma in array",
			jsonInput: `[1, 2,`,
			truncatedExpectation: expectation{
				expectedOutput: []any{int64(1), int64(2)},
			},
			notTruncatedExpectation: expectation{
				expectEncodingError: true,
			},
		},
		{
			name:      "malformed json - trailing comma in object",
			jsonInput: `{"key1":"val1", }`,
			truncatedExpectation: expectation{
				expectedOutput: map[string]any{"key1": "val1"}, // Might change
			},
			notTruncatedExpectation: expectation{
				expectEncodingError: true,
			},
		},
		{
			name:      "malformed json - missing colon",
			jsonInput: `{"key" "value"}`,
			truncatedExpectation: expectation{
				expectedOutput: map[string]any{}, // Might change to invalid
			},
			notTruncatedExpectation: expectation{
				expectEncodingError: true,
			},
		},
		{
			name:      "malformed json - bare string",
			jsonInput: `hello world`,
			truncatedExpectation: expectation{
				expectEncodingError: true,
			},
			notTruncatedExpectation: expectation{
				expectEncodingError: true,
			},
		},
		{
			name:      "root string too long",
			jsonInput: `"thisisaverylongstringthatwillbetruncated"`,
			encoderSetup: func(e *jsonEncoder) {
				e.stringMaxSize = 10
			},
			truncatedExpectation: expectation{
				expectedOutput: "thisisaver",
				truncations:    map[TruncationReason][]int{StringTooLong: {40}}, // Length of original string
			},
			notTruncatedExpectation: expectation{
				expectedOutput: "thisisaver",
				truncations:    map[TruncationReason][]int{StringTooLong: {40}},
			},
		},
		{
			name:      "root level not an object or array - max depth 0",
			jsonInput: `"string"`, // A string is not a container, depth is effectively 0 for it.
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 0
			},
			truncatedExpectation: expectation{
				expectedOutput: "string",
			},
			notTruncatedExpectation: expectation{
				expectedOutput: "string",
			},
		},
		{
			name:      "object max depth 0 - actual object",
			jsonInput: `{}`,
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 0
			},
			truncatedExpectation: expectation{
				truncations:         map[TruncationReason][]int{ObjectTooDeep: {1}},
				expectEncodingError: true,
			},
			notTruncatedExpectation: expectation{
				truncations:         map[TruncationReason][]int{ObjectTooDeep: {1}},
				expectEncodingError: true,
			},
		},
		{
			name:      "array max depth 0 - actual array",
			jsonInput: `[]`,
			encoderSetup: func(e *jsonEncoder) {
				e.objectMaxDepth = 0
			},
			truncatedExpectation: expectation{
				truncations:         map[TruncationReason][]int{ObjectTooDeep: {1}},
				expectEncodingError: true,
			},
			notTruncatedExpectation: expectation{
				truncations:         map[TruncationReason][]int{ObjectTooDeep: {1}},
				expectEncodingError: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			expectations := map[bool]expectation{
				true:  tc.truncatedExpectation,
				false: tc.notTruncatedExpectation,
			}

			for truncated, exp := range expectations {
				encoder := newTestJSONEncoder(&pinner, truncated)
				if tc.encoderSetup != nil {
					tc.encoderSetup(encoder)
				}

				if !truncated {
					// Unmarshal using encoding/json
					var decoded any
					err := json.Unmarshal([]byte(tc.jsonInput), &decoded)

					if exp.expectEncodingError && err == nil {
						t.Fatalf("Expected an error during Encode, but got nil")
					}

					if !exp.expectEncodingError && err != nil {
						t.Fatalf("Expected no error during Encode, but got %v", err)
					}
				}

				wafObj, err := encoder.Encode([]byte(tc.jsonInput))

				if exp.expectEncodingError {
					require.Error(t, err, "Expected an error during Encode")
					require.Nil(t, wafObj, "WAFObject is not nil")
					return
				}

				require.NoError(t, err, "Encode failed unexpectedly")
				require.NotNil(t, wafObj, "WAFObject is nil")

				decoded, decodeErr := decodeObject(wafObj)

				require.NoError(t, decodeErr, "decodeObject failed")
				require.NotNil(t, decoded, "Decoded object is nil")

				require.True(t, reflect.DeepEqual(exp.expectedOutput, decoded), fmt.Sprintf("Decoded object mismatch.\nExpected: %v\nGot:      %v", exp.expectedOutput, decoded))

				actualTruncs := encoder.Truncations()
				if len(exp.truncations) == 0 {
					require.Empty(t, actualTruncs, "Expected no truncations")
				} else {
					require.Equal(t, sortTruncations(exp.truncations), sortTruncations(actualTruncs), "Truncations mismatch")
				}

			}

		})
	}
}

// We'll add more tests for arrays, objects, and truncations next.
// For example: TestJSONEncode_Arrays, TestJSONEncode_Objects, TestJSONEncode_Truncations
