// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package bindings

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// largeJSONArray returns a JSON array of n strings: "v0", "v1", ...
func largeJSONArray(n int) []byte {
	var sb strings.Builder
	sb.WriteByte('[')
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"v%d"`, i)
	}
	sb.WriteByte(']')
	return []byte(sb.String())
}

// largeJSONObject returns a JSON object with n keys: {"k0":"v0","k1":"v1",...}
func largeJSONObject(n int) []byte {
	var sb strings.Builder
	sb.WriteByte('{')
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"k%d":"v%d"`, i, i)
	}
	sb.WriteByte('}')
	return []byte(sb.String())
}

// TestWAFObjectLargeFromJSON uses the real libddwaf library to make the
// objects, so it checks the large layout (type, size, capacity bit-fields)
// against the compiled C code of the embedded library.
func TestWAFObjectLargeFromJSON(t *testing.T) {
	ok, err := Load()
	require.True(t, ok, "libddwaf must load: %v", err)

	parse := func(t *testing.T, json []byte) *WAFObject {
		t.Helper()
		obj, ok := Lib.ObjectFromJSON(json, Lib.DefaultAllocator())
		require.True(t, ok, "ddwaf_object_from_json failed")
		t.Cleanup(func() { Lib.ObjectDestroy(&obj, Lib.DefaultAllocator()) })
		return &obj
	}

	t.Run("array", func(t *testing.T) {
		for _, tc := range []struct {
			size     int
			expected WAFObjectType
		}{
			{size: 65_535, expected: WAFArrayType},
			{size: 65_536, expected: WAFLargeArrayType},
			{size: 70_000, expected: WAFLargeArrayType},
		} {
			t.Run(fmt.Sprint(tc.size), func(t *testing.T) {
				obj := parse(t, largeJSONArray(tc.size))
				require.Equal(t, tc.expected, obj.Type())
				require.True(t, obj.IsArray())
				require.False(t, obj.IsMap())

				size, err := obj.ArraySize()
				if tc.expected == WAFArrayType {
					require.NoError(t, err)
					require.EqualValues(t, tc.size, size)
				} else {
					require.Error(t, err)
				}

				values, err := obj.ArrayValues()
				require.NoError(t, err)
				require.Len(t, values, tc.size)

				first, err := values[0].StringValue()
				require.NoError(t, err)
				require.Equal(t, "v0", first)
				last, err := values[tc.size-1].StringValue()
				require.NoError(t, err)
				require.Equal(t, fmt.Sprintf("v%d", tc.size-1), last)

				decoded, err := obj.AnyValue()
				require.NoError(t, err)
				require.Len(t, decoded, tc.size)
				require.Equal(t, fmt.Sprintf("v%d", tc.size-1), decoded.([]any)[tc.size-1])
			})
		}
	})

	t.Run("map", func(t *testing.T) {
		for _, tc := range []struct {
			size     int
			expected WAFObjectType
		}{
			{size: 65_535, expected: WAFMapType},
			{size: 65_536, expected: WAFLargeMapType},
			{size: 70_000, expected: WAFLargeMapType},
		} {
			t.Run(fmt.Sprint(tc.size), func(t *testing.T) {
				obj := parse(t, largeJSONObject(tc.size))
				require.Equal(t, tc.expected, obj.Type())
				require.True(t, obj.IsMap())
				require.False(t, obj.IsArray())

				size, err := obj.MapSize()
				if tc.expected == WAFMapType {
					require.NoError(t, err)
					require.EqualValues(t, tc.size, size)
				} else {
					require.Error(t, err)
				}

				entries, err := obj.MapEntries()
				require.NoError(t, err)
				require.Len(t, entries, tc.size)

				decoded, err := obj.MapValue()
				require.NoError(t, err)
				require.Len(t, decoded, tc.size)
				require.Equal(t, "v0", decoded["k0"])
				require.Equal(t, fmt.Sprintf("v%d", tc.size-1), decoded[fmt.Sprintf("k%d", tc.size-1)])
			})
		}
	})
}
