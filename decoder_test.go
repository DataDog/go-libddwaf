// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test needs a working encoder to function properly, as it first encodes the objects before decoding them
func TestDecoder(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		e := newMaxEncoder()
		objBuilder := func(value any) *wafObject {
			encoded, err := e.Encode(value)
			require.NoError(t, err, "Encoding object failed")
			return encoded
		}

		for _, tc := range []struct {
			Name          string
			ExpectedValue map[string][]string
		}{
			{
				Name:          "empty",
				ExpectedValue: map[string][]string{},
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
				val, err := decodeErrors(objBuilder(tc.ExpectedValue))
				require.NoErrorf(t, err, "Error decoding the object: %v", err)
				require.Equal(t, tc.ExpectedValue, val)
			})
		}

		keepAlive(e.cgoRefs.arrayRefs)
		keepAlive(e.cgoRefs.stringRefs)
	})
	t.Run("Values", func(t *testing.T) {

		for _, tc := range []struct {
			name string
			data any
		}{
			{
				name: "int64",
				data: int64(-4),
			},
			{
				name: "uint64",
				data: uint64(4),
			},
			{
				name: "float64",
				data: 4.4444,
			},
			{
				name: "bool",
				data: true,
			},
			{
				name: "bool",
				data: false,
			},
			{
				name: "string",
				data: "",
			},
			{
				name: "string",
				data: "EliottAndFrancoisLoveDecoding",
			},
			{
				name: "string",
				data: "123",
			},
			{
				name: "slice",
				data: []any{int64(1), int64(2), int64(3), int64(4)},
			},
			{
				name: "slice",
				data: []any{"1", "2", "3", "4"},
			},
			{
				name: "slice",
				data: []any{true, false, false, true, true, true},
			},
			{
				name: "slice-nested",
				data: []any{[]any{true, false}, []any{false, false}, []any{true, true, true}},
			},
			{
				name: "map",
				data: map[string]any{"1": int64(1), "2": int64(2), "3": int64(3)},
			},
			{
				name: "map",
				data: map[string]any{"1": uint64(1), "2": uint64(2), "3": uint64(3)},
			},
			{
				name: "map",
				data: map[string]any{"1": 1.111, "2": 2.222, "3": 3.333},
			},
			{
				name: "map",
				data: map[string]any{"1": "1", "2": "2", "3": "3"},
			},
			{
				name: "map-nested",
				data: map[string]any{"1": map[string]any{"1": int64(1), "2": int64(2)}, "2": map[string]any{"3": int64(3), "4": int64(4)}},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newMaxEncoder()
				obj, err := e.Encode(tc.data)
				require.NoError(t, err)

				val, err := decodeObject(obj)
				require.NoError(t, err)
				require.True(t, reflect.DeepEqual(tc.data, val))
			})
		}

	})
}
