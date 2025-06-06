// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package libddwaf

import (
	"runtime"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/object"
	"github.com/DataDog/go-libddwaf/v4/object/reflect"
	"github.com/stretchr/testify/require"
)

// This test needs a working Encoder to function properly, as it first encodes the objects before decoding them
func TestDecodeErrors(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		encoder, _ := reflect.NewEncoder(object.NewUnlimitedEncoderConfig(&pinner))
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
