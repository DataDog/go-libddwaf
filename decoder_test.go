// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/DataDog/go-libddwaf/v5/waferrors"

	"github.com/stretchr/testify/require"
)

// diagnosticsFeatureKeys lists the top-level diagnostics keys that hold a
// Feature, in the same order as the fields of Diagnostics.
var diagnosticsFeatureKeys = []string{
	"rules",
	"custom_rules",
	"actions",
	"exclusions",
	"rules_override",
	"rules_data",
	"exclusion_data",
	"processors",
	"processor_overrides",
	"scanners",
}

// encodeForDecoderTest encodes a Go value into a WAFObject that the pinner keeps alive.
func encodeForDecoderTest(t testing.TB, p *runtime.Pinner, v any) *WAFObject {
	t.Helper()

	encoder, err := newEncoder(newEncoderConfig(p, WithUnlimitedLimits()))
	require.NoError(t, err)

	obj, err := encoder.Encode(v)
	require.NoError(t, err)
	return obj
}

// newIntObject returns a WAFObject that holds an integer.
func newIntObject() *WAFObject {
	obj := new(WAFObject)
	obj.SetInt(42)
	return obj
}

// newIntKeyMapObject returns a map with one entry whose key is an integer, and
// not a string.
func newIntKeyMapObject(p *runtime.Pinner) *WAFObject {
	obj := new(WAFObject)
	entries := obj.SetMap(p, 1)
	entries[0].Key.SetInt(1)
	entries[0].Val.SetInt(2)
	obj.SetMapSize(1)
	return obj
}

// newCorruptMapObject returns a map that has a size of 1 and a nil entries
// pointer. The public setters cannot build this object, so the size is written
// directly. The offset 2 is the size field of a map in the C ddwaf_object layout.
func newCorruptMapObject() *WAFObject {
	const mapSizeOffset = 2

	obj := new(WAFObject)
	obj.SetMap(nil, 0)
	size := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(obj), mapSizeOffset)), 2)
	binary.NativeEndian.PutUint16(size, 1)
	return obj
}

func TestDecodeDiagnosticsFieldMapping(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// Each feature gets its own key as its only loaded ID. A key that is
	// decoded into the wrong field makes the comparison fail.
	input := map[string]any{
		"ruleset_version": "1.2.3",
		"unknown_key":     map[string]any{"loaded": []any{"unknown_key"}},
	}
	for _, key := range diagnosticsFeatureKeys {
		input[key] = map[string]any{"loaded": []any{key}}
	}

	diags, err := decodeDiagnostics(encodeForDecoderTest(t, &pinner, input))
	require.NoError(t, err)

	require.Equal(t, Diagnostics{
		Rules:              &Feature{Loaded: []string{"rules"}},
		CustomRules:        &Feature{Loaded: []string{"custom_rules"}},
		Actions:            &Feature{Loaded: []string{"actions"}},
		Exclusions:         &Feature{Loaded: []string{"exclusions"}},
		RulesOverrides:     &Feature{Loaded: []string{"rules_override"}},
		RulesData:          &Feature{Loaded: []string{"rules_data"}},
		ExclusionData:      &Feature{Loaded: []string{"exclusion_data"}},
		Processors:         &Feature{Loaded: []string{"processors"}},
		ProcessorOverrides: &Feature{Loaded: []string{"processor_overrides"}},
		Scanners:           &Feature{Loaded: []string{"scanners"}},
		Version:            "1.2.3",
	}, diags)
}

func TestDecodeFeatureFieldMapping(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// Each field gets a different value. A key that is decoded into the wrong
	// field makes the comparison fail.
	obj := encodeForDecoderTest(t, &pinner, map[string]any{
		"error":    "the error",
		"errors":   map[string]any{"error-message": []any{"error-rule-1", "error-rule-2"}},
		"warnings": map[string]any{"warning-message": []any{"warning-rule"}},
		"failed":   []any{"failed-rule"},
		"loaded":   []any{"loaded-rule-1", "loaded-rule-2"},
		"skipped":  []any{"skipped-rule"},
		"unknown":  "ignored",
	})

	feature, err := decodeFeature(obj)
	require.NoError(t, err)

	require.Equal(t, &Feature{
		Error:    "the error",
		Errors:   map[string][]string{"error-message": {"error-rule-1", "error-rule-2"}},
		Warnings: map[string][]string{"warning-message": {"warning-rule"}},
		Failed:   []string{"failed-rule"},
		Loaded:   []string{"loaded-rule-1", "loaded-rule-2"},
		Skipped:  []string{"skipped-rule"},
	}, feature)
}

// decoderErrorCase is one row of an error table. The build function receives
// the subtest's t, and not the parent test's t.
type decoderErrorCase struct {
	name  string
	build func(t testing.TB, p *runtime.Pinner) *WAFObject
	// want is the exact error text.
	want string
	// notSentinel is true when the error must not wrap waferrors.ErrInvalidObjectType.
	// Every other error must wrap it.
	notSentinel bool
}

func runDecoderErrorCases[T any](t *testing.T, decode func(*WAFObject) (T, error), cases []decoderErrorCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pinner runtime.Pinner
			defer pinner.Unpin()

			_, err := decode(tc.build(t, &pinner))
			require.EqualError(t, err, tc.want)
			if tc.notSentinel {
				require.NotErrorIs(t, err, waferrors.ErrInvalidObjectType)
			} else {
				require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
			}
		})
	}
}

func TestDecodeDiagnosticsErrors(t *testing.T) {
	const invalidType = "invalid type encountered when decoding"

	cases := []decoderErrorCase{
		{
			name:  "not-a-map",
			build: func(testing.TB, *runtime.Pinner) *WAFObject { return newIntObject() },
			want:  "decodeDiagnostics: " + invalidType + ": expected map, got int",
		},
		{
			name:        "map-entries-error",
			build:       func(testing.TB, *runtime.Pinner) *WAFObject { return newCorruptMapObject() },
			want:        "decodeDiagnostics: failed to get map entries: nil pointer in map object with size 1",
			notSentinel: true,
		},
		{
			name:  "non-string-key",
			build: func(_ testing.TB, p *runtime.Pinner) *WAFObject { return newIntKeyMapObject(p) },
			want:  "decodeDiagnostics: failed to decode diagnostics key: " + invalidType + ": value is not a string but int",
		},
		{
			name: "ruleset_version-not-a-string",
			build: func(t testing.TB, p *runtime.Pinner) *WAFObject {
				return encodeForDecoderTest(t, p, map[string]any{"ruleset_version": 42})
			},
			want: `decodeDiagnostics: failed to decode feature "ruleset_version": ` + invalidType + ": value is not a string but int",
		},
	}

	for _, key := range diagnosticsFeatureKeys {
		cases = append(cases, decoderErrorCase{
			name: key + "-not-a-map",
			build: func(t testing.TB, p *runtime.Pinner) *WAFObject {
				return encodeForDecoderTest(t, p, map[string]any{key: 42})
			},
			want: fmt.Sprintf("decodeDiagnostics: failed to decode feature %q: decodeFeature: %s: expected map, got int", key, invalidType),
		})
	}

	runDecoderErrorCases(t, decodeDiagnostics, cases)
}

func TestDecodeFeatureErrors(t *testing.T) {
	const invalidType = "invalid type encountered when decoding"

	cases := []decoderErrorCase{
		{
			name:  "not-a-map",
			build: func(testing.TB, *runtime.Pinner) *WAFObject { return newIntObject() },
			want:  "decodeFeature: " + invalidType + ": expected map, got int",
		},
		{
			name:        "map-entries-error",
			build:       func(testing.TB, *runtime.Pinner) *WAFObject { return newCorruptMapObject() },
			want:        "decodeFeature: failed to get map entries: nil pointer in map object with size 1",
			notSentinel: true,
		},
		{
			name:  "non-string-key",
			build: func(_ testing.TB, p *runtime.Pinner) *WAFObject { return newIntKeyMapObject(p) },
			want:  "decodeFeature: failed to decode key: " + invalidType + ": value is not a string but int",
		},
	}

	fields := []struct {
		name string
		want string
	}{
		{"error", invalidType + ": value is not a string but int"},
		{"errors", "decodeErrors: " + invalidType + ": expected map, got int"},
		{"warnings", "decodeErrors: " + invalidType + ": expected map, got int"},
		{"failed", "decodeStringArray: " + invalidType + ": expected array, got int"},
		{"loaded", "decodeStringArray: " + invalidType + ": expected array, got int"},
		{"skipped", "decodeStringArray: " + invalidType + ": expected array, got int"},
	}
	for _, field := range fields {
		cases = append(cases, decoderErrorCase{
			name: field.name + "-wrong-type",
			build: func(t testing.TB, p *runtime.Pinner) *WAFObject {
				return encodeForDecoderTest(t, p, map[string]any{field.name: 42})
			},
			want: fmt.Sprintf("decodeFeature: failed to decode field %q: %s", field.name, field.want),
		})
	}

	runDecoderErrorCases(t, decodeFeature, cases)
}

func BenchmarkDecodeDiagnostics(b *testing.B) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	input := map[string]any{"ruleset_version": "1.2.3"}
	for _, key := range diagnosticsFeatureKeys {
		input[key] = map[string]any{
			"loaded":   []any{key + "-1", key + "-2"},
			"failed":   []any{},
			"skipped":  []any{},
			"errors":   map[string]any{},
			"warnings": map[string]any{},
		}
	}
	obj := encodeForDecoderTest(b, &pinner, input)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := decodeDiagnostics(obj); err != nil {
			b.Fatal(err)
		}
	}
}
