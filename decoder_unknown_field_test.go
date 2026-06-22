// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.28 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDecodeFeatureIgnoresUnknownField verifies that an unknown field inside a
// per-feature diagnostics map is ignored for forward compatibility, the same
// way decodeDiagnostics ignores unknown top-level keys.
//
// Currently decodeFeature returns an error on any unknown field, and that error
// propagates through decodeDiagnostics and Builder.AddOrUpdateConfig. As a
// result, a future libddwaf that adds a new per-feature diagnostic field would
// make an otherwise-valid ruleset fail to load.
func TestDecodeFeatureIgnoresUnknownField(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	encoder, err := newEncoder(newEncoderConfig(&pinner, WithUnlimitedLimits()))
	require.NoError(t, err)

	obj, err := encoder.Encode(map[string]any{
		"rules": map[string]any{
			"loaded":                      []any{"rule-1"},
			"future_field_from_newer_waf": "some-value",
		},
	})
	require.NoError(t, err)

	diags, err := decodeDiagnostics(obj)
	require.NoError(t, err)
	require.NotNil(t, diags.Rules)
	require.Contains(t, diags.Rules.Loaded, "rule-1")
}
