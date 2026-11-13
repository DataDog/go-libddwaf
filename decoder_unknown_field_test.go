// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

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
// If decodeFeature returned an error on an unknown field, that error would
// propagate through decodeDiagnostics and Builder.AddOrUpdateConfig, and a
// newer libddwaf that adds a per-feature diagnostic field would make a valid
// ruleset fail to load.
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
