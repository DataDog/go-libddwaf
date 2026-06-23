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

func TestDiagnosticsTopLevelError(t *testing.T) {
	t.Run("nil-when-no-errors", func(t *testing.T) {
		require.NoError(t, (&Diagnostics{}).TopLevelError())

		d := Diagnostics{
			Rules:       &Feature{Loaded: []string{"rule-1"}},
			CustomRules: &Feature{},
		}
		require.NoError(t, d.TopLevelError())
	})

	t.Run("rolls-up-feature-errors", func(t *testing.T) {
		d := Diagnostics{
			Rules:       &Feature{Error: "rules parse failed"},
			Processors:  &Feature{Error: "processors invalid"},
			CustomRules: &Feature{Loaded: []string{"ok"}},
		}
		err := d.TopLevelError()
		require.Error(t, err)
		require.ErrorContains(t, err, "rules")
		require.ErrorContains(t, err, "rules parse failed")
		require.ErrorContains(t, err, "processors")
		require.ErrorContains(t, err, "processors invalid")
	})
}

func TestDecodeDiagnosticsExclusionData(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	encoder, err := newEncoder(newEncoderConfig(&pinner, WithUnlimitedLimits()))
	require.NoError(t, err)

	obj, err := encoder.Encode(map[string]any{
		"exclusion_data": map[string]any{
			"loaded": []any{"id1"},
		},
	})
	require.NoError(t, err)

	diags, err := decodeDiagnostics(obj)
	require.NoError(t, err)
	require.NotNil(t, diags.ExclusionData)
	require.Contains(t, diags.ExclusionData.Loaded, "id1")
}

func TestDecodeProcessorOverrides(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	encoder, err := newEncoder(newEncoderConfig(&pinner, WithUnlimitedLimits()))
	require.NoError(t, err)

	obj, err := encoder.Encode(map[string]any{
		"processor_overrides": map[string]any{
			"loaded": []any{"id1"},
		},
	})
	require.NoError(t, err)

	diags, err := decodeDiagnostics(obj)
	require.NoError(t, err)
	require.NotNil(t, diags.ProcessorOverrides)
	require.Contains(t, diags.ProcessorOverrides.Loaded, "id1")
}
