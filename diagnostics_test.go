// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.26 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeDiagnosticsExclusionData(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	encoder, err := newEncoder(newUnlimitedEncoderConfig(&pinner))
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
