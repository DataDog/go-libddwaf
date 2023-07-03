// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Build when the target OS or Arch are not supported
//go:build (!linux && !darwin) || (!amd64 && !arm64)

package waf_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	ok, err := Load()
	require.True(t, ok)
	require.Error(t, err)
}

func TestHealth(t *testing.T) {
	require.Error(t, Health)
}
