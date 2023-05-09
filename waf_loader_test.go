// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWafOpen(t *testing.T) {

	loader, err := newWafLoader()
	require.NoError(t, err)
	defer loader.dlClose()

}

func TestWafGetVersion(t *testing.T) {

	loader, err := newWafLoader()
	require.NoError(t, err)
	defer loader.dlClose()

	require.Regexp(t, `[0-9]+\.[0-9]+\.[0-9]+`, loader.wafGetVersion())

}
