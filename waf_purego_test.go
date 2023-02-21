// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && !windows && (amd64 || arm64) && (linux || darwin)

package waf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHealth(t *testing.T) {
	require.NoError(t, Health())
}

func TestVersion(t *testing.T) {
	require.Regexp(t, `[0-9]+\.[0-9]+\.[0-9]+`, Version())
}