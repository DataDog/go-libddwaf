// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Build when the target OS or Arch are not supported
//go:build !((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64)) || (windows && (amd64 || 386))) || go1.22

package waf_test

import (
	"errors"
	"testing"

	waf "github.com/DataDog/go-libddwaf"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	ok, err := waf.Load()
	require.False(t, ok)
	require.Error(t, err)
	var expectedErr *waf.UnsupportedTargetError
	require.Truef(t, errors.As(err, &expectedErr), "unexpected error of type %[1]T: %[1]v", err)
}

func TestSupportsTarget(t *testing.T) {
	supported, err := waf.SupportsTarget()
	require.False(t, supported)
	require.Error(t, err)
}
