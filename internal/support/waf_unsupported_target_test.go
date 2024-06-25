// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (!linux && !darwin) || (!amd64 && !arm64)

package support_test

import (
	"testing"

	waf "github.com/DataDog/go-libddwaf/v3"
	"github.com/DataDog/go-libddwaf/v3/errors"
	"github.com/stretchr/testify/require"
)

func TestUnsupportedPlatform(t *testing.T) {

	t.Run("SupportsTarget", func(t *testing.T) {
		supported, err := waf.SupportsTarget()
		require.False(t, supported)
		require.Error(t, err)
		require.ErrorIs(t, err, errors.UnsupportedOSArchError{runtime.GOOS, runtime.GOARCH})
	})

	t.Run("Load", func(t *testing.T) {
		ok, err := waf.Load()
		require.False(t, ok)
		require.Error(t, err)
	})

	t.Run("Health", func(t *testing.T) {
		ok, err := waf.Health()
		require.False(t, ok)
		require.Error(t, err)
	})
}
