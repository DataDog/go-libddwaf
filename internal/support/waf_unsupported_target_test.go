// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (!linux && !darwin) || (!amd64 && !arm64)

package support_test

import (
	"runtime"
	"testing"

	"github.com/DataDog/go-libddwaf/v4"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
	"github.com/stretchr/testify/require"
)

func TestUnsupportedPlatform(t *testing.T) {
	expectedErr := waferrors.UnsupportedOSArchError{OS: runtime.GOOS, Arch: runtime.GOARCH}

	t.Run("Load", func(t *testing.T) {
		ok, err := libddwaf.Load()
		require.False(t, ok)
		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("Usable", func(t *testing.T) {
		ok, err := libddwaf.Usable()
		require.False(t, ok)
		require.ErrorIs(t, err, expectedErr)
	})
}
