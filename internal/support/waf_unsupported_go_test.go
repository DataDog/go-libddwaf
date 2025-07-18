// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build go1.26

package support_test

import (
	"testing"

	"github.com/DataDog/go-libddwaf/v4"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
	"github.com/stretchr/testify/require"
)

func TestUnsupportedGoRuntime(t *testing.T) {
	t.Run("Load", func(t *testing.T) {
		ok, err := libddwaf.Load()
		require.False(t, ok)
		require.ErrorIs(t, err, waferrors.UnsupportedGoVersionError{})
	})

	t.Run("Usable", func(t *testing.T) {
		ok, err := libddwaf.Usable()
		require.False(t, ok)
		require.ErrorIs(t, err, waferrors.UnsupportedGoVersionError{})
	})
}
