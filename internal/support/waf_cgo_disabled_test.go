// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && !appsec

package support_test

import (
	"testing"

	waf "github.com/DataDog/go-libddwaf/v2"
	"github.com/DataDog/go-libddwaf/v2/errors"
	"github.com/stretchr/testify/require"
)

func TestCgoDisabled(t *testing.T) {
	t.Run("TestSupportsTarget", func(t *testing.T) {
		supported, err := waf.SupportsTarget()
		require.False(t, supported)
		require.Error(t, err)
		require.ErrorIs(t, err, errors.CgoDisabledError{})
	})

	t.Run("TestLoad", func(t *testing.T) {
		ok, err := waf.Load()
		require.False(t, ok)
		require.Error(t, err)
	})

	t.Run("TestHealth", func(t *testing.T) {
		ok, err := waf.Health()
		require.False(t, ok)
		require.Error(t, err)
	})
}
