// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build datadog.no_waf

package support_test

import (
	"testing"

	waf "github.com/DataDog/go-libddwaf/v4"
	"github.com/DataDog/go-libddwaf/v4/errors"

	"github.com/stretchr/testify/require"
)

func TestManuallyDisabled(t *testing.T) {
	t.Run("Load", func(t *testing.T) {
		ok, err := waf.Load()
		require.False(t, ok)
		require.ErrorIs(t, err, errors.ManuallyDisabledError{})
	})

	t.Run("Usable", func(t *testing.T) {
		ok, err := waf.Usable()
		require.False(t, ok)
		require.ErrorIs(t, err, errors.ManuallyDisabledError{})
	})
}
