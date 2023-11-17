// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build datadog.no_waf

package waf_test

import (
	"testing"

	waf "github.com/DataDog/go-libddwaf/v2"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	ok, err := waf.Load()
	require.False(t, ok)
	require.Error(t, err)
}

func TestHealth(t *testing.T) {
	ok, err := waf.Health()
	require.False(t, ok)
	require.Error(t, err)
	require.ErrorIs(t, err, waf.ManuallyDisabledError{})
}
