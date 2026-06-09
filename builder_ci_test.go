// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ci

package libddwaf

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestArrayBuilder_NextValueAfterClose_PanicsUnderCI verifies that appending to
// an ArrayBuilder after Close is caught by the CI-only invariant assertion.
// Such entries would otherwise be silently dropped (Close is idempotent and
// never re-commits).
func TestArrayBuilder_NextValueAfterClose_PanicsUnderCI(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 1)
	b.Close()

	defer func() {
		require.NotNil(t, recover(), "expected panic on NextValue after Close")
	}()
	b.NextValue()
}

// TestMapBuilder_NextValueAfterClose_PanicsUnderCI verifies the same guard for
// the MapBuilder.
func TestMapBuilder_NextValueAfterClose_PanicsUnderCI(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 1)
	b.Close()

	defer func() {
		require.NotNil(t, recover(), "expected panic on NextValue after Close")
	}()
	b.NextValue("k")
}
