// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChildTimersShareClockPointer(t *testing.T) {
	root, err := NewTreeTimer(WithBudget(1), WithComponents("a"))
	require.NoError(t, err)

	t.Run("leaf", func(t *testing.T) {
		leaf, err := root.NewLeaf("a")
		require.NoError(t, err)

		rootImpl := root.(*nodeTimer)
		leafImpl := leaf.(*baseTimer)

		require.Equal(t, reflect.Pointer, reflect.TypeOf(rootImpl.baseTimer.clock).Kind())
		require.Equal(t, reflect.Pointer, reflect.TypeOf(leafImpl.clock).Kind())
		require.Equal(t, reflect.ValueOf(rootImpl.baseTimer.clock).Pointer(), reflect.ValueOf(leafImpl.clock).Pointer())
	})

	t.Run("node", func(t *testing.T) {
		node, err := root.NewNode("a", WithComponents("b"))
		require.NoError(t, err)

		rootImpl := root.(*nodeTimer)
		nodeImpl := node.(*nodeTimer)

		require.Equal(t, reflect.Pointer, reflect.TypeOf(rootImpl.baseTimer.clock).Kind())
		require.Equal(t, reflect.Pointer, reflect.TypeOf(nodeImpl.baseTimer.clock).Kind())
		require.Equal(t, reflect.ValueOf(rootImpl.baseTimer.clock).Pointer(), reflect.ValueOf(nodeImpl.baseTimer.clock).Pointer())
	})
}
