// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func newArrayTestEncoder(t *testing.T, pinner *runtime.Pinner, maxContainer, maxString uint16) Encoder {
	t.Helper()
	return Encoder{
		Config: EncoderConfig{
			Pinner:           pinner,
			MaxContainerSize: maxContainer,
			MaxStringSize:    maxString,
		},
	}
}

func TestArrayBuilder_NextValue_AppendsSlot(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 1)
	slot := b.NextValue()
	require.NotNil(t, slot)
	slot.SetInt(7)
	b.Close()

	require.True(t, parent.IsArray())
	size, err := parent.ArraySize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
}

func TestArrayBuilder_NextValue_AtCapacityReturnsNil(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 2, 64)
	var parent WAFObject

	b := enc.Array(&parent, 2)
	require.NotNil(t, b.NextValue())
	require.NotNil(t, b.NextValue())
	require.Nil(t, b.NextValue())
}

func TestArrayBuilder_Skip_IncrementsOverflow(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent)
	require.Equal(t, 0, b.skipped)
	b.Skip()
	require.Equal(t, 1, b.skipped)
}

func TestArrayBuilder_DropLast_RemovesEntry(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 2)
	b.NextValue().SetInt(1)
	b.NextValue().SetInt(2)
	b.DropLast()
	b.Close()

	size, err := parent.ArraySize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
}

func TestArrayBuilder_Close_PreservesAllEntries(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 3)
	b.NextValue().SetInt(10)
	b.NextValue().SetInt(20)
	b.NextValue().SetInt(30)
	b.Close()

	vals, err := parent.ArrayValues()
	require.NoError(t, err)
	require.Len(t, vals, 3)
	v0, err := vals[0].IntValue()
	require.NoError(t, err)
	require.Equal(t, int64(10), v0)
	v2, err := vals[2].IntValue()
	require.NoError(t, err)
	require.Equal(t, int64(30), v2)
}

func TestArrayBuilder_Close_CommitsToParent(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	require.True(t, parent.IsInvalid(), "parent must be invalid before close")

	b := enc.Array(&parent, 1)
	b.NextValue().SetInt(5)
	b.Close()

	require.True(t, parent.IsArray())
	size, err := parent.ArraySize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
}

func TestArrayBuilder_Close_RecordsContainerTooLarge(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 1)
	b.NextValue().SetInt(1)
	b.Skip()
	b.Close()

	require.Len(t, enc.Truncations.ContainerTooLarge, 1)
	require.Equal(t, 2, enc.Truncations.ContainerTooLarge[0])
}

func TestArrayBuilder_Close_Idempotent(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 1)
	b.NextValue().SetInt(1)
	b.Skip()

	b.Close()
	b.Close()

	require.Len(t, enc.Truncations.ContainerTooLarge, 1, "truncation must be recorded exactly once")
	require.True(t, parent.IsArray())
}

func TestArrayBuilder_DropOnError_Pattern(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 2)

	b.NextValue().SetInt(1)

	b.NextValue()
	b.DropLast()

	b.Close()

	size, err := parent.ArraySize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
}

func TestArrayBuilder_DropLast_NoEntries_NoOp(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newArrayTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent)
	require.NotPanics(t, func() { b.DropLast() })
	require.Len(t, b.entries, 0)
}
