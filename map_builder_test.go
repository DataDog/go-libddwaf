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

func newMapTestEncoder(t *testing.T, pinner *runtime.Pinner, maxContainer, maxString uint16) Encoder {
	t.Helper()
	return Encoder{
		Config: EncoderConfig{
			Pinner:           pinner,
			MaxContainerSize: maxContainer,
			MaxStringSize:    maxString,
		},
	}
}

func TestMapBuilder_NextValue_AppendsKV(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 2)
	slot := b.NextValue("key1")
	require.NotNil(t, slot)
	slot.SetInt(42)
	b.Close()

	require.True(t, parent.IsMap())
	size, err := parent.MapSize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
	entries, err := parent.MapEntries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	keyStr, err := entries[0].Key.StringValue()
	require.NoError(t, err)
	require.Equal(t, "key1", keyStr)
}

func TestMapBuilder_NextValue_TruncatesKey(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 3)
	var parent WAFObject

	b := enc.Map(&parent, 1)
	slot := b.NextValue("longkey")
	require.NotNil(t, slot)

	require.Len(t, enc.Truncations.StringTooLong, 1)
	require.Equal(t, 7, enc.Truncations.StringTooLong[0])
}

func TestMapBuilder_NextValue_AtCapacityReturnsNil(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 2, 64)
	var parent WAFObject

	b := enc.Map(&parent, 2)
	require.NotNil(t, b.NextValue("k1"))
	require.NotNil(t, b.NextValue("k2"))
	require.Nil(t, b.NextValue("k3"))
}

func TestMapBuilder_Skip_IncrementsOverflow(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent)
	require.Equal(t, 0, b.skipped)
	b.Skip()
	require.Equal(t, 1, b.skipped)
	b.Skip()
	require.Equal(t, 2, b.skipped)
}

func TestMapBuilder_DropLast_RemovesEntry(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 2)
	b.NextValue("k1").SetInt(1)
	b.NextValue("k2").SetInt(2)
	b.DropLast()
	b.Close()

	size, err := parent.MapSize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
}

func TestMapBuilder_DropLast_NoEntries_NoOp(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent)
	require.NotPanics(t, func() { b.DropLast() })
	require.Len(t, b.entries, 0)
}

func TestMapBuilder_Close_CommitsToParent(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	require.True(t, parent.IsInvalid(), "parent must be invalid before close")

	b := enc.Map(&parent, 1)
	b.NextValue("key").SetInt(99)
	b.Close()

	require.True(t, parent.IsMap())
	size, err := parent.MapSize()
	require.NoError(t, err)
	require.Equal(t, uint16(1), size)
}

func TestMapBuilder_Close_RecordsContainerTooLarge(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 1)
	b.NextValue("k1").SetInt(1)
	b.Skip()
	b.Close()

	require.Len(t, enc.Truncations.ContainerTooLarge, 1)
	require.Equal(t, 2, enc.Truncations.ContainerTooLarge[0])
}

func TestMapBuilder_Close_Idempotent(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 1)
	b.NextValue("k").SetInt(1)
	b.Skip()

	b.Close()
	b.Close()

	require.Len(t, enc.Truncations.ContainerTooLarge, 1, "truncation must be recorded exactly once")
	require.True(t, parent.IsMap())
}

func TestMapBuilder_KeyPreservedOnInvalidValue(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newMapTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 1)
	slot := b.NextValue("foo")
	require.NotNil(t, slot)
	b.Close()

	entries, err := parent.MapEntries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	keyStr, err := entries[0].Key.StringValue()
	require.NoError(t, err)
	require.Equal(t, "foo", keyStr)
	require.True(t, entries[0].Val.IsInvalid(), "unset value must remain invalid")
}

func TestMapBuilder_ZeroValueSlotIsInvalid(t *testing.T) {
	var obj WAFObject
	require.True(t, obj.IsInvalid(), "zero-value WAFObject must be invalid")
}
