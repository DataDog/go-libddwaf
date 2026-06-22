// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"math"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestEncoder(t *testing.T, pinner *runtime.Pinner, maxContainer, maxString uint16) Encoder {
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 2, 64)
	var parent WAFObject

	b := enc.Array(&parent, 2)
	require.NotNil(t, b.NextValue())
	require.NotNil(t, b.NextValue())
	require.Nil(t, b.NextValue())
}

func TestArrayBuilder_Skip_IncrementsOverflow(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 0)
	require.Equal(t, 0, b.skipped)
	b.Skip()
	require.Equal(t, 1, b.skipped)
}

func TestArrayBuilder_DropLast_RemovesEntry(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Array(&parent, 0)
	require.NotPanics(t, func() { b.DropLast() })
	require.Len(t, b.entries, 0)
}

func TestMapBuilder_NextValue_AppendsKV(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 3)
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
	enc := newTestEncoder(t, &pinner, 2, 64)
	var parent WAFObject

	b := enc.Map(&parent, 2)
	require.NotNil(t, b.NextValue("k1"))
	require.NotNil(t, b.NextValue("k2"))
	require.Nil(t, b.NextValue("k3"))
}

func TestMapBuilder_Skip_IncrementsOverflow(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 0)
	require.Equal(t, 0, b.skipped)
	b.Skip()
	require.Equal(t, 1, b.skipped)
	b.Skip()
	require.Equal(t, 2, b.skipped)
}

func TestMapBuilder_DropLast_RemovesEntry(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
	var parent WAFObject

	b := enc.Map(&parent, 0)
	require.NotPanics(t, func() { b.DropLast() })
	require.Len(t, b.entries, 0)
}

func TestMapBuilder_Close_CommitsToParent(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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
	enc := newTestEncoder(t, &pinner, 4, 64)
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

func TestArrayBuilder_OverUint16IsCappedNotEmptied(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}
	var parent WAFObject

	b := enc.Array(&parent, 0)
	for i := 0; i <= math.MaxUint16; i++ {
		slot := b.NextValue()
		require.NotNil(t, slot)
		slot.SetInt(int64(i))
	}
	b.Close()

	require.True(t, parent.IsArray())
	size, err := parent.ArraySize()
	require.NoError(t, err)
	require.Equal(t, uint16(math.MaxUint16), size, "oversized array must be capped at MaxUint16, not silently emptied")
	require.NotEmpty(t, enc.Truncations.ContainerTooLarge, "oversized array must record a ContainerTooLarge truncation")
}

func TestMapBuilder_OverUint16IsCappedNotEmptied(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}
	var parent WAFObject

	b := enc.Map(&parent, 0)
	for i := 0; i <= math.MaxUint16; i++ {
		slot := b.NextValue("k")
		require.NotNil(t, slot)
		slot.SetInt(int64(i))
	}
	b.Close()

	require.True(t, parent.IsMap())
	entries, err := parent.MapEntries()
	require.NoError(t, err)
	require.Len(t, entries, math.MaxUint16, "oversized map must be capped at MaxUint16, not silently emptied")
	require.NotEmpty(t, enc.Truncations.ContainerTooLarge, "oversized map must record a ContainerTooLarge truncation")
}
