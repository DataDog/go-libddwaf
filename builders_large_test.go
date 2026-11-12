// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// unlimitedEncoder is the encoder of Builder.AddOrUpdateConfig: all 3 limits
// are math.MaxUint16, so the layout is the only cap.
func unlimitedEncoder(pinner *runtime.Pinner) Encoder {
	return Encoder{Config: newEncoderConfig(pinner, WithUnlimitedLimits())}
}

// TestArrayBuilder_OverUint16UsesLargeLayout replaces the test that expected
// the 65,535 cut. 65,536 items or more now give a large array with every item.
func TestArrayBuilder_OverUint16UsesLargeLayout(t *testing.T) {
	for _, n := range []int{math.MaxUint16 + 1, 70_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var pinner runtime.Pinner
			defer pinner.Unpin()
			enc := unlimitedEncoder(&pinner)
			var parent WAFObject

			b := enc.Array(&parent, 0)
			for i := range n {
				slot := b.NextValue()
				require.NotNil(t, slot)
				slot.SetInt(int64(i))
			}
			b.Close()

			require.Equal(t, WAFLargeArrayType, parent.Type(), "65,536 items must use the large layout with no truncation")
			require.True(t, enc.Truncations.IsEmpty(), "65,536 items must use the large layout with no truncation")
			values, err := parent.ArrayValues()
			require.NoError(t, err)
			require.Len(t, values, n)
			last, err := values[n-1].IntValue()
			require.NoError(t, err)
			require.EqualValues(t, n-1, last)
		})
	}
}

// TestMapBuilder_OverUint16UsesLargeLayout is the map version of
// TestArrayBuilder_OverUint16UsesLargeLayout.
func TestMapBuilder_OverUint16UsesLargeLayout(t *testing.T) {
	for _, n := range []int{math.MaxUint16 + 1, 70_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var pinner runtime.Pinner
			defer pinner.Unpin()
			enc := unlimitedEncoder(&pinner)
			var parent WAFObject

			b := enc.Map(&parent, 0)
			for i := range n {
				slot := b.NextValue("k")
				require.NotNil(t, slot)
				slot.SetInt(int64(i))
			}
			b.Close()

			require.Equal(t, WAFLargeMapType, parent.Type(), "65,536 items must use the large layout with no truncation")
			require.True(t, enc.Truncations.IsEmpty(), "65,536 items must use the large layout with no truncation")
			entries, err := parent.MapEntries()
			require.NoError(t, err)
			require.Len(t, entries, n)
			last, err := entries[n-1].Val.IntValue()
			require.NoError(t, err)
			require.EqualValues(t, n-1, last)
		})
	}
}

// TestBuilderLayout_65535StaysCompact checks the edge below the large layout.
func TestBuilderLayout_65535StaysCompact(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := unlimitedEncoder(&pinner)
	var arr, mp WAFObject

	ab := enc.Array(&arr, 0)
	mb := enc.Map(&mp, 0)
	for i := range math.MaxUint16 {
		ab.NextValue().SetInt(int64(i))
		mb.NextValue("k").SetInt(int64(i))
	}
	ab.Close()
	mb.Close()

	require.Equal(t, WAFArrayType, arr.Type())
	require.Equal(t, WAFMapType, mp.Type())
	require.True(t, enc.Truncations.IsEmpty())
	values, err := arr.ArrayValues()
	require.NoError(t, err)
	require.Len(t, values, math.MaxUint16)
	entries, err := mp.MapEntries()
	require.NoError(t, err)
	require.Len(t, entries, math.MaxUint16)
}

// TestBuilderLayout_DefaultLimitUnchanged checks that the run limit (256
// items) still cuts, and still records the original size.
func TestBuilderLayout_DefaultLimitUnchanged(t *testing.T) {
	const items = 300
	var pinner runtime.Pinner
	defer pinner.Unpin()
	enc := Encoder{Config: newEncoderConfig(&pinner)}
	var arr, mp WAFObject

	ab := enc.Array(&arr, 0)
	mb := enc.Map(&mp, 0)
	for i := range items {
		if slot := ab.NextValue(); slot != nil {
			slot.SetInt(int64(i))
		} else {
			ab.Skip()
		}
		if slot := mb.NextValue(fmt.Sprint("k", i)); slot != nil {
			slot.SetInt(int64(i))
		} else {
			mb.Skip()
		}
	}
	ab.Close()
	mb.Close()

	require.Equal(t, []int{items, items}, enc.Truncations.ContainerTooLarge)
	values, err := arr.ArrayValues()
	require.NoError(t, err)
	require.Len(t, values, 256)
	entries, err := mp.MapEntries()
	require.NoError(t, err)
	require.Len(t, entries, 256)
}
