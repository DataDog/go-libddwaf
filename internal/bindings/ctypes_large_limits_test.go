// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLargeLayoutCapacity checks the 28-bit limit of the size check with
// numbers only: no large slice is allocated, and none is faked with
// unsafe.Slice (checkptr rejects that under -race).
func TestLargeLayoutCapacity(t *testing.T) {
	require.Equal(t, 268_435_455, MaxLargeContainerSize)

	for _, tc := range []struct {
		name         string
		length       int
		capacity     int
		wantCapacity int
		wantErr      bool
	}{
		{"compact", 10, 10, 10, false},
		{"spare capacity", 10, 70_000, 70_000, false},
		{"max length", MaxLargeContainerSize, MaxLargeContainerSize, MaxLargeContainerSize, false},
		{"max length, larger capacity", MaxLargeContainerSize, MaxLargeContainerSize + 5, MaxLargeContainerSize, false},
		{"small length, huge capacity", 10, MaxLargeContainerSize + 5, MaxLargeContainerSize, false},
		{"one over", MaxLargeContainerSize + 1, MaxLargeContainerSize + 1, 0, true},
		{"five over", MaxLargeContainerSize + 5, MaxLargeContainerSize + 5, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capacity, err := largeLayoutCapacity(tc.length, tc.capacity)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantCapacity, capacity)
			require.GreaterOrEqual(t, capacity, tc.length)
		})
	}
}
