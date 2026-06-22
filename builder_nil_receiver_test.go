// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// TestBuilderNilReceiverDoesNotPanic verifies that calling Builder methods on a
// nil *Builder returns the graceful error the `if b == nil` guards promise,
// rather than panicking.
//
// The bug is observable only under `ci` builds: acquire() runs before the nil
// guard and dereferences the receiver (b.inUse.CompareAndSwap) when
// invariant.Active() is true, so each method panics before reaching the
// graceful return. Run with `-tags ci` to see it red. In production builds
// acquire() short-circuits, so the same test passes.
func TestBuilderNilReceiverDoesNotPanic(t *testing.T) {
	tests := []struct {
		name string
		call func(t *testing.T, b *Builder)
	}{
		{"Build", func(t *testing.T, b *Builder) {
			h, err := b.Build()
			require.Nil(t, h)
			require.ErrorIs(t, err, waferrors.ErrBuilderInitFailed)
		}},
		{"AddOrUpdateConfig", func(t *testing.T, b *Builder) {
			_, err := b.AddOrUpdateConfig("some/path", map[string]any{})
			require.ErrorIs(t, err, errBuilderClosed)
		}},
		{"RemoveConfig", func(t *testing.T, b *Builder) {
			require.False(t, b.RemoveConfig("some/path"))
		}},
		{"ConfigPaths", func(t *testing.T, b *Builder) {
			_, err := b.ConfigPaths("")
			require.ErrorIs(t, err, errBuilderClosed)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("(*Builder)(nil).%s panicked instead of returning gracefully: %v", tc.name, r)
				}
			}()

			var b *Builder // nil receiver
			tc.call(t, b)
		})
	}
}
