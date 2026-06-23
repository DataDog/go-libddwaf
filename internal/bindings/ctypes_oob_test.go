// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStringValueRejectsOversizedSmallString verifies that StringValue returns
// an error instead of panicking when a small-string WAFObject claims a size
// larger than the 14-byte inline buffer.
//
// The size byte (data[1]) can be 0-255 for a raw/FFI-produced object, but
// StringValue slices data[2:2+size] out of the fixed [16]byte array without an
// upper-bound check, so any size > wafObjectSStrMaxLen (14) panics with
// "slice bounds out of range".
func TestStringValueRejectsOversizedSmallString(t *testing.T) {
	var w WAFObject
	w.setType(WAFSmallStringType)
	w.data[wafObjectSStrSize] = wafObjectSStrMaxLen + 1 // 15: exceeds the 14-byte inline buffer

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StringValue panicked on oversized small-string size byte instead of returning an error: %v", r)
		}
	}()

	_, err := w.StringValue()
	require.Error(t, err)
}
