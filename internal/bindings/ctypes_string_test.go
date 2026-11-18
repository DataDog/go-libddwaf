// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// TestStringValueErrors pins the error text of each StringValue error path.
func TestStringValueErrors(t *testing.T) {
	nilPointer := func() *WAFObject {
		var obj WAFObject
		obj.setType(WAFStringType)
		binary.NativeEndian.PutUint32(obj.data[wafObjectStringSizeOffset:], 3)
		return &obj
	}
	oversized := func() *WAFObject {
		var obj WAFObject
		obj.setType(WAFSmallStringType)
		obj.data[wafObjectSStrSize] = wafObjectSStrMaxLen + 1
		return &obj
	}
	notString := func() *WAFObject {
		var obj WAFObject
		obj.SetInt(42)
		return &obj
	}

	cases := []struct {
		name    string
		obj     *WAFObject
		want    string
		wrapped bool
	}{
		{"nil-pointer", nilPointer(), "nil pointer in string object with size 3", false},
		{"oversized-small-string", oversized(), waferrors.ErrInvalidObjectType.Error() + ": small string size 15 exceeds max 14", true},
		{"not-a-string", notString(), waferrors.ErrInvalidObjectType.Error() + ": value is not a string but int", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := tc.obj.StringValue()
			require.Empty(t, val)
			require.EqualError(t, err, tc.want)
			require.Equal(t, tc.wrapped, errors.Is(err, waferrors.ErrInvalidObjectType))
		})
	}
}

// TestStringValueReturnsCopy checks that the result of StringValue does not
// change when the source bytes change. If StringValue returned a view of the
// source bytes, this test would fail.
func TestStringValueReturnsCopy(t *testing.T) {
	t.Run("small-string", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, "actions")
		val, err := obj.StringValue()
		require.NoError(t, err)

		obj.SetString(&pinner, "XXXXXXX")
		require.Equal(t, "actions", val)
	})

	for _, set := range []struct {
		name string
		set  func(*WAFObject, *runtime.Pinner, string)
	}{
		{"string", (*WAFObject).SetString},
		{"literal-string", (*WAFObject).SetLiteralString},
	} {
		t.Run(set.name, func(t *testing.T) {
			var pinner runtime.Pinner
			defer pinner.Unpin()

			const want = "processor_overrides-and-more"
			buf := []byte(want)
			var obj WAFObject
			// SetString and SetLiteralString keep a pointer to buf, with no copy.
			set.set(&obj, &pinner, unsafe.String(&buf[0], len(buf)))
			val, err := obj.StringValue()
			require.NoError(t, err)

			clear(buf)
			require.Equal(t, want, val)
		})
	}
}

// TestStringValueDoesNotAllocate checks that StringValue does not allocate
// when the caller only compares the result. This needs the compiler to inline
// StringValue. If a change makes StringValue too large to inline, this test
// fails.
//
// This test covers the default build only. Other builds can inline differently:
// for example, a build with -pgo, or with -gcflags=-l. The test does not cover
// them.
func TestStringValueDoesNotAllocate(t *testing.T) {
	skipAllocCheckOnDevelGo(t)
	for _, key := range []string{"k", "actions", "12345678901234", "123456789012345", strings.Repeat("x", 32)} {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var obj WAFObject
		obj.SetString(&pinner, key)
		// Do not pass val to a function such as t.Fatalf: that makes it
		// escape, and then the copy is on the heap.
		mismatches := 0
		allocs := testing.AllocsPerRun(100, func() {
			if val, err := obj.StringValue(); err != nil || val != key {
				mismatches++
			}
		})
		require.Zero(t, mismatches, "key of length %d", len(key))
		require.Zero(t, allocs, "key of length %d", len(key))
	}
}

// valueSurvivesChange calls StringValue, then change, then compares the value
// with want. The value does not escape, so the compiler can put its copy on
// the stack. This checks the copy that callers such as unwrapWafResult get.
//
//go:noinline
func valueSurvivesChange(obj *WAFObject, change func(), want string) bool {
	val, err := obj.StringValue()
	change()
	return err == nil && val == want
}

// TestStringValueLocalCopy checks that a value that does not escape is a copy,
// for each string layout and for the lengths around the 14-byte small-string
// limit and the 32-byte stack buffer of the Go runtime.
func TestStringValueLocalCopy(t *testing.T) {
	for _, length := range []int{0, 1, 7, 14, 15, 32, 33, 128} {
		want := strings.Repeat("k", length)
		for _, set := range []struct {
			name string
			set  func(*WAFObject, *runtime.Pinner, string)
		}{
			{"string", (*WAFObject).SetString},
			{"literal-string", (*WAFObject).SetLiteralString},
		} {
			t.Run(fmt.Sprintf("%s-%d", set.name, length), func(t *testing.T) {
				var pinner runtime.Pinner
				defer pinner.Unpin()

				buf := []byte(want)
				var obj WAFObject
				if length == 0 {
					set.set(&obj, &pinner, "")
				} else {
					// The object keeps a pointer to buf (long strings), or a
					// copy of it in its own bytes (small strings).
					set.set(&obj, &pinner, unsafe.String(&buf[0], len(buf)))
				}
				change := func() {
					clear(buf)
					obj.SetInt(0)
				}
				require.True(t, valueSurvivesChange(&obj, change, want))
			})
		}
	}
}

// skipAllocCheckOnDevelGo skips an allocation check on a Go development
// version. The check depends on the inliner, and CI also tests Go "tip".
func skipAllocCheckOnDevelGo(t *testing.T) {
	t.Helper()
	if strings.HasPrefix(runtime.Version(), "devel") {
		t.Skip("the allocation check needs a released Go version")
	}
}
