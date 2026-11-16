// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux || darwin

package bindings

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/DataDog/go-libddwaf/v5/internal/unsafeutil"
)

// TestStringValueCopiesFromUnmappedMemory puts the string bytes in memory that
// Go does not manage, as libddwaf does. It unmaps that memory after the call.
// If the value was a view of that memory, the comparison would crash.
func TestStringValueCopiesFromUnmappedMemory(t *testing.T) {
	for _, length := range []int{15, 32, 33, 128} {
		for _, objType := range []WAFObjectType{WAFStringType, WAFLiteralStringType} {
			t.Run(fmt.Sprintf("%s-%d", objType, length), func(t *testing.T) {
				want := strings.Repeat("k", length)
				mem, err := unix.Mmap(-1, 0, unix.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
				require.NoError(t, err)
				copy(mem, want)

				var obj WAFObject
				obj.setType(objType)
				binary.NativeEndian.PutUint32(obj.data[wafObjectStringSizeOffset:], uint32(length))
				unsafeutil.WritePtr(&obj.data[wafObjectPtrOffset], unsafe.Pointer(&mem[0]))

				unmapped := false
				change := func() {
					require.NoError(t, unix.Munmap(mem))
					unmapped = true
				}
				require.True(t, valueSurvivesChange(&obj, change, want))
				require.True(t, unmapped)
			})
		}
	}
}
