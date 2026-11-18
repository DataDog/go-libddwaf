// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/unsafeutil"
)

// unmappableMemory returns at least size bytes of writable memory that Go does
// not manage, as libddwaf memory is, and a function that unmaps it. Each
// platform that runs the unmapped-memory test has its own implementation.
type unmappableMemory func(t *testing.T, size int) (mem []byte, unmap func())

// testStringValueCopiesFromUnmappedMemory puts the string bytes in memory that
// Go does not manage, and unmaps that memory after the call. If the value was a
// view of that memory, the comparison would crash. The platform files call it
// with their own allocator, so that all platforms run the same cases.
func testStringValueCopiesFromUnmappedMemory(t *testing.T, alloc unmappableMemory) {
	for _, length := range []int{15, 32, 33, 128} {
		for _, objType := range []WAFObjectType{WAFStringType, WAFLiteralStringType} {
			t.Run(fmt.Sprintf("%s-%d", objType, length), func(t *testing.T) {
				want := strings.Repeat("k", length)
				mem, unmap := alloc(t, length)
				require.GreaterOrEqual(t, len(mem), length)
				copy(mem, want)

				var obj WAFObject
				obj.setType(objType)
				binary.NativeEndian.PutUint32(obj.data[wafObjectStringSizeOffset:], uint32(length))
				unsafeutil.WritePtr(&obj.data[wafObjectPtrOffset], unsafe.Pointer(&mem[0]))

				unmapped := false
				change := func() {
					unmap()
					unmapped = true
				}
				require.True(t, valueSurvivesChange(&obj, change, want))
				require.True(t, unmapped)
			})
		}
	}
}
