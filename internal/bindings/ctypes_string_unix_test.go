// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux || darwin

package bindings

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestStringValueCopiesFromUnmappedMemory runs the unmapped-memory cases with
// memory from mmap, and unmaps it with munmap.
func TestStringValueCopiesFromUnmappedMemory(t *testing.T) {
	testStringValueCopiesFromUnmappedMemory(t, func(t *testing.T, size int) ([]byte, func()) {
		mem, err := unix.Mmap(-1, 0, max(size, unix.Getpagesize()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
		require.NoError(t, err)
		return mem, func() { require.NoError(t, unix.Munmap(mem)) }
	})
}
