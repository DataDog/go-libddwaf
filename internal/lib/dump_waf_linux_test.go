// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && (amd64 || arm64) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package lib

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDumpEmbeddedWAFSealed(t *testing.T) {
	path, closer, err := DumpEmbeddedWAF()
	if err != nil {
		t.Fatalf("DumpEmbeddedWAF: %v", err)
	}
	t.Cleanup(func() {
		if err := closer(); err != nil {
			t.Errorf("closer: %v", err)
		}
	})

	fd, err := strconv.Atoi(filepath.Base(path))
	if err != nil {
		t.Fatalf("unexpected path %q: %v", path, err)
	}

	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatalf("F_GET_SEALS: %v", err)
	}
	if seals&memfdSeals != memfdSeals {
		t.Fatalf("seals = %#x, want at least %#x", seals, memfdSeals)
	}

	fdFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("memfd is missing FD_CLOEXEC")
	}

	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Fatal("opening the library for writing unexpectedly succeeded")
	}
}
