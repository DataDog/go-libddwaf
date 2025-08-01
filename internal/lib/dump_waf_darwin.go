// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build darwin && (amd64 || arm64) && !go1.26 && !datadog.no_waf && (cgo || appsec)

package lib

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"

	"github.com/DataDog/go-libddwaf/v4/internal/unsafe"
	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

const shmAddress = "/libddwaf"

// DumpEmbeddedWAF for darwin systems.
// It creates a file descriptor in memory and writes the embedded WAF library to it. Then it returns the path the /proc/self/fd/<fd> path
// to the file. This trick makes us able to load the library without having to write it to disk.
// Hence, making go-libddwaf work on full read-only filesystems.
func DumpEmbeddedWAF() (_ string, _ func() error, err error) {
	addr, err := purego.Dlsym(purego.RTLD_DEFAULT, "shm_open")
	if err != nil {
		return "", nil, fmt.Errorf("error finding shm_open symbol: %w", err)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	fd, _, errno := purego.SyscallN(addr,
		unsafe.PtrToUintptr(unsafe.Cstring(&pinner, shmAddress)),
		uintptr(unix.O_CREAT|unix.O_EXCL|unix.O_RDWR),
		uintptr(0o600),
	)
	if fd < 0 {
		return "", nil, fmt.Errorf("error creating shared memory fd: %w", unix.Errno(errno))
	}

	closer := func() error {
		symbol, err := purego.Dlsym(purego.RTLD_DEFAULT, "shm_unlink")
		if err != nil {
			return fmt.Errorf("error finding shm_unlink symbol: %w", err)
		}

		var pinner runtime.Pinner
		defer pinner.Unpin()
		_, _, errno := purego.SyscallN(symbol, unsafe.PtrToUintptr(unsafe.Cstring(&pinner, shmAddress)))
		if errno != 0 {
			return fmt.Errorf("error unlinking shared memory fd: %w", unix.Errno(errno))
		}

		return nil
	}

	defer func() {
		if err != nil {
			if rmErr := closer(); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("error removing %s: %w", shmAddress, rmErr))
			}
		}
	}()

	gr, err := gzip.NewReader(bytes.NewReader(libddwaf))
	if err != nil {
		return "", nil, fmt.Errorf("error creating gzip reader: %w", err)
	}

	defer gr.Close()

	src, err := io.ReadAll(gr)
	if err != nil {
		return "", nil, fmt.Errorf("error reading gzip data: %w", err)
	}

	dst, err := unix.Mmap(int(fd), 0, len(src), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return "", nil, err
	}

	copy(dst, src)

	return "/proc/self/fd/" + strconv.Itoa(int(fd)), closer, nil
}
