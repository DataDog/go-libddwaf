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
	"os/exec"
	"runtime"
	"strconv"

	"github.com/DataDog/go-libddwaf/v4/internal/unsafe"
	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

const shmAddress = "libddwaf"

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

	// Create a shared memory file descriptor using shm_open so we can use it to run dlopen(/proc/self/fd/<fd>).
	fd, _, errno := purego.SyscallN(addr,
		unsafe.PtrToUintptr(unsafe.Cstring(&pinner, shmAddress)),
		uintptr(unix.O_CREAT|unix.O_RDWR),
		uintptr(unix.S_IRWXU|unix.S_IRWXG|unix.S_IRWXO), // rwx for user, group, and others
	)
	if fd < 0 {
		return "", nil, fmt.Errorf("error creating shared memory fd: %w", unix.Errno(errno))
	}

	shmUnlink := func() error {
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

	closer := shmUnlink

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

	// Grow the shared memory file descriptor to the size of the WAF library.
	if err := unix.Ftruncate(int(fd), int64(len(src))); err != nil {
		return "", nil, fmt.Errorf("error truncating shared memory fd: %w", err)
	}

	// Map the shared memory file descriptor to a memory region.
	dst, err := unix.Mmap(int(fd), 0, len(src), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return "", nil, fmt.Errorf("error mapping memory for shared memory fd: %w", err)
	}

	// Change the closer function to unmap the memory and unlink the shared memory instead of just unlinking it.
	closer = func() error {
		return errors.Join(unix.Munmap(dst), shmUnlink())
	}

	copy(dst, src)

	// Ensure that the data is written to the shared memory file descriptor synchronously.
	if err := unix.Msync(dst, unix.MS_SYNC); err != nil {
		return "", nil, fmt.Errorf("error syncing memory for shared memory fd: %w", err)
	}

	return "/dev/fd/" + strconv.Itoa(int(fd)), closer, nil
}
