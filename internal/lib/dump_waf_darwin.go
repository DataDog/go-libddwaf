// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build darwin && (amd64 || arm64) && !go1.26 && !datadog.no_waf && (cgo || appsec)

package lib

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const libddwafDylibName = "libddwaf.dylib"

// DumpEmbeddedWAF for darwin platform.
// DumpEmbeddedWAF creates a temporary file with the embedded WAF library content and returns the path to the file,
// a closer function and an error. This is the only way to make all implementations of DumpEmbeddedWAF consistent
// across all platforms.
func DumpEmbeddedWAF() (_ string, closer func() error, err error) {
	path := filepath.Join(os.TempDir(), libddwafDylibName)
	var fp *os.File
	const nbAttempts = 20

	defer func() {
		if err != nil && closer != nil {
			err = errors.Join(err, closer())
		}
	}()

	for i := 0; i < nbAttempts; i++ {
		if fp, err = os.Open(path); os.IsNotExist(err) {
			// The file does not exist, try to create it.
			if fp, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600); os.IsExist(err) {
				// It was created by another process, try to open it again.
				continue
			}

			if err != nil {
				return "", nil, fmt.Errorf("error creating file %s: %w", path, err)
			}

			closer = fp.Close

			// We were the one to create the file, so we can lock it.
			if err = lock(fp); err != nil {
				return "", nil, fmt.Errorf("error locking file %s: %w", path, err)
			}

			closer = func() error {
				return errors.Join(unlock(fp), fp.Close())
			}

			gr, err := gzip.NewReader(bytes.NewReader(libddwaf))
			if err != nil {
				return "", nil, fmt.Errorf("error creating gzip reader: %w", err)
			}

			if _, err := io.Copy(fp, gr); err != nil {
				return "", nil, fmt.Errorf("error copying gzip content to file: %w", err)
			}

			if err := gr.Close(); err != nil {
				return "", nil, fmt.Errorf("error closing gzip reader: %w", err)
			}

			return fp.Name(), closer, nil
		}

		if err != nil {
			return "", nil, fmt.Errorf("error opening file %s: %w", path, err)
		}

		closer = fp.Close

		// The file exists, try to rlock it.
		if err = rlock(fp); err != nil {
			return "", nil, fmt.Errorf("error rlocking file %s: %w", path, err)
		}

		closer = func() error {
			return errors.Join(unlock(fp), fp.Close())
		}

		return fp.Name(), closer, nil
	}

	return "", nil, fmt.Errorf("failed to create or open file %s after %d attempts, last error: %w", path, nbAttempts, err)
}

// rlock places an advisory shared lock on the specified file.
func rlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
}

// lock places an advisory exclusive lock on the specified file.
func lock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlock removes any advisory locks from the specified file.
func unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
