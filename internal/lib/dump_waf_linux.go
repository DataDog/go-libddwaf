// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && (amd64 || arm64) && !go1.24 && !datadog.no_waf && (cgo || appsec)

package lib

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"

	_ "embed"
)

//go:embed .version
var EmbeddedWAFVersion string

func DumpEmbeddedWAF() (file *os.File, closer func() error, err error) {

	fd, err := unix.MemfdCreate("libddwaf", 0)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating memfd: %w", err)
	}

	file = os.NewFile(uintptr(fd), fmt.Sprintf("/proc/self/fd/%d", fd))
	if file == nil {
		return nil, nil, errors.New("error creating file from fd")
	}

	defer func() {
		if file != nil && err != nil {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("error closing file: %w", closeErr))
			}
		}
	}()

	gr, err := gzip.NewReader(bytes.NewReader(libddwaf))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating gzip reader: %w", err)
	}

	if _, err := io.Copy(file, gr); err != nil {
		return nil, nil, fmt.Errorf("error copying gzip content to memfd: %w", err)
	}

	if err := gr.Close(); err != nil {
		return nil, nil, fmt.Errorf("error closing gzip reader: %w", err)
	}

	return file, file.Close, nil
}
