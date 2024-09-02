// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build darwin && (amd64 || arm64) && !go1.24 && !datadog.no_waf && (cgo || appsec)

package lib

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"

	_ "embed"
)

//go:embed .version
var EmbeddedWAFVersion string

func DumpEmbeddedWAF() (file *os.File, closer func() error, err error) {
	file, err = os.CreateTemp("", embedNamePattern)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating temp file: %w", err)
	}

	defer func() {
		if err != nil {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("error closing file: %w", closeErr))
			}
			if rmErr := os.Remove(file.Name()); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("error removing file: %w", rmErr))
			}
		}
	}()

	gr, err := gzip.NewReader(bytes.NewReader(libddwaf))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating gzip reader: %w", err)
	}

	if _, err := io.Copy(file, gr); err != nil {
		return nil, nil, fmt.Errorf("error copying gzip content to file: %w", err)
	}

	if err := gr.Close(); err != nil {
		return nil, nil, fmt.Errorf("error closing gzip reader: %w", err)
	}

	return file, func() error {
		return errors.Join(file.Close(), os.Remove(file.Name()))
	}, nil
}
