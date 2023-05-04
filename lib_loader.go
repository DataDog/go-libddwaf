// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64) && !cgo

package waf

import (
	"fmt"

	"github.com/ebitengine/purego"
)

type libLoader struct {
	symbols map[string]uintptr
	handle  uintptr
}

func dlOpen(name string, symbolsNeeded []string) (*libLoader, error) {
	handle, err := purego.Dlopen(name, purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return nil, fmt.Errorf("Error opening shared library '%s'. Reason: %w", name, err)
	}

	loader := &libLoader{
		handle:  handle,
		symbols: make(map[string]uintptr, len(symbolsNeeded)),
	}

	for _, symbolName := range symbolsNeeded {
		loader.symbols[symbolName], err = purego.Dlsym(handle, symbolName)
		if err != nil {
			return nil, fmt.Errorf("Cannot load symbol '%s' from library '%s'. Reason: %w", symbolName, name, err)
		}
	}

	return loader, nil
}

func (loader *libLoader) GetSymbol(name string) uintptr {
	return loader.symbols[name]
}

func (loader *libLoader) dlClose() {
	purego.Dlclose(loader.handle)
}
