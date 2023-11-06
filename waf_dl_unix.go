// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64))) && !go1.22

package waf

import "github.com/ebitengine/purego"

func loadSharedObject(file string) (uintptr, error) {
	return purego.Dlopen(file, purego.RTLD_GLOBAL|purego.RTLD_NOW)
}

func resolveSymbol(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}

func closeSharedObject(handle uintptr) error {
	return purego.Dlclose(handle)
}
