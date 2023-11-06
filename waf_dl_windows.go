// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && (amd64 || 386) && !go1.22

package waf

import "golang.org/x/sys/windows"

func loadSharedObject(file string) (uintptr, error) {
	handle, err := windows.LoadLibrary(file)
	return uintptr(handle), err
}

func resolveSymbol(handle uintptr, name string) (uintptr, error) {
	return windows.GetProcAddress(windows.Handle(handle), name)
}

func closeSharedObject(handle uintptr) error {
	return windows.FreeLibrary(windows.Handle(handle))
}
