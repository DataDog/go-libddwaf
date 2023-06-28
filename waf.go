// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64)

package waf

import "sync"

// Globally dlopen() libddwaf only once because several dlopens (eg. during tests) aren't
// supported on macOS.
var (
	// libddwaf's dynamic library handle and entrypoints
	wafLib *wafDl
	// libddwaf's dlopen error if any
	wafErr      error
	openWafOnce sync.Once
)
var wafVersion string

func InitWaf() error {
	openWafOnce.Do(func() {
		wafLib, wafErr = newWafDl()
		if wafErr != nil {
			return
		}

		wafVersion = wafLib.wafGetVersion()
	})

	return wafErr
}

func Health() error {
	return InitWaf()
}

func Version() string {
	return wafVersion
}
