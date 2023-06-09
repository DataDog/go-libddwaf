// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64)

package waf

import "sync"

// For now we have to do dlopen on a global level because MacOS WAF behaves stangely
// when we do a second dlopen on the same file
var wafLib *wafDl
var wafErr error
var openWafOnce sync.Once

func InitWaf() error {
	if wafLib == nil {
		openWafOnce.Do(func() {
			wafLib, wafErr = newWafDl()
		})
	}

	return wafErr
}

func CloseWaf() error {
	err := wafLib.Close()
	wafLib = nil
	wafErr = nil
	return err
}

func Health() error {
	return InitWaf()
}

func Version() string {
	return wafLib.wafGetVersion()
}
