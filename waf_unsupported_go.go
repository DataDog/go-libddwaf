// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Supported OS/Arch but unsupported Go version
//               Supported OS              Supported Arch Bad Go Version Not manually disabled
//go:build (linux || darwin || windows) && (amd64 || arm64) && go1.22 && !datadog.no_waf

package waf

import (
	"fmt"
	"runtime"
)

var disabledWafErr = &WafDisabledError{fmt.Errorf("the Go version %s is not supported", runtime.Version())}
