// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Supported OS/Arch but unsupported Go version
//           Supported OS        Supported Arch     Bad Go Version
//go:build ((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64)) || (windows && (amd64 || 386))) && go1.22

package waf

import (
	"fmt"
	"runtime"
)

var unsupportedTargetErr = &UnsupportedTargetError{fmt.Errorf("the Go version %s is not supported", runtime.Version())}
