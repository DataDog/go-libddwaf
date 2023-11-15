// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Unsupported target OS or architecture on a supported Go version
//            Unsupported OS        Unsupported Arch   Good Go Version Not manually disabled
//go:build ((!linux && !darwin) || (!amd64 && !arm64)) && !go1.22 && !datadog.no_waf

package waf

import (
	"fmt"
	"runtime"
)

var disabledWafErr = &WafDisabledError{fmt.Errorf("the target operating-system %s or architecture %s are not supported", runtime.GOOS, runtime.GOARCH)}
