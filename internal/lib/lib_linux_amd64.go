// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && amd64 && !go1.22 && !datadog.no_waf

package lib

import bin "github.com/DataDog/go-libddwaf/v2/internal/lib/linux-amd64"

var libddwaf = bin.Libddwaf

const embedNamePattern = "libddwaf-*.so"
