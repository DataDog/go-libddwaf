// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && armv7 && !go1.22
package vendor

import _ "embed" // Needed for go:embed

//go:embed linux-armv7/libddwaf.so
var libddwaf []byte

const embedNamePattern = "libddwaf-*.so"
