// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package vendor is required to help go tools support vendoring.
// DO NOT REMOVE

//go:build linux && amd64

package shared

// Adds a dynamic import for libm.so because libddwaf needs the ceilf symbol
//go:cgo_import_dynamic purego_ceilf ceilf "libm.so.6"
//go:cgo_import_dynamic _ _ "libm.so.6"

import _ "embed" // Needed for go:embedw

//go:embed linux-amd64
var Libddwaf []byte

var purego_ceilf uint
