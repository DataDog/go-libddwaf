// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && darwin && arm64

// Package vendor is required to help go tools support vendoring.
// DO NOT REMOVE
package vendor

import _ "embed"

//go:embed libddwaf.dylib
var Libddwaf []byte