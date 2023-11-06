// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && amd64 && !go1.22
package vendor

import _ "embed" // Needed for go:embed

//go:embed windows-amd64/ddwaf.dll
var libddwaf []byte

const embedNamePattern = "ddwaf-*.dll"
