// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package vendor is required to help go tools support vendoring.
// DO NOT REMOVE

//go:build darwin && amd64

package shared

import _ "embed" // Needed for go:embed

//go:embed darwin-amd64
var Libddwaf []byte
