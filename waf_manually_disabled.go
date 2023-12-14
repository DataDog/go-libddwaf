// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Manually set datadog.no_waf build tag
//go:build datadog.no_waf && (linux || darwin) && (amd64 || arm64) && !go1.22

package waf

func init() {
	wafManuallyDisabledErr = ManuallyDisabledError{}
}