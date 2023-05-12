// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !cgo && !windows && (amd64 || arm64) && (linux || darwin)

package waf

import (
	"testing"

	"github.com/ebitengine/purego"
)

// BenchmarkBindingsNoCGO is a simple nominal benchmark to test the cost of using purego for libddwaf bindings
// The goal is to compare it with the exact same benchmark when using CGO, and purego WITH CGO
func BenchmarkBindingsNoCGO(b *testing.B) {
	lib := getLibddwaf()
	get_version_sym := getSymbol(lib, "ddwaf_get_version")

	b.Run("purego-without-CGO", func(b *testing.B) {
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			purego.SyscallN(get_version_sym)
		}
	})
}
