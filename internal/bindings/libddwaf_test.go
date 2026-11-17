// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package bindings

import (
	"errors"
	"reflect"
	"runtime"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/require"
)

// TestWafSymbolsTable checks the name, the order and the target field of each
// row of [wafSymbols.table]. The order decides which symbol an error names when
// more than 1 symbol is missing.
func TestWafSymbolsTable(t *testing.T) {
	var syms wafSymbols

	want := []wafSymbol{
		{"ddwaf_builder_add_or_update_config", &syms.builderAddOrUpdateConfig},
		{"ddwaf_builder_build_instance", &syms.builderBuildInstance},
		{"ddwaf_builder_destroy", &syms.builderDestroy},
		{"ddwaf_builder_get_config_paths", &syms.builderGetConfigPaths},
		{"ddwaf_builder_init", &syms.builderInit},
		{"ddwaf_builder_remove_config", &syms.builderRemoveConfig},
		{"ddwaf_context_destroy", &syms.contextDestroy},
		{"ddwaf_context_init", &syms.contextInit},
		{"ddwaf_context_eval", &syms.contextEval},
		{"ddwaf_subcontext_init", &syms.subcontextInit},
		{"ddwaf_subcontext_eval", &syms.subcontextEval},
		{"ddwaf_subcontext_destroy", &syms.subcontextDestroy},
		{"ddwaf_destroy", &syms.destroy},
		{"ddwaf_get_version", &syms.getVersion},
		{"ddwaf_known_actions", &syms.knownActions},
		{"ddwaf_known_addresses", &syms.knownAddresses},
		{"ddwaf_object_destroy", &syms.objectDestroy},
		{"ddwaf_object_from_json", &syms.objectFromJSON},
		{"ddwaf_get_default_allocator", &syms.getDefaultAllocator},
		{"ddwaf_set_log_cb", &syms.setLogCb},
	}

	// Each field of wafSymbols has exactly 1 row.
	require.Len(t, want, reflect.TypeFor[wafSymbols]().NumField())

	got := syms.table()
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].name, got[i].name, "name of entry %d", i)
		// Compare the addresses: [require.Equal] would compare the values
		// that the pointers point to, and all the fields are 0.
		require.Same(t, want[i].addr, got[i].addr, "field of entry %d (%s)", i, want[i].name)
	}
}

// TestNewWafSymbolsMissingSymbol loads a library that has none of the libddwaf
// symbols, and checks the error of [newWafSymbols].
func TestNewWafSymbolsMissingSymbol(t *testing.T) {
	lib := "libc.so.6"
	if runtime.GOOS == "darwin" {
		lib = "/usr/lib/libSystem.B.dylib"
	}

	handle, err := purego.Dlopen(lib, purego.RTLD_NOW|purego.RTLD_LOCAL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = purego.Dlclose(handle) })

	syms, err := newWafSymbols(handle)
	require.Error(t, err)

	// The error wraps the error of purego.Dlsym (%w).
	cause := errors.Unwrap(err)
	require.IsType(t, purego.Dlerror{}, cause)

	// The error names the first symbol of the table. A loop that does not stop
	// at the first error would name the last one.
	require.Equal(t,
		"failed to resolve libddwaf symbol \"ddwaf_builder_add_or_update_config\": "+cause.Error(),
		err.Error())

	// No symbol is returned on error.
	require.Zero(t, syms)
}
