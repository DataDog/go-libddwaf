// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package bindings

import (
	"fmt"

	"github.com/ebitengine/purego"
)

type wafSymbols struct {
	builderInit              uintptr
	builderAddOrUpdateConfig uintptr
	builderRemoveConfig      uintptr
	builderBuildInstance     uintptr
	builderGetConfigPaths    uintptr
	builderDestroy           uintptr
	destroy                  uintptr
	knownAddresses           uintptr
	knownActions             uintptr
	getVersion               uintptr
	contextInit              uintptr
	contextEval              uintptr
	contextDestroy           uintptr
	subcontextInit           uintptr
	subcontextEval           uintptr
	subcontextDestroy        uintptr
	objectDestroy            uintptr
	objectFromJSON           uintptr
	getDefaultAllocator      uintptr
	setLogCb                 uintptr
}

// wafSymbol links a libddwaf symbol name to the [wafSymbols] field that stores
// its address.
type wafSymbol struct {
	name string
	addr *uintptr
}

// table returns the symbols of syms, in the order in which they are resolved.
func (syms *wafSymbols) table() []wafSymbol {
	return []wafSymbol{
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
}

// newWafSymbols resolves the symbols of [wafSymbols] from the provided
// [purego.Dlopen] handle. It stops at the first symbol that it cannot resolve.
func newWafSymbols(handle uintptr) (syms wafSymbols, err error) {
	for _, sym := range syms.table() {
		if *sym.addr, err = purego.Dlsym(handle, sym.name); err != nil {
			return syms, fmt.Errorf("failed to resolve libddwaf symbol %q: %w", sym.name, err)
		}
	}
	return syms, nil
}
