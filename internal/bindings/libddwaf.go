// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package bindings

import "github.com/ebitengine/purego"

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
	contextEval              uintptr // v2: renamed from ddwaf_run
	contextDestroy           uintptr
	subcontextInit           uintptr // v2: new
	subcontextEval           uintptr // v2: new
	subcontextDestroy        uintptr // v2: new
	objectDestroy            uintptr // v2: renamed from ddwaf_object_free
	objectFromJSON           uintptr
	getDefaultAllocator      uintptr
	setLogCb                 uintptr
}

// newWafSymbols resolves the symbols of [wafSymbols] from the provided
// [purego.Dlopen] handle.
func newWafSymbols(handle uintptr) (syms wafSymbols, err error) {
	if syms.builderAddOrUpdateConfig, err = purego.Dlsym(handle, "ddwaf_builder_add_or_update_config"); err != nil {
		return syms, err
	}
	if syms.builderBuildInstance, err = purego.Dlsym(handle, "ddwaf_builder_build_instance"); err != nil {
		return syms, err
	}
	if syms.builderDestroy, err = purego.Dlsym(handle, "ddwaf_builder_destroy"); err != nil {
		return syms, err
	}
	if syms.builderGetConfigPaths, err = purego.Dlsym(handle, "ddwaf_builder_get_config_paths"); err != nil {
		return syms, err
	}
	if syms.builderInit, err = purego.Dlsym(handle, "ddwaf_builder_init"); err != nil {
		return syms, err
	}
	if syms.builderRemoveConfig, err = purego.Dlsym(handle, "ddwaf_builder_remove_config"); err != nil {
		return syms, err
	}
	if syms.contextDestroy, err = purego.Dlsym(handle, "ddwaf_context_destroy"); err != nil {
		return syms, err
	}
	if syms.contextInit, err = purego.Dlsym(handle, "ddwaf_context_init"); err != nil {
		return syms, err
	}
	if syms.contextEval, err = purego.Dlsym(handle, "ddwaf_context_eval"); err != nil {
		return syms, err
	}
	if syms.subcontextInit, err = purego.Dlsym(handle, "ddwaf_subcontext_init"); err != nil {
		return syms, err
	}
	if syms.subcontextEval, err = purego.Dlsym(handle, "ddwaf_subcontext_eval"); err != nil {
		return syms, err
	}
	if syms.subcontextDestroy, err = purego.Dlsym(handle, "ddwaf_subcontext_destroy"); err != nil {
		return syms, err
	}
	if syms.destroy, err = purego.Dlsym(handle, "ddwaf_destroy"); err != nil {
		return syms, err
	}
	if syms.getVersion, err = purego.Dlsym(handle, "ddwaf_get_version"); err != nil {
		return syms, err
	}
	if syms.knownActions, err = purego.Dlsym(handle, "ddwaf_known_actions"); err != nil {
		return syms, err
	}
	if syms.knownAddresses, err = purego.Dlsym(handle, "ddwaf_known_addresses"); err != nil {
		return syms, err
	}
	if syms.objectDestroy, err = purego.Dlsym(handle, "ddwaf_object_destroy"); err != nil {
		return syms, err
	}
	if syms.objectFromJSON, err = purego.Dlsym(handle, "ddwaf_object_from_json"); err != nil {
		return syms, err
	}
	if syms.getDefaultAllocator, err = purego.Dlsym(handle, "ddwaf_get_default_allocator"); err != nil {
		return syms, err
	}
	if syms.setLogCb, err = purego.Dlsym(handle, "ddwaf_set_log_cb"); err != nil {
		return syms, err
	}
	return syms, nil
}
