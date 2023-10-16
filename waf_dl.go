// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.22

package waf

import (
	"fmt"
	"os"

	"github.com/ebitengine/purego"
)

// wafDl is the type wrapper for all C calls to the waf
// It uses `libwaf` to make C calls
// All calls must go through this one-liner to be type safe
// since purego calls are not type safe
type wafDl struct {
	wafSymbols
	handle uintptr
}

type wafSymbols struct {
	rulesetInfoFree   uintptr
	init              uintptr
	update            uintptr
	destroy           uintptr
	requiredAddresses uintptr
	getVersion        uintptr
	contextInit       uintptr
	contextDestroy    uintptr
	resultFree        uintptr
	run               uintptr
}

// newWafDl loads the libddwaf shared library and resolves all tge relevant symbols.
// The caller is responsible for calling wafDl.Close on the returned object once they
// are done with it so that associated resources can be released.
func newWafDl() (dl *wafDl, err error) {
	var file string
	file, err = dumpWafLibrary()
	if err != nil {
		return
	}
	defer func() {
		rmErr := os.Remove(file)
		if rmErr != nil {
			if err == nil {
				err = rmErr
			} else {
				// TODO: rely on errors.Join() once go1.20 is our min supported Go version
				err = fmt.Errorf("%w; along with an error while removing %s: %v", err, file, rmErr)
			}
		}
	}()

	var handle uintptr
	if handle, err = purego.Dlopen(file, purego.RTLD_GLOBAL|purego.RTLD_NOW); err != nil {
		return
	}

	var symbols wafSymbols
	if symbols, err = resolveWafSymbols(handle); err != nil {
		if closeErr := purego.Dlclose(handle); closeErr != nil {
			// TODO: rely on errors.Join() once go1.20 is our min supported Go version
			err = fmt.Errorf("%w; along with an error while releasing the shared libddwaf library: %v", err, closeErr)
		}
		return
	}

	dl = &wafDl{symbols, handle}

	// Try calling the waf to make sure everything is fine
	err = tryCall(func() error {
		dl.wafGetVersion()
		return nil
	})
	if err != nil {
		if closeErr := purego.Dlclose(handle); closeErr != nil {
			// TODO: rely on errors.Join() once go1.20 is our min supported Go version
			err = fmt.Errorf("%w; along with an error while releasing the shared libddwaf library: %v", err, closeErr)
		}
		return
	}

	return
}

func (waf *wafDl) Close() error {
	return purego.Dlclose(waf.handle)
}

// wafGetVersion returned string is a static string so we do not need to free it
func (waf *wafDl) wafGetVersion() string {
	return gostring(cast[byte](waf.syscall(waf.getVersion)))
}

func (waf *wafDl) wafInit(ruleset *wafObject, config *wafConfig, info *wafRulesetInfo) wafHandle {
	handle := wafHandle(waf.syscall(waf.init, ptrToUintptr(ruleset), ptrToUintptr(config), ptrToUintptr(info)))
	keepAlive(ruleset)
	keepAlive(config)
	keepAlive(info)
	return handle
}

func (waf *wafDl) wafUpdate(handle wafHandle, ruleset *wafObject, info *wafRulesetInfo) wafHandle {
	newHandle := wafHandle(waf.syscall(waf.update, uintptr(handle), ptrToUintptr(ruleset), ptrToUintptr(info)))
	keepAlive(ruleset)
	keepAlive(info)
	return newHandle
}

func (waf *wafDl) wafRulesetInfoFree(info *wafRulesetInfo) {
	waf.syscall(waf.rulesetInfoFree, ptrToUintptr(info))
	keepAlive(info)
}

func (waf *wafDl) wafDestroy(handle wafHandle) {
	waf.syscall(waf.destroy, uintptr(handle))
	keepAlive(handle)
}

// wafRequiredAddresses returns static strings so we do not need to free them
func (waf *wafDl) wafRequiredAddresses(handle wafHandle) []string {
	var nbAddresses uint32

	arrayVoidC := waf.syscall(waf.requiredAddresses, uintptr(handle), ptrToUintptr(&nbAddresses))
	if arrayVoidC == 0 {
		return nil
	}

	addresses := make([]string, int(nbAddresses))
	for i := 0; i < int(nbAddresses); i++ {
		addresses[i] = gostring(*castWithOffset[*byte](arrayVoidC, uint64(i)))
	}

	keepAlive(&nbAddresses)
	keepAlive(handle)

	return addresses
}

func (waf *wafDl) wafContextInit(handle wafHandle) wafContext {
	ctx := wafContext(waf.syscall(waf.contextInit, uintptr(handle)))
	keepAlive(handle)
	return ctx
}

func (waf *wafDl) wafContextDestroy(context wafContext) {
	waf.syscall(waf.contextDestroy, uintptr(context))
	keepAlive(context)
}

func (waf *wafDl) wafResultFree(result *wafResult) {
	waf.syscall(waf.resultFree, ptrToUintptr(result))
	keepAlive(result)
}

func (waf *wafDl) wafRun(context wafContext, obj *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	rc := wafReturnCode(waf.syscall(waf.run, uintptr(context), ptrToUintptr(obj), ptrToUintptr(result), uintptr(timeout)))
	keepAlive(context)
	keepAlive(obj)
	keepAlive(result)
	keepAlive(timeout)
	return rc
}

// syscall is the only way to make C calls with this interface.
// purego implementation limits the number of arguments to 9, it will panic if more are provided
// Note: `purego.SyscallN` has 3 return values: these are the following:
//
//	1st - The return value is a pointer or a int of any type
//	2nd - The return value is a float
//	3rd - The value of `errno` at the end of the call
func (waf *wafDl) syscall(fn uintptr, args ...uintptr) uintptr {
	ret, _, _ := purego.SyscallN(fn, args...)
	return ret
}

// resolveWafSymbols resolves relevant symbols from the libddwaf shared library using the provided
// purego.Dlopen handle.
func resolveWafSymbols(handle uintptr) (symbols wafSymbols, err error) {
	if symbols.rulesetInfoFree, err = purego.Dlsym(handle, "ddwaf_ruleset_info_free"); err != nil {
		return
	}
	if symbols.init, err = purego.Dlsym(handle, "ddwaf_init"); err != nil {
		return
	}
	if symbols.update, err = purego.Dlsym(handle, "ddwaf_update"); err != nil {
		return
	}
	if symbols.destroy, err = purego.Dlsym(handle, "ddwaf_destroy"); err != nil {
		return
	}
	if symbols.requiredAddresses, err = purego.Dlsym(handle, "ddwaf_required_addresses"); err != nil {
		return
	}
	if symbols.getVersion, err = purego.Dlsym(handle, "ddwaf_get_version"); err != nil {
		return
	}
	if symbols.contextInit, err = purego.Dlsym(handle, "ddwaf_context_init"); err != nil {
		return
	}
	if symbols.contextDestroy, err = purego.Dlsym(handle, "ddwaf_context_destroy"); err != nil {
		return
	}
	if symbols.resultFree, err = purego.Dlsym(handle, "ddwaf_result_free"); err != nil {
		return
	}
	if symbols.run, err = purego.Dlsym(handle, "ddwaf_run"); err != nil {
		return
	}

	return
}

// Implement SupportsTarget()
func supportsTarget() (bool, error) {
	return true, nil
}
