// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Build when the target OS or architecture are not supported
//go:build !((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64)) || (windows && (amd64 || 386))) || go1.22

package waf

type wafDl struct{}

func newWafDl() (dl *wafDl, err error) {
	return nil, unsupportedTargetErr
}

func (waf *wafDl) wafGetVersion() string {
	return ""
}

func (waf *wafDl) wafInit(obj *wafObject, config *wafConfig, info *wafObject) wafHandle {
	return 0
}

func (waf *wafDl) wafUpdate(handle wafHandle, ruleset *wafObject, info *wafObject) wafHandle {
	return 0
}

func (waf *wafDl) wafDestroy(handle wafHandle) {
}

func (waf *wafDl) wafKnownAddresses(handle wafHandle) []string {
	return nil
}

func (waf *wafDl) wafContextInit(handle wafHandle) wafContext {
	return 0
}

func (waf *wafDl) wafContextDestroy(context wafContext) {
}

func (waf *wafDl) wafResultFree(result *wafResult) {
}

func (waf *wafDl) wafObjectFree(obj *wafObject) {
}

func (waf *wafDl) wafRun(context wafContext, persistentData, ephemeralData *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	return wafErrInternal
}

// Implement SupportsTarget()
func supportsTarget() (bool, error) {
	// TODO: provide finer-grained unsupported target error message giving the
	//    exact reason why
	return false, unsupportedTargetErr
}
