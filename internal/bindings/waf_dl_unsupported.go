// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Build when the target OS or architecture are not supported
//go:build (!linux && !darwin) || (!amd64 && !arm64) || go1.23 || datadog.no_waf || (!cgo && !appsec)

package bindings

type wafDl struct{}

func newWafDl() (dl *wafDl, err error) {
	return nil, nil
}

func (waf *wafDl) wafGetVersion() string {
	return ""
}

func (waf *wafDl) wafInit(obj *WafObject, config *WafConfig, info *WafObject) WafHandle {
	return 0
}

func (waf *wafDl) wafUpdate(handle WafHandle, ruleset *WafObject, info *WafObject) WafHandle {
	return 0
}

func (waf *wafDl) wafDestroy(handle WafHandle) {
}

func (waf *wafDl) wafKnownAddresses(handle WafHandle) []string {
	return nil
}

func (waf *wafDl) WafContextInit(handle WafHandle) WafContext {
	return 0
}

func (waf *wafDl) WafContextDestroy(context WafContext) {
}

func (waf *wafDl) wafResultFree(result *WafResult) {
}

func (waf *wafDl) wafObjectFree(obj *WafObject) {
}

func (waf *wafDl) wafRun(context WafContext, persistentData, ephemeralData *WafObject, result *WafResult, timeout uint64) WafReturnCode {
	return WafErrInternal
}
