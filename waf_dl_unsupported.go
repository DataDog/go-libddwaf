// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Build when the target OS or architecture are not supported
//go:build (!linux && !darwin) || (!amd64 && !arm64)

package waf

import (
	"fmt"
	"runtime"
)

type wafDl struct{}

func newWafDl() (dl *wafDl, err error) {
	return nil, UnsupportedTargetError{fmt.Errorf("the target operating-system %s or architecture %s are not supported", runtime.GOOS, runtime.GOARCH)}
}

func (waf *wafDl) wafGetVersion() string {
	return ""
}

func (waf *wafDl) wafInit(obj *wafObject, config *wafConfig, info *wafRulesetInfo) wafHandle {
	return 0
}

func (waf *wafDl) wafRulesetInfoFree(info *wafRulesetInfo) {
}

func (waf *wafDl) wafDestroy(handle wafHandle) {
}

func (waf *wafDl) wafRequiredAddresses(handle wafHandle) []string {
	return nil
}

func (waf *wafDl) wafContextInit(handle wafHandle) wafContext {
	return 0
}

func (waf *wafDl) wafContextDestroy(context wafContext) {
}

func (waf *wafDl) wafResultFree(result *wafResult) {
}

func (waf *wafDl) wafRun(context wafContext, obj *wafObject, result *wafResult, timeout uint64) wafReturnCode {
	return wafErrInternal
}
