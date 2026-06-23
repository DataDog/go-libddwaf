// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ci

package libddwaf

import (
	"errors"
	"flag"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/log"
	"github.com/DataDog/go-libddwaf/v5/internal/support"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

var (
	wafSupportedFlag *string
	wafBuildTags     *string
)

func init() {
	wafSupportedFlag = flag.String("waf-supported", "false", "Set to true if the WAF is supported on the current target (true, false, maybe)")
	wafBuildTags = flag.String("waf-build-tags", "", "Set to the build tags used to build the WAF")
}

// TestSupport is used to make sure the WAF is actually enabled and disabled when it respectively should be
// using data send by the CI.
func TestSupport(t *testing.T) {
	require.NotNil(t, wafSupportedFlag, "The `waf-supported` flag should be set")
	require.Contains(t, []string{"true", "false", "maybe"}, *wafSupportedFlag, "The `waf-supported` flag should be set to true, false or maybe")
	require.NotNil(t, wafBuildTags, "The `waf-build-tags` flag should be set")
	if *wafBuildTags == "" {
		t.Skip("waf-build-tags is provided by ci.sh")
	}
	require.NotEmpty(t, *wafBuildTags, "The `waf-build-tags` flag should not be empty")

	supportErrors := make([]error, len(support.WafSupportErrors()))
	copy(supportErrors, support.WafSupportErrors())
	if support.WafManuallyDisabledError() != nil {
		supportErrors = append(supportErrors, support.WafManuallyDisabledError())
	}

	ok, _ := Usable()
	switch *wafSupportedFlag {
	case "true":
		require.True(t, ok, "WAF support should match the value of the `waf-supported` flag in the CI (was true)")
	case "false":
		require.False(t, ok, "WAF support should match the value of the `waf-supported` flag in the CI (was false)")
	case "maybe":
		t.Logf("The actual WAF support status is %v", ok)
	}

	if ok {
		require.Empty(t, supportErrors, "No errors should be returned when the WAF is supported")
		require.NotZero(t, log.CallbackFunctionPointer(), "The log callback function pointer should not be zero when the WAF is supported")
	} else {
		require.NotEmpty(t, supportErrors, "Errors should be returned when the WAF is not supported")
	}

	for _, err := range supportErrors {
		var (
			osArchErr    waferrors.UnsupportedOSArchError
			goVersionErr waferrors.UnsupportedGoVersionError
			disabledErr  waferrors.ManuallyDisabledError
			cgoErr       waferrors.CgoDisabledError
		)
		switch {
		case errors.As(err, &osArchErr):
			require.Contains(t, *wafBuildTags, osArchErr.OS, "The OS is marked as supported but a support error appeared", err)
			require.Contains(t, *wafBuildTags, osArchErr.Arch, "The architecture is marked as supported but a support error appeared", err)
		case errors.As(err, &goVersionErr):
			// We can't check anything here because we forced the version to be wrong we a build tag added manually instead of just having an incompatible version
		case errors.As(err, &disabledErr):
			require.Contains(t, *wafBuildTags, "datadog.no_waf", "The WAF is marked as enabled but a support error appeared", err)
		case errors.As(err, &cgoErr):
			require.NotContainsf(t, *wafBuildTags, "cgo", "The build tags contains cgo but a support error appeared", err)
		default:
			require.Fail(t, "Unknown error type", err)
		}
	}
}
