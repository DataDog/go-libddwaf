// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ci

package libddwaf

import (
	"flag"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/internal/log"
	"github.com/DataDog/go-libddwaf/v4/internal/support"
	"github.com/DataDog/go-libddwaf/v4/waferrors"
	"github.com/stretchr/testify/require"
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
	require.NotEmpty(t, *wafBuildTags, "The `waf-build-tags` flag should not be empty")

	errors := make([]error, len(support.WafSupportErrors()))
	copy(errors, support.WafSupportErrors())
	if support.WafManuallyDisabledError() != nil {
		errors = append(errors, support.WafManuallyDisabledError())
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
		require.Empty(t, errors, "No errors should be returned when the WAF is supported")
		require.NotZero(t, log.CallbackFunctionPointer(), "The log callback function pointer should not be zero when the WAF is supported")
	} else {
		require.NotEmpty(t, errors, "Errors should be returned when the WAF is not supported")
	}

	for _, err := range errors {
		switch err := err.(type) {
		case waferrors.UnsupportedOSArchError:
			require.Contains(t, *wafBuildTags, err.OS, "The OS is marked as supported but a support error appeared", err)
			require.Contains(t, *wafBuildTags, err.Arch, "The architecture is marked as supported but a support error appeared", err)
		case waferrors.UnsupportedGoVersionError:
			// We can't check anything here because we forced the version to be wrong we a build tag added manually instead of just having an incompatible version
		case waferrors.ManuallyDisabledError:
			require.Contains(t, *wafBuildTags, "datadog.no_waf", "The WAF is marked as enabled but a support error appeared", err)
		case waferrors.CgoDisabledError:
			require.NotContainsf(t, *wafBuildTags, "cgo", "The build tags contains cgo but a support error appeared", err)
		default:
			require.Fail(t, "Unknown error type", err)
		}
	}
}
