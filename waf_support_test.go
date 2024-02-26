// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ci

package waf

import (
	"flag"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	wafSupportedFlag *bool
	wafBuildTags     *string
)

func init() {
	wafSupportedFlag = flag.Bool("waf-supported", false, "Set to true if the WAF is supported on the current target")
	wafBuildTags = flag.String("waf-build-tags", "", "Set to the build tags used to build the WAF")
}

// TestSupport is used to make sure the WAF is actually enabled and disabled when it respectively should be
// using data send by the CI.
func TestSupport(t *testing.T) {
	require.NotNil(t, wafSupportedFlag, "The `waf-supported` flag should be set")
	require.NotNil(t, wafBuildTags, "The `waf-build-tags` flag should be set")
	require.NotEmpty(t, *wafBuildTags, "The `waf-build-tags` flag should not be empty")

	errors := make([]error, len(wafSupportErrors))
	copy(errors, wafSupportErrors)
	if wafManuallyDisabledErr != nil {
		errors = append(errors, wafManuallyDisabledErr)
	}

	ok, _ := Health()
	require.Equal(t, *wafSupportedFlag, ok, "WAF support should match the value of the `waf-supported` flag in the CI")

	if *wafSupportedFlag {
		require.Empty(t, errors, "No errors should be returned when the WAF is supported")
	} else {
		require.NotEmpty(t, errors, "Errors should be returned when the WAF is not supported")
	}

	for _, err := range errors {
		switch err.(type) {
		case UnsupportedOSArchError:
			require.Contains(t, *wafBuildTags, err.(UnsupportedOSArchError).Os, "The OS is marked as supported but a support error appeared", err)
			require.Contains(t, *wafBuildTags, err.(UnsupportedOSArchError).Arch, "The architecture is marked as supported but a support error appeared", err)
		case UnsupportedGoVersionError:
			// We can't check anything here because we forced the version to be wrong we a build tag added manually instead of just having an incompatible version
		case ManuallyDisabledError:
			require.Contains(t, *wafBuildTags, "datadog.no_waf", "The WAF is marked as enabled but a support error appeared", err)
		case CgoDisabledError:
			require.NotContainsf(t, *wafBuildTags, "cgo", "The build tags contains cgo but a support error appeared", err)
		default:
			require.Fail(t, "Unknown error type", err)
		}
	}
}
