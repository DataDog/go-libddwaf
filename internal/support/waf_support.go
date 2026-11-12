// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package support

// Errors used to report data using the Health function
// Store all the errors related to why go-liddwaf is unavailable for the current target at runtime.
var wafSupportErrors []error

// Not nil if the build tag `datadog.no_waf` is set
var wafManuallyDisabledErr error

// WafSupportErrors returns the errors that explain why go-libddwaf is not
// available for the current target. The list is empty when the target is supported.
func WafSupportErrors() []error {
	return wafSupportErrors
}

// WafManuallyDisabledError returns the error that tells that the WAF is manually
// disabled with the `datadog.no_waf` go build tag. It returns nil when the tag
// is not set.
func WafManuallyDisabledError() error {
	return wafManuallyDisabledErr
}
