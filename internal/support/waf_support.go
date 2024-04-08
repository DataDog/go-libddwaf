// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package support

import "errors"

// Errors used to report data using the Health function
// Store all the errors related to why go-liddwaf is unavailable for the current target at runtime.
var wafSupportErrors []error

// Not nil if the build tag `datadog.no_waf` is set
var wafManuallyDisabledErr error

// WafSupportErrors returns all the errors related to why go-liddwaf is unavailable for the current target at runtime.
func WafSupportErrors() error {
	return errors.Join(wafSupportErrors...)
}

// WafManuallyDisabledError returns an error if the build tag `datadog.no_waf` is set
func WafManuallyDisabledError() error {
	return wafManuallyDisabledErr
}
