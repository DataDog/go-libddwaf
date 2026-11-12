// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waferrors

import (
	"fmt"
	"runtime"
)

// UnsupportedOSArchError is a wrapper error type helping to handle the error
// case of trying to execute this package when the OS or architecture is not supported.
type UnsupportedOSArchError struct {
	OS   string
	Arch string
}

// Error returns a message that names the unsupported OS and architecture.
func (e UnsupportedOSArchError) Error() string {
	return fmt.Sprintf("unsupported OS/Arch: %s/%s", e.OS, e.Arch)
}

// UnsupportedGoVersionError is a wrapper error type helping to handle the error
// case of trying to execute this package when the Go version is not supported.
type UnsupportedGoVersionError struct{}

// Error returns a message that names the Go version in use and tells the user
// to update go-libddwaf.
func (e UnsupportedGoVersionError) Error() string {
	return fmt.Sprintf(
		"unsupported Go version: %s (try running `go get github.com/DataDog/go-libddwaf@latest`)",
		runtime.Version(),
	)
}

// CgoDisabledError is a wrapper error type helping to handle the error case of
// trying to execute this package when cgo is disabled and the `appsec` go build
// tag is not set.
type CgoDisabledError struct{}

// Error returns a message that explains that go-libddwaf is disabled without
// cgo, and lists the shared libraries that are needed at run time on Linux.
func (e CgoDisabledError) Error() string {
	return "go-libddwaf is disabled when cgo is disabled unless you compile with the go build tag `appsec`. It will require libdl.so.2. libpthread.so.0 and libc.so.6 shared libraries at run time on linux"
}

// ManuallyDisabledError is a wrapper error type helping to handle the error
// case of trying to execute this package when the WAF has been manually disabled with
// the `datadog.no_waf` go build tag.
type ManuallyDisabledError struct{}

// Error returns a message that explains that the `datadog.no_waf` go build tag
// disabled the WAF.
func (e ManuallyDisabledError) Error() string {
	return "the WAF has been manually disabled using the `datadog.no_waf` go build tag"
}
