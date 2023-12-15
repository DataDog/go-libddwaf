// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.22 && !datadog.no_waf

package waf

import (
	"fmt"
	"log"

	"github.com/ebitengine/purego"
)

// ddwafLogLevel replicates the definition of `DDWAF_LOG_LEVEL` from `ddwaf.h`.
type ddwafLogLevel uint

const (
	ddwafLogLevelTrace ddwafLogLevel = iota
	ddwafLogLevelDebug
	ddwafLogLevelInfo
	ddwafLogLevelWarning
	ddwafLogLevelError
	ddwafLogLevelOff
)

// ddwafLogCallback is a purego-ready function pointer to a C-ABI compatible
// version of ddwafLogCallbackFn.
var ddwafLogCallback = purego.NewCallback(ddwafLogCallbackFn)

// ddwafLogCallbackFn
func ddwafLogCallbackFn(level ddwafLogLevel, fnPtr, filePtr *byte, line uint, msgPtr *byte, messageLen uint64) {
	function := gostring(fnPtr)
	file := gostring(filePtr)
	message := gostring(msgPtr)

	log.Printf("[%-5s] libddwaf @ %s:%d (%s): %s\n", level.String(), file, line, function, message)
}

func (l ddwafLogLevel) String() string {
	switch l {
	case ddwafLogLevelTrace:
		return "TRACE"
	case ddwafLogLevelDebug:
		return "DEBUG"
	case ddwafLogLevelInfo:
		return "INFO"
	case ddwafLogLevelWarning:
		return "WARN"
	case ddwafLogLevelError:
		return "ERROR"
	case ddwafLogLevelOff:
		return "OFF"
	default:
		return fmt.Sprintf("0x%X", uintptr(l))
	}
}
