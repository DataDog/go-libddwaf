// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	"fmt"
	"log"
	"strings"
)

// Level replicates the definition of `DDWAF_LOG_LEVEL` from `ddwaf.h`.
type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarning
	LevelError
	LevelOff
)

// LevelNamed returns the log level corresponding to the given name, or LevelOff
// if the name corresponds to no known log level.
func LevelNamed(name string) Level {
	switch strings.ToLower(name) {
	case "trace":
		return LevelTrace
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarning
	case "error":
		return LevelError
	case "off":
		return LevelOff
	default:
		return LevelOff
	}
}

func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarning:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelOff:
		return "OFF"
	default:
		return fmt.Sprintf("0x%X", uintptr(l))
	}
}

func logMessage(level Level, function, file string, line uint, message string) {
	log.Printf("[%-5s] libddwaf @ %s:%d (%s): %s\n", level, file, line, function, message)
}
