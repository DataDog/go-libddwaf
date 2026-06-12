// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	"bytes"
	stdlog "log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLevelNamed(t *testing.T) {
	for _, tc := range []struct {
		name string
		want Level
	}{
		{"trace", LevelTrace},
		{"TRACE", LevelTrace},
		{"Trace", LevelTrace},
		{"debug", LevelDebug},
		{"info", LevelInfo},
		{"warn", LevelWarning},
		{"warning", LevelWarning},
		{"WARNING", LevelWarning},
		{"error", LevelError},
		{"off", LevelOff},
		{"", LevelOff},
		{"nonsense", LevelOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, LevelNamed(tc.name))
		})
	}
}

func TestLevelString(t *testing.T) {
	for _, tc := range []struct {
		level Level
		want  string
	}{
		{LevelTrace, "TRACE"},
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarning, "WARN"},
		{LevelError, "ERROR"},
		{LevelOff, "OFF"},
		{Level(99), "0x63"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			require.Equal(t, tc.want, tc.level.String())
		})
	}
}

func TestLogMessageFormatting(t *testing.T) {
	// logFilter() compiles DD_APPSEC_WAF_LOG_FILTER only when DD_APPSEC_WAF_LOG_LEVEL
	// is set (as CI does), which would suppress this synthetic message. Skip then.
	if os.Getenv(EnvVarLogLevel) != "" {
		t.Skip("log filter env is active; logMessage output would be filtered")
	}

	var buf bytes.Buffer
	stdlog.SetOutput(&buf)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	logMessage(LevelInfo, "myFunc", "encoder.go", 42, "hello world")

	require.Contains(t, buf.String(), "[INFO] libddwaf @ encoder.go:42 (myFunc): hello world")
}
