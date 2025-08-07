// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package purego

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ebitengine/purego"
)

const (
	RTLD_NOW   = purego.RTLD_NOW
	RTLD_LOCAL = purego.RTLD_LOCAL
)

func Dlopen(path string, flags int) (uintptr, error) {
	DebugLogSlow("Dlopen(%q, 0x%x)", path, flags)
	handle, err := purego.Dlopen(path, flags)
	DebugLogSlow("Dlopen(%q, 0x%x) = 0x%x, %v", path, flags, handle, err)
	return handle, err
}

func Dlsym(handle uintptr, name string) (uintptr, error) {
	DebugLogSlow("Dlsym(0x%x, %q)", handle, name)
	ptr, err := purego.Dlsym(handle, name)
	DebugLogSlow("Dlsym(0x%x, %q) = 0x%x, %v", handle, name, ptr, err)
	return ptr, err
}

func Dlclose(handle uintptr) error {
	handlePtr := handle
	DebugLogSlow("Dlclose(0x%x)", handlePtr)
	err := purego.Dlclose(handle)
	DebugLogSlow("Dlclose(0x%x) = %v", handlePtr, err)
	return err
}

func SyscallN(fn uintptr, args ...uintptr) (uintptr, uintptr, uintptr) {
	var argsStr string
	for _, arg := range args {
		argsStr += fmt.Sprintf(", 0x%x", arg)
	}

	DebugLogSlow("SyscallN(0x%x%s)", fn, argsStr)
	ret, f, e := purego.SyscallN(fn, args...)
	DebugLogSlow("SyscallN(0x%x%s) = 0x%x, 0x%x, 0x%x", fn, argsStr, ret, f, e)
	return ret, f, e
}

var (
	once  sync.Once
	file  *os.File
	start time.Time
)

func DebugLogSlow(format string, args ...any) {
	once.Do(func() {
		var err error
		filepath := filepath.Join(os.Getenv("HOME"), fmt.Sprintf("libddwaf-purego.%v.log", os.Getpid()))
		file, err = os.Create(filepath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create debug log file %q: %v\n", filepath, err)
			file = os.Stderr
		}
		start = time.Now()
	})

	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	_, _ = fmt.Fprintf(file, "[+%5dms] ", time.Since(start).Milliseconds())
	_, _ = fmt.Fprintf(file, format, args...)
	// Try to ensure this isn't in OS I/O buffer if we panic...
	_ = file.Sync()
}
