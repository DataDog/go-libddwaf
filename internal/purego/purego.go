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
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	RTLD_NOW   = purego.RTLD_NOW
	RTLD_LOCAL = purego.RTLD_LOCAL
)

func Dlopen(path string, flags int) (uintptr, error) {
	debug_log("Dlopen(%q, 0x%x)", path, flags)
	handle, err := purego.Dlopen(path, flags)
	debug_log("Dlopen(%q, 0x%x) = %p, %v", path, flags, unsafe.Pointer(handle), err)
	return handle, err
}

func Dlsym(handle uintptr, name string) (uintptr, error) {
	debug_log("Dlsym(%p, %q)", unsafe.Pointer(handle), name)
	ptr, err := purego.Dlsym(handle, name)
	debug_log("Dlsym(%p, %q) = %p, %v", unsafe.Pointer(handle), name, unsafe.Pointer(ptr), err)
	return ptr, err
}

func Dlclose(handle uintptr) error {
	handlePtr := unsafe.Pointer(handle)
	debug_log("Dlclose(%p)", handlePtr)
	err := purego.Dlclose(handle)
	debug_log("Dlclose(%p) = %v", handlePtr, err)
	return err
}

func SyscallN(fn uintptr, args ...uintptr) (uintptr, uintptr, uintptr) {
	var argsStr string
	for _, arg := range args {
		argsStr += fmt.Sprintf(", %p", unsafe.Pointer(arg))
	}

	debug_log("SyscallN(%p%s)", unsafe.Pointer(fn), argsStr)
	ret, f, e := purego.SyscallN(fn, args...)
	debug_log("SyscallN(%p%s) = %p, %p, %v", unsafe.Pointer(fn), argsStr, unsafe.Pointer(ret), unsafe.Pointer(f), unsafe.Pointer(e))
	return ret, f, e
}

var (
	once  sync.Once
	file  *os.File
	start time.Time
)

func debug_log(format string, args ...any) {
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
