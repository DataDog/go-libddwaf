// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.27 && !datadog.no_waf && cgo

package log

// #include "./ddwaf.h"
// extern void ddwafLogCallbackFnV4(
//   DDWAF_LOG_LEVEL level,
//   char* function,
//   char* file,
//   unsigned line,
//   char* message,
//   uint64_t message_len
// );
import "C"
import "github.com/DataDog/go-libddwaf/v4/internal/unsafe"

// CallbackFunctionPointer returns a pointer to the log callback function which
// can be used with libddwaf.
func CallbackFunctionPointer() uintptr {
	return uintptr(C.ddwafLogCallbackFnV4)
}

//export ddwafLogCallbackFnV4
func ddwafLogCallbackFnV4(level C.DDWAF_LOG_LEVEL, fnPtr, filePtr *C.char, line C.unsigned, msgPtr *C.char, _ C.uint64_t) {
	function := unsafe.Gostring((*byte)(unsafe.Pointer(fnPtr)))
	file := unsafe.Gostring((*byte)(unsafe.Pointer(filePtr)))
	message := unsafe.Gostring((*byte)(unsafe.Pointer(msgPtr)))

	logMessage(Level(level), function, file, uint(line), message)
}
