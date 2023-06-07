// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package empty_free

import "unsafe"

//go:linkname _empty_free _empty_free
var _empty_free byte
var EmptyFreeFn uintptr = uintptr(unsafe.Pointer(&_empty_free))
