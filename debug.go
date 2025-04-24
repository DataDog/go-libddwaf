// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build libddwaf.debug

package libddwaf

import "github.com/DataDog/go-libddwaf/v4/internal/log"

func init() {
	ok, _ := Load()
	if !ok {
		return
	}
	wafLib.SetLogCb(log.CallbackFunctionPointer(), log.LevelDebug)
}
