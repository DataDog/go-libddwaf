// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import "github.com/DataDog/go-libddwaf/v5/timer"

const (
	// EncodeTimeKey is the key used to track the time spent encoding the address data reported in [Result.TimerStats].
	EncodeTimeKey timer.Key = "encode"
	// DurationTimeKey is the key used to track the time spent in libddwaf ddwaf_run C function reported in [Result.TimerStats].
	DurationTimeKey timer.Key = "duration"
	// DecodeTimeKey is the key used to track the time spent decoding the address data reported in [Result.TimerStats].
	DecodeTimeKey timer.Key = "decode"
)
