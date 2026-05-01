// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"github.com/DataDog/go-libddwaf/v5/timer"
)

// RunAddressData provides address data to the [Context.Run] method.
// Fields tagged `ddwaf:"ignore"` are omitted when encoding Go structs to the WAF-compatible format.
//
// Data passed to Run persists for the lifetime of the context or subcontext.
// Use NewSubcontext() for shorter-lived data.
type RunAddressData struct {
	// Data is passed to the WAF and persists across multiple calls to Run
	// until the context or subcontext closes.
	Data map[string]any

	// TimerKey tracks time spent in the WAF for this run.
	// Leave it empty to start a new timer with unlimited budget.
	TimerKey timer.Key
}

func (d RunAddressData) isEmpty() bool {
	return len(d.Data) == 0
}

// merge combines two maps of slices into one. All returned slice values
// share a single backing array for efficiency. Callers MUST NOT append
// to individual slices in the returned map, as this would corrupt
// adjacent entries in the shared backing array.
//
// It contains all keys from both a and b, with the corresponding values
// from a and b concatenated in that order. The named return keeps the
// empty-input fast path concise while still allowing the accumulator to be
// built without extra copies.
