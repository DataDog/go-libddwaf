// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"github.com/DataDog/go-libddwaf/v5/timer"
)

// numTruncationReasons is the number of known [TruncationReason]s; sized so
// the truncations map allocated in NewContext/NewSubcontext rarely grows.
const numTruncationReasons = 3

// RunAddressData provides address data to the [Context.Run] method.
// When encoding Go structs to the WAF-compatible format, fields with the `ddwaf:"ignore"` tag are
// ignored and will not be visible to the WAF.
//
// Data passed to Run is stored and persists for the lifetime of the context or subcontext.
// Use NewSubcontext() to scope data to a shorter lifetime.
type RunAddressData struct {
	// Data is the address data to pass to the WAF. Data is stored and persists across multiple
	// calls to Run until the context or subcontext is closed.
	Data map[string]any

	// TimerKey is the key used to track the time spent in the WAF for this run.
	// If left empty, a new timer with unlimited budget is started.
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
func merge[K comparable, V any](a, b map[K][]V) (merged map[K][]V) {
	if len(a) == 0 && len(b) == 0 {
		return
	}

	totalCount := 0
	for _, v := range a {
		totalCount += len(v)
	}
	for _, v := range b {
		totalCount += len(v)
	}

	merged = make(map[K][]V, len(a)+len(b))
	values := make([]V, 0, totalCount)

	for k, av := range a {
		start := len(values)
		values = append(values, av...)
		values = append(values, b[k]...)
		merged[k] = values[start:]
	}

	for k, bv := range b {
		if _, ok := merged[k]; !ok {
			start := len(values)
			values = append(values, bv...)
			merged[k] = values[start:]
		}
	}

	return
}
