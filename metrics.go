// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"fmt"
	"sync"
	"time"
)

// Stats stores the metrics collected by the WAF.
type Stats struct {
	// Timers returns a map of metrics and their durations.
	Timers map[string]time.Duration

	// TimeoutCount for the Default Scope i.e. "waf"
	TimeoutCount uint64

	// TimeoutRASPCount for the RASP Scope i.e. "rasp"
	TimeoutRASPCount uint64

	// Truncations provides details about truncations that occurred while
	// encoding address data for WAF execution.
	Truncations map[TruncationReason][]int

	// TruncationsRASP provides details about truncations that occurred while
	// encoding address data for RASP execution.
	TruncationsRASP map[TruncationReason][]int
}

// Scope is the way to classify the different runs in the same context in order to have different metrics
type Scope string

const (
	DefaultScope Scope = "waf"
	RASPScope    Scope = "rasp"
)

const (
	wafEncodeTag     = "encode"
	wafRunTag        = "duration_ext"
	wafDurationTag   = "duration"
	wafDecodeTag     = "decode"
	wafTimeoutTag    = "timeouts"
	wafTruncationTag = "truncations"
)

// Metrics transform the stats returned by the WAF into a map of key value metrics for datadog backend
func (stats Stats) Metrics() map[string]any {
	tags := make(map[string]any, len(stats.Timers)+len(stats.Truncations)+1)
	for k, v := range stats.Timers {
		tags[k] = float64(v.Nanoseconds()) / float64(time.Microsecond) // The metrics should be in microseconds
	}

	if stats.TimeoutCount > 0 {
		tags[key(DefaultScope, wafTimeoutTag)] = stats.TimeoutCount
	}

	if stats.TimeoutRASPCount > 0 {
		tags[key(RASPScope, wafTimeoutTag)] = stats.TimeoutRASPCount
	}

	for reason, list := range stats.Truncations {
		tags[fmt.Sprintf("%s.%s", key(DefaultScope, wafTruncationTag), reason.String())] = list
	}

	for reason, list := range stats.TruncationsRASP {
		tags[fmt.Sprintf("%s.%s", key(RASPScope, wafTruncationTag), reason.String())] = list

	}

	return tags
}

type metricsStore struct {
	data  map[string]time.Duration
	mutex sync.RWMutex
}

func key(scope Scope, component string) string {
	return fmt.Sprintf("%s.%s", scope, component)
}

func (metrics *metricsStore) add(scope Scope, component string, duration time.Duration) {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.data == nil {
		metrics.data = make(map[string]time.Duration, 5)
	}

	metrics.data[key(scope, component)] += duration
}

func (metrics *metricsStore) get(scope Scope, component string) time.Duration {
	metrics.mutex.RLock()
	defer metrics.mutex.RUnlock()
	return metrics.data[key(scope, component)]
}

func (metrics *metricsStore) copy() map[string]time.Duration {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.data == nil {
		return nil
	}

	copy := make(map[string]time.Duration, len(metrics.data))
	for k, v := range metrics.data {
		copy[k] = v
	}
	return copy
}

// merge merges the current metrics with new ones
func (metrics *metricsStore) merge(scope Scope, other map[string]time.Duration) {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.data == nil {
		metrics.data = make(map[string]time.Duration, 5)
	}

	for component, val := range other {
		key := key(scope, component)
		prev, ok := metrics.data[key]
		if !ok {
			prev = 0
		}
		metrics.data[key] = prev + val
	}
}
