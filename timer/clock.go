// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"sync"
	"time"
)

// clock is a simple cache for time.Now() to hopefully avoid some expensive calls to REALTIME part of time.Now()
type clock struct {
	mu          sync.Mutex
	lastRequest time.Time
}

func newTimeCache() *clock {
	return &clock{
		lastRequest: time.Now(),
	}
}

func (ct *clock) now() time.Time {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	if now.After(ct.lastRequest) {
		ct.lastRequest = now
	}
	return ct.lastRequest
}
