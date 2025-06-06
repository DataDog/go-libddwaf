// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"time"

	"github.com/DataDog/go-libddwaf/v4/timer"
)

// Result stores the multiple values returned by a call to [Context.Run].
type Result struct {
	// Events is the list of events the WAF detected, together with any relevant
	// details. These are typically forwarded as opaque objects to the Datadog
	// backend.
	Events []any

	// Derivatives is the set of key-value pairs generated by the WAF, and which
	// need to be reported on the trace to provide additional data to the Datadog
	// backend.
	Derivatives map[string]any

	// Actions is the set of actions the WAF decided on when evaluating rules
	// against the provided address data. It maps action types to their dynamic
	// parameter values.
	Actions map[string]any

	// Timer returns the time spend in the different parts of the run. Keys can be found with the suffix [
	TimerStats map[timer.Key]time.Duration

	// Keep is true if the WAF instructs the trace should be set to manual keep priority.
	Keep bool
}

// HasEvents return true if the [Result] holds at least 1 event.
func (r *Result) HasEvents() bool {
	return len(r.Events) > 0
}

// HasDerivatives return true if the [Result] holds at least 1 derivative.
func (r *Result) HasDerivatives() bool {
	return len(r.Derivatives) > 0
}

// HasActions return true if the [Result] holds at least 1 action.
func (r *Result) HasActions() bool {
	return len(r.Actions) > 0
}

const (
	// EncodeTimeKey is the key used to track the time spent encoding the address data reported in [Result.TimerStats].
	EncodeTimeKey timer.Key = "encode"
	// DurationTimeKey is the key used to track the time spent in libddwaf ddwaf_run C function reported in [Result.TimerStats].
	DurationTimeKey timer.Key = "duration"
	// DecodeTimeKey is the key used to track the time spent decoding the address data reported in [Result.TimerStats].
	DecodeTimeKey timer.Key = "decode"
)
