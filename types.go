// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"errors"
	"fmt"

	"go.uber.org/atomic"
)

// RunError the WAF can return when running it.
type RunError int

// RulesetInfo stores the information - provided by the WAF - about WAF rules initialization.
type RulesetInfo struct {
	// Number of rules successfully loaded
	Loaded uint16
	// Number of rules which failed to parse
	Failed uint16
	// Map from an error string to an array of all the rule ids for which
	// that error was raised. {error: [rule_ids]}
	Errors map[string]interface{}
	// Ruleset version
	Version string
}

// Errors the WAF can return when running it.
const (
	ErrInternal RunError = -3
	ErrInvalidObject RunError = -2
	ErrInvalidArgument RunError = -1
	OK = 0
	Match = 1

	ErrOutOfMemory RunError = 5
	ErrEmptyRuleAddresses RunError = 6
	ErrTimeout RunError = 7
)

// Error returns the string representation of the RunError.
func (e RunError) Error() string {
	switch e {
	case ErrInternal:
		return "internal waf error"
	case ErrTimeout:
		return "waf timeout"
	case ErrInvalidObject:
		return "invalid waf object"
	case ErrInvalidArgument:
		return "invalid waf argument"
	case ErrOutOfMemory:
		return "out of memory"
	case ErrEmptyRuleAddresses:
		return "empty rule addresses"
	default:
		return fmt.Sprintf("unknown waf error %d", e)
	}
}

// AtomicU64 can be used to perform atomic operations on an uint64 type
type AtomicU64 = atomic.Uint64

// Errors the encoder and decoder can return.
var (
	errMaxDepth         = errors.New("max depth reached")
	errUnsupportedValue = errors.New("unsupported Go value")
	errOutOfMemory      = errors.New("out of memory")
	errInvalidMapKey    = errors.New("invalid WAF object map key")
	errNilObjectPtr     = errors.New("nil WAF object pointer")
)

