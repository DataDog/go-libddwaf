// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"errors"
	"fmt"
)

// RulesetInfo stores the information - provided by the WAF - about WAF rules initialization.
type RulesetInfo struct {
	// Number of rules successfully loaded
	Loaded uint16
	// Number of rules which failed to parse
	Failed uint16
	// Map from an error string to an array of all the rule ids for which
	// that error was raised. {error: [rule_ids]}
	Errors map[string][]string
	// Ruleset version
	Version string
}

// Encoder/Decoder errors
var (
	errMaxDepth          = errors.New("max depth reached")
	errUnsupportedValue  = errors.New("unsupported Go value")
	errInvalidMapKey     = errors.New("invalid WAF object map key")
	errNilObjectPtr      = errors.New("nil WAF object pointer")
	errInvalidObjectType = errors.New("Invalid type encountered when decoding")
)

// RunError the WAF can return when running it.
type RunError int

// Errors the WAF can return when running it.
const (
	ErrInternal RunError = iota + 1
	ErrInvalidObject
	ErrInvalidArgument
	ErrTimeout
	ErrOutOfMemory
	ErrEmptyRuleAddresses
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
