// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"errors"
	"fmt"
)

// Diagnostics stores the information - provided by the WAF - about WAF rules initialization.
type Diagnostics struct {
	// Rules contains information about the loaded rules.
	Rules *DiagnosticEntry
	// CustomRules contains information about the loaded custom rules.
	CustomRules *DiagnosticEntry
	// Actions contains information about the loaded actions.
	Actions *DiagnosticEntry
	// Exclusions contains information about the loaded exclusions.
	Exclusions *DiagnosticEntry
	// RulesOverrides contains information about the loaded rules overrides.
	RulesOverrides *DiagnosticEntry
	// RulesData contains information about the loaded rules data.
	RulesData *DiagnosticEntry
	// ExclusionData contains information about the loaded exclusion data.
	ExclusionData *DiagnosticEntry
	// Processors contains information about the loaded processors.
	Processors *DiagnosticEntry
	// Scanners contains information about the loaded scanners.
	Scanners *DiagnosticEntry
	// Version is the version of the parsed ruleset if available.
	Version string
}

// TopLevelError returns the list of top-level errors reported by the WAF on any of the Diagnostics
// entries, rolled up into a single error value. Returns nil if no top-level errors were reported.
// Individual, item-level errors might still exist.
func (d *Diagnostics) TopLevelError() error {
	fields := map[string]*DiagnosticEntry{
		"rules":          d.Rules,
		"actions":        d.Actions,
		"custom_rules":   d.CustomRules,
		"exclusions":     d.Exclusions,
		"rules_override": d.RulesOverrides,
		"rules_data":     d.RulesData,
		"exclusion_data": d.ExclusionData,
		"processors":     d.Processors,
		"scanners":       d.Scanners,
	}

	var err error
	for field, entry := range fields {
		if entry == nil || entry.Error == "" {
			// No entry or no error => we're all good.
			continue
		}
		err = errors.Join(err, fmt.Errorf("in %q: %s", field, entry.Error))
	}

	return err
}

// DiagnosticEntry stores the information - provided by the WAF - about loaded and failed rules
// for a specific entry in the WAF ruleset
type DiagnosticEntry struct {
	Addresses *DiagnosticAddresses
	// Errors is a map of parsing errors to a list of unique identifiers from the elements which
	// failed loading due to this specific error.
	Errors map[string][]string
	// Warnings is a map of parsing warnings to a list of unique identifiers from the elements which
	// resulted in this specific warning.
	Warnings map[string][]string
	// Error is the single error which prevented parsing this feature.
	Error string
	// Loaded is a list of the unique identifiers from successfully loaded elements.
	Loaded []string
	// Failed is a list of the unique identifiers from the elements which couldn't be loaded.
	Failed []string
	// Skipped is a list of the unique identifiers from the elements which were skipped.
	Skipped []string
}

// DiagnosticAddresses stores the information - provided by the WAF - about the known addresses and
// whether they are required or optional. Addresses used by WAF rules are always required. Addresses
// used by WAF exclusion filters may be required or (rarely) optional. Addresses used by WAF
// processors may be required or optional.
type DiagnosticAddresses struct {
	Required []string
	Optional []string
}
