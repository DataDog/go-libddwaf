// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"fmt"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// decodeErrors decodes WAF diagnostics error data into a map structure for easier consumption.
// The WAF library returns errors grouped by message, with each message mapping to the rule IDs
// that failed with that error. This structure allows callers to report both error messages and
// the specific rules that failed.
func decodeErrors(obj *WAFObject) (map[string][]string, error) {
	if !obj.IsMap() {
		return nil, fmt.Errorf("decodeErrors: %w: expected map, got %s", waferrors.ErrInvalidObjectType, obj.Type())
	}
	entries, err := obj.MapEntries()
	if err != nil {
		return nil, fmt.Errorf("decodeErrors: failed to get map entries: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	wafErrors := make(map[string][]string, len(entries))
	for _, entry := range entries {
		errorMessage, err := entry.Key.StringValue()
		if err != nil {
			return nil, fmt.Errorf("decodeErrors: failed to decode error key: %w", err)
		}

		ruleIds, err := decodeStringArray(&entry.Val)
		if err != nil {
			return nil, fmt.Errorf("decodeErrors: failed to decode rule IDs for error %q: %w", errorMessage, err)
		}

		wafErrors[errorMessage] = ruleIds
	}

	return wafErrors, nil
}

func decodeDiagnostics(obj *WAFObject) (Diagnostics, error) {
	if !obj.IsMap() {
		return Diagnostics{}, fmt.Errorf("decodeDiagnostics: %w: expected map, got %s", waferrors.ErrInvalidObjectType, obj.Type())
	}
	entries, err := obj.MapEntries()
	if err != nil {
		return Diagnostics{}, fmt.Errorf("decodeDiagnostics: failed to get map entries: %w", err)
	}

	var diags Diagnostics
	for _, entry := range entries {
		var handled bool
		handled, err = decodeKnownDiagnosticEntry(entry, &diags)
		if err != nil {
			return Diagnostics{}, err
		}
		if handled {
			continue
		}
		if _, err := entry.Key.StringValue(); err != nil {
			return Diagnostics{}, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
		}
	}

	return diags, nil
}

func decodeKnownDiagnosticEntry(entry WAFObjectKV, diags *Diagnostics) (bool, error) {
	match, err := keyMatches(&entry.Key, "actions")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "actions", err)
		}
		diags.Actions = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "custom_rules")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "custom_rules", err)
		}
		diags.CustomRules = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "exclusions")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "exclusions", err)
		}
		diags.Exclusions = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "rules")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "rules", err)
		}
		diags.Rules = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "rules_data")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "rules_data", err)
		}
		diags.RulesData = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "exclusion_data")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "exclusion_data", err)
		}
		diags.ExclusionData = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "rules_override")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "rules_override", err)
		}
		diags.RulesOverrides = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "processors")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "processors", err)
		}
		diags.Processors = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "processor_overrides")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "processor_overrides", err)
		}
		diags.ProcessorOverrides = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "scanners")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		feature, err := decodeFeature(&entry.Val)
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "scanners", err)
		}
		diags.Scanners = feature
		return true, nil
	}

	match, err = keyMatches(&entry.Key, "ruleset_version")
	if err != nil {
		return false, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
	}
	if match {
		version, err := entry.Val.StringValue()
		if err != nil {
			return false, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", "ruleset_version", err)
		}
		diags.Version = version
		return true, nil
	}

	return false, nil
}

func decodeFeature(obj *WAFObject) (*Feature, error) {
	if !obj.IsMap() {
		return nil, fmt.Errorf("decodeFeature: %w: expected map, got %s", waferrors.ErrInvalidObjectType, obj.Type())
	}
	entries, err := obj.MapEntries()
	if err != nil {
		return nil, fmt.Errorf("decodeFeature: failed to get map entries: %w", err)
	}

	var feature Feature
	for _, entry := range entries {
		key, err := entry.Key.StringValue()
		if err != nil {
			return nil, fmt.Errorf("decodeFeature: failed to decode key: %w", err)
		}

		switch key {
		case "error":
			feature.Error, err = entry.Val.StringValue()
		case "errors":
			feature.Errors, err = decodeErrors(&entry.Val)
		case "failed":
			feature.Failed, err = decodeStringArray(&entry.Val)
		case "loaded":
			feature.Loaded, err = decodeStringArray(&entry.Val)
		case "skipped":
			feature.Skipped, err = decodeStringArray(&entry.Val)
		case "warnings":
			feature.Warnings, err = decodeErrors(&entry.Val)
		default:
			return nil, fmt.Errorf("decodeFeature: %w: unknown field %q", waferrors.ErrUnsupportedValue, key)
		}

		if err != nil {
			return nil, fmt.Errorf("decodeFeature: failed to decode field %q: %w", key, err)
		}
	}

	return &feature, nil
}

func decodeStringArray(obj *WAFObject) ([]string, error) {
	if obj.IsNil() {
		return nil, nil
	}

	if !obj.IsArray() {
		return nil, fmt.Errorf("decodeStringArray: %w: expected array, got %s", waferrors.ErrInvalidObjectType, obj.Type())
	}
	items, err := obj.ArrayValues()
	if err != nil {
		return nil, fmt.Errorf("decodeStringArray: failed to get array values: %w", err)
	}

	if len(items) == 0 {
		return nil, nil
	}

	strArr := make([]string, 0, len(items))
	for i, item := range items {
		if !item.IsString() {
			return nil, fmt.Errorf("decodeStringArray: %w: expected string at index %d, got %s", waferrors.ErrInvalidObjectType, i, item.Type())
		}

		str, err := item.StringValue()
		if err != nil {
			return nil, fmt.Errorf("decodeStringArray: failed to decode string at index %d: %w", i, err)
		}
		strArr = append(strArr, str)
	}

	return strArr, nil
}

// DecodeObject decodes a [WAFObject] into a generic Go value.
//
// Deprecated: This is merely wrapping [WAFObject.AnyValue], which should be
// used directly instead.
func DecodeObject(obj *WAFObject) (any, error) {
	return obj.AnyValue()
}
