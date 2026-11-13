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

// mapEntries checks that obj is a map and returns its entries. The caller name
// prefixes the error texts.
func mapEntries(obj *WAFObject, caller string) ([]WAFObjectKV, error) {
	if !obj.IsMap() {
		return nil, fmt.Errorf("%s: %w: expected map, got %s", caller, waferrors.ErrInvalidObjectType, obj.Type())
	}
	entries, err := obj.MapEntries()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get map entries: %w", caller, err)
	}
	return entries, nil
}

func decodeDiagnostics(obj *WAFObject) (Diagnostics, error) {
	entries, err := mapEntries(obj, "decodeDiagnostics")
	if err != nil {
		return Diagnostics{}, err
	}

	var diags Diagnostics
	for i := range entries {
		entry := &entries[i]
		key, err := entry.Key.StringValue()
		if err != nil {
			return Diagnostics{}, fmt.Errorf("decodeDiagnostics: failed to decode diagnostics key: %w", err)
		}

		if err := decodeDiagnosticsEntry(&diags, key, &entry.Val); err != nil {
			return Diagnostics{}, fmt.Errorf("decodeDiagnostics: failed to decode feature %q: %w", key, err)
		}
	}

	return diags, nil
}

// decodeDiagnosticsEntry decodes one top-level diagnostics entry into diags.
// The keys are split over this function and decodeOtherDiagnosticsFeature to
// keep each switch small. Both use direct calls, which let escape analysis
// keep diags on the stack.
func decodeDiagnosticsEntry(diags *Diagnostics, key string, val *WAFObject) (err error) {
	switch key {
	case "rules":
		diags.Rules, err = decodeFeature(val)
	case "custom_rules":
		diags.CustomRules, err = decodeFeature(val)
	case "rules_data":
		diags.RulesData, err = decodeFeature(val)
	case "rules_override":
		diags.RulesOverrides, err = decodeFeature(val)
	case "actions":
		diags.Actions, err = decodeFeature(val)
	case "ruleset_version":
		diags.Version, err = val.StringValue()
	default:
		err = decodeOtherDiagnosticsFeature(diags, key, val)
	}
	return err
}

// decodeOtherDiagnosticsFeature decodes the diagnostics entries that
// decodeDiagnosticsEntry does not handle.
func decodeOtherDiagnosticsFeature(diags *Diagnostics, key string, val *WAFObject) (err error) {
	switch key {
	case "exclusions":
		diags.Exclusions, err = decodeFeature(val)
	case "exclusion_data":
		diags.ExclusionData, err = decodeFeature(val)
	case "processors":
		diags.Processors, err = decodeFeature(val)
	case "processor_overrides":
		diags.ProcessorOverrides, err = decodeFeature(val)
	case "scanners":
		diags.Scanners, err = decodeFeature(val)
	default:
		// Unknown diagnostic keys are intentionally ignored so newer libddwaf
		// versions don't break this decoder.
	}
	return err
}

func decodeFeature(obj *WAFObject) (*Feature, error) {
	entries, err := mapEntries(obj, "decodeFeature")
	if err != nil {
		return nil, err
	}
	return decodeFeatureEntries(entries)
}

// decodeFeatureEntries decodes the fields of one feature. It has no helper per
// field on purpose: this loop runs for every field of every feature, and one
// more call for each field makes the decoding slower.
func decodeFeatureEntries(entries []WAFObjectKV) (*Feature, error) {
	var feature Feature
	for i := range entries {
		entry := &entries[i]
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
			// Unknown feature fields are intentionally ignored so newer
			// libddwaf versions can add per-feature diagnostic fields without
			// breaking config loading, mirroring decodeDiagnostics' handling
			// of unknown top-level keys.
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
