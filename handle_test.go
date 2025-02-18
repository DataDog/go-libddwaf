// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.25 && !datadog.no_waf && (cgo || appsec)

package waf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHandle(t *testing.T) {
	if supported, err := Health(); !supported || err != nil {
		t.Skip("target is not supported by the WAF")
		return
	}

	t.Run("accepts the valid ruleset", func(t *testing.T) {
		rules := makeValidRuleset()
		waf, err := NewHandle(rules, "", "")
		require.NoError(t, err)
		require.NotNil(t, waf)
		waf.Close()
	})

	t.Run("successfully loads a ruleset that uses a 'new' operator", func(t *testing.T) {
		ruleId := "new-operator-rule"
		newOperator := "made_up_operator_which_does_not_exist_and_never_will_exist"

		rules := appendRule(
			makeValidRuleset(),
			map[string]any{
				"id":   ruleId,
				"name": "Rule with 'new' operator",
				"tags": map[string]any{
					"type":     "phony",
					"category": "new-operator",
				},
				"conditions": []any{
					map[string]any{
						"parameters": map[string]any{
							"inputs": []any{
								map[string]any{
									"address": "http.client_ip",
								},
							},
						},
						"operator": newOperator,
					},
				},
				"transformers": []string{},
				"on_match": []string{
					"block",
				},
			},
		)
		waf, err := NewHandle(rules, "", "")
		require.NoError(t, err)
		require.NotNil(t, waf)
		defer waf.Close()

		wafDiags := waf.Diagnostics()
		require.Contains(t, wafDiags.Rules.Failed, ruleId)
		require.Contains(t, wafDiags.Rules.Errors[fmt.Sprintf("unknown matcher: %s", newOperator)], ruleId)
	})

	t.Run("does not return error on partially invalid input", func(t *testing.T) {
		for _, field := range []string{
			"custom_rules",
			"exclusions",
			"rules",
			"rules_data",
			"rules_override",
			"processors",
			"scanners",
		} {
			t.Run(field, func(t *testing.T) {
				// Start off with a perfectly valid input...
				rules := makeValidRuleset()
				// And corrupt data for one particular field...
				rules[field] = 1337.42

				// Now ensure the WAF init does not err out (at least 1 rule is valid in this scenario)
				waf, err := NewHandle(rules, "", "")
				require.NoError(t, err)
				require.NotNil(t, waf)
				waf.Close()
			})
		}
	})

}

// makeValidRuleset returns a "valid" ruleset that is expected to cleanly parse and load into the WAF.
func makeValidRuleset() map[string]any {
	return map[string]any{
		"version": "2.2",
		"metadata": map[string]string{
			"rules_version": "0.0.1-test.0",
		},
		"custom_rules": []map[string]any{
			{
				"id":   "blk-001-001-custom",
				"name": "Block IP Addresses",
				"tags": map[string]any{
					"type":     "block_ip",
					"category": "security_response",
				},
				"conditions": []any{
					map[string]any{
						"parameters": map[string]any{
							"inputs": []any{
								map[string]any{
									"address": "http.client_ip",
								},
							},
							"data": "blocked_ips",
						},
						"operator": "ip_match",
					},
				},
				"transformers": []string{},
				"on_match": []string{
					"block",
				},
			},
		},
		"exclusions": []map[string]any{},
		"rules": []map[string]any{
			{
				"id":   "blk-001-001",
				"name": "Block IP Addresses",
				"tags": map[string]any{
					"type":     "block_ip",
					"category": "security_response",
				},
				"conditions": []any{
					map[string]any{
						"parameters": map[string]any{
							"inputs": []any{
								map[string]any{
									"address": "http.client_ip",
								},
							},
							"data": "blocked_ips",
						},
						"operator": "ip_match",
					},
				},
				"transformers": []string{},
				"on_match": []string{
					"block",
				},
			},
		},
		"rules_data":     []map[string]any{},
		"rules_override": []map[string]any{},
		"processors":     []map[string]any{},
		"scanners":       []map[string]any{},
	}
}

func appendRule(ruleset map[string]any, rule map[string]any) map[string]any {
	var rules []map[string]any
	if prop, found := ruleset["rules"]; found {
		rules = prop.([]map[string]any)
	} else {
		rules = make([]map[string]any, 1)
	}

	ruleset["rules"] = append(rules, rule)

	return ruleset
}
