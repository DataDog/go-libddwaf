// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHandle(t *testing.T) {
	if supported, err := supportsTarget(); !supported || err != nil {
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

	t.Run("rejects invalid WAF input", func(t *testing.T) {
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

				// Now ensure the WAF init rejects it appropriately
				waf, err := NewHandle(rules, "", "")
				require.Error(t, err)
				require.Equal(t, fmt.Sprintf("the WAF reported a top-level error: in %#v: bad cast, expected 'array', obtained 'float'", field), err.Error())
				if waf != nil {
					waf.Close()
				}
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
