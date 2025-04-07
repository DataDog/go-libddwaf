// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.25 && !datadog.no_waf && (cgo || appsec)

package waf

import (
	"maps"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/stretchr/testify/require"
)

func TestBuilder(t *testing.T) {
	if supported, err := Health(); !supported || err != nil {
		t.Skipf("target is not supported by the WAF: %v", err)
		return
	}

	validRule := map[string]any{
		"id":   "ua0-600-12x",
		"name": "Arachni",
		"tags": map[string]any{
			"type":     "security_scanner",
			"category": "attack_attempt",
		},
		"conditions": []map[string]any{
			{
				"operator": "match_regex",
				"parameters": map[string]any{
					"inputs": []map[string]any{
						{"address": "server.request.headers.no_cookies"},
					},
					"regex": "^Arachni",
				},
			},
		},
	}

	t.Run("accepts a valid ruleset", func(t *testing.T) {
		builder, err := NewBuilder("", "")
		require.NoError(t, err)
		require.NotNil(t, builder)
		defer builder.Close()

		// The config is currently empty...
		require.Equal(t, []string{}, builder.ConfigPaths(""))
		handle := builder.Build()
		require.Nil(t, handle)

		// Let's add some configuration now...
		rules := map[string]any{
			"version": "2.1",
			"rules":   []map[string]any{validRule},
		}
		diag, err := builder.AddOrUpdateConfig("test/config", rules)
		require.NoError(t, err)
		require.Equal(t, Diagnostics{Rules: &DiagnosticEntry{Loaded: []string{"ua0-600-12x"}}}, diag)

		require.Equal(t, []string{"test/config"}, builder.ConfigPaths(""))
		handle = builder.Build()
		require.NotNil(t, handle)
		defer handle.Close()

		ctx, err := handle.NewContextWithBudget(timer.UnlimitedBudget)
		require.NoError(t, err)
		require.NotNil(t, ctx)
		defer ctx.Close()

		res, err := ctx.Run(RunAddressData{Persistent: map[string]any{"server.request.headers.no_cookies": []string{"Arachni/v1"}}})
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
	})

	t.Run("accepts (and ignores) an unknown operator", func(t *testing.T) {
		builder, err := NewBuilder("", "")
		require.NoError(t, err)
		require.NotNil(t, builder)

		const (
			ruleId      = "new-operator-rule"
			newOperator = "made_up_operator_which_does_not_exist_and_never_will_exist"
		)

		rules := map[string]any{
			"version": "2.1",
			"rules": []map[string]any{
				validRule,
				{
					"id":   ruleId,
					"name": "Rule with 'new' operator",
					"tags": map[string]any{
						"type":     "phony",
						"category": "new-operator",
					},
					"conditions": []map[string]any{
						{
							"parameters": map[string]any{
								"inputs": []map[string]any{
									{"address": "http.client_ip"},
								},
							},
							"operator": newOperator,
						},
					},
					"transformers": []string{},
					"on_match":     []string{"block"},
				},
			},
		}
		diag, err := builder.AddOrUpdateConfig("/", rules)
		require.NoError(t, err)
		require.Contains(t, diag.Rules.Failed, ruleId)
		require.Equal(t, diag.Rules.Warnings, map[string][]string{"unknown operator: '" + newOperator + "'": {ruleId}})
	})

	t.Run("accepts partially invalid input", func(t *testing.T) {
		for _, field := range []string{
			"custom_rules",
			"exclusions",
			"rules",
			"rules_data",
			"rules_override",
			"processors",
			"scanners",
		} {
			builder, err := NewBuilder("", "")
			require.NoError(t, err)
			require.NotNil(t, builder)
			_, err = builder.AddOrUpdateConfig("/", map[string]any{
				"version": "2.1",
				"rules":   []map[string]any{maps.Clone(validRule)},
			})
			require.NoError(t, err)

			t.Run(field, func(t *testing.T) {
				// Build up a fragment with the invalid field value...
				rules := map[string]any{"version": "2.1", field: 1337.42}
				// The builder will reject the broken update...
				_, err := builder.AddOrUpdateConfig("/broken", rules)
				require.ErrorIs(t, err, errUpdateFailed)
				// ... but we can still obtain a valid handle since there is 1 valid rule...
				waf := builder.Build()
				require.NotNil(t, waf)
				waf.Close()
			})
		}
	})

	t.Run("updating rules", func(t *testing.T) {
		runData := RunAddressData{
			Persistent: map[string]any{"my.input": "Arachni"},
			Ephemeral:  map[string]any{"safe": true},
		}

		builder, err := NewBuilder("", "")
		require.NoError(t, err)

		_, err = builder.AddOrUpdateConfig("/", map[string]any{
			"version": "2.1",
			"rules": []map[string]any{
				{
					"id":   "ua0-600-12x",
					"name": "Arachni",
					"tags": map[string]any{
						"type":     "security_scanner",
						"category": "attack_attempt",
					},
					"conditions": []map[string]any{
						{
							"operator": "match_regex",
							"parameters": map[string]any{
								"inputs": []map[string]any{
									{"address": "my.input"},
								},
								"regex": "^Arachni",
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)

		// Check with the original, non-blocking rules
		waf := builder.Build()
		require.NotNil(t, waf)
		defer waf.Close()
		ctx, err := waf.NewContextWithBudget(timer.UnlimitedBudget)
		require.NoError(t, err)
		require.NotNil(t, ctx)
		defer ctx.Close()
		res, err := ctx.Run(runData)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
		require.Empty(t, res.Actions)

		// Update the rules to block
		_, err = builder.AddOrUpdateConfig("/", map[string]any{
			"version": "2.1",
			"rules": []map[string]any{
				{
					"id":   "ua0-600-12x",
					"name": "Arachni",
					"tags": map[string]any{
						"type":     "security_scanner",
						"category": "attack_attempt",
					},
					"conditions": []map[string]any{
						{
							"operator": "match_regex",
							"parameters": map[string]any{
								"inputs": []map[string]any{
									{"address": "my.input"},
								},
								"regex": "^Arachni",
							},
						},
					},
					"on_match": []string{"block"},
				},
			},
		})
		require.NoError(t, err)

		// Check with the updated, blocking rules
		waf = builder.Build()
		require.NotNil(t, waf)
		defer waf.Close()
		ctx, err = waf.NewContextWithBudget(timer.UnlimitedBudget)
		require.NoError(t, err)
		require.NotNil(t, ctx)
		defer ctx.Close()
		res, err = ctx.Run(runData)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
		require.Equal(t,
			map[string]any{"block_request": map[string]any{
				"grpc_status_code": "10",
				"status_code":      "403",
				"type":             "auto",
			}},
			res.Actions,
		)
	})
}
