// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.25 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v4/timer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilder(t *testing.T) {
	if supported, err := Usable(); !supported || err != nil {
		t.Skipf("target is not supported by the WAF: %v", err)
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

	t.Run("recommended ruleset", func(t *testing.T) {
		builder, err := NewBuilder("", "")
		require.NoError(t, err)
		require.NotNil(t, builder)
		defer builder.Close()

		// The config is currently empty...
		require.Equal(t, []string{}, builder.ConfigPaths(""))
		handle := builder.Build()
		require.Nil(t, handle)

		// We can add the default recommended ruleset alright...
		diag, err := builder.AddDefaultRecommendedRuleset()
		require.NoError(t, err)
		assert.NotEmpty(t, diag.Version)
		assert.NotEmpty(t, diag.Rules.Loaded)

		// The default recommended ruleset is now indeed in there...
		require.Equal(t, []string{defaultRecommendedRulesetPath}, builder.ConfigPaths(""))

		// Adding again is idempotent...
		diag, err = builder.AddDefaultRecommendedRuleset()
		require.NoError(t, err)
		assert.NotEmpty(t, diag.Version)
		assert.NotEmpty(t, diag.Rules.Loaded)
		require.Equal(t, []string{defaultRecommendedRulesetPath}, builder.ConfigPaths(""))

		// We can actually build a handle with the default recommended ruleset...
		hdl := builder.Build()
		require.NotNil(t, hdl)
		hdl.Close()

		// And we can remove it...
		require.True(t, builder.RemoveDefaultRecommendedRuleset())
		require.Equal(t, []string{}, builder.ConfigPaths(""))
		hdl = builder.Build()
		require.Nil(t, hdl)

		// Removing it again is "idempotent" (almost, it returns false)
		require.False(t, builder.RemoveDefaultRecommendedRuleset())
		require.Equal(t, []string{}, builder.ConfigPaths(""))

		// Finally, we can add the default recommended ruleset again after deleting it...
		diag, err = builder.AddDefaultRecommendedRuleset()
		require.NoError(t, err)
		assert.NotEmpty(t, diag.Version)
		assert.NotEmpty(t, diag.Rules.Loaded)
		hdl = builder.Build()
		require.NotNil(t, hdl)
		hdl.Close()
	})

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
		require.Equal(t, Diagnostics{Rules: &Feature{Loaded: []string{"ua0-600-12x"}}}, diag)

		require.Equal(t, []string{"test/config"}, builder.ConfigPaths(""))
		handle = builder.Build()
		require.NotNil(t, handle)
		defer handle.Close()

		ctx, err := handle.NewContext(timer.WithBudget(timer.UnlimitedBudget))
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
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
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
		ctx, err = waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
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

	t.Run("DataDog/appsec-event-rules", func(t *testing.T) {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			t.Skip("GITHUB_TOKEN is not set, unable to access DataDog/appsec-event-rules releases")
		}

		req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/DataDog/appsec-event-rules/releases/latest", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var release struct {
			TagName string `json:"tag_name"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&release))

		req, err = http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/DataDog/appsec-event-rules/refs/tags/"+release.TagName+"/build/recommended.json", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var rules map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&rules))

		// Now that we have the rules, try them out...
		builder, err := NewBuilder("", "")
		require.NoError(t, err)
		defer builder.Close()

		diags, err := builder.AddOrUpdateConfig("/", rules)
		t.Logf("diags: %#v", diags)
		require.NoError(t, err)

		handle := builder.Build()
		require.NotNil(t, handle)
		handle.Close()
	})

	t.Run("blank-string-encoding", func(t *testing.T) {
		var rulesJSON = `{
			"version": "2.1",
			"metadata": {
				"rules_version": "1.2.6"
			},
			"rules": [
				{
					"id": "canary_rule4",
					"name": "Canary 4",
					"tags": {
						"type": "security_scanner",
						"category": "attack_attempt"
					},
					"conditions": [
						{
							"parameters": {
								"inputs": [
									{
										"address": "server.request.headers.no_cookies",
										"key_path": [
											"user-agent"
										]
									}
								],
								"regex": "^Canary\\/v4"
							},
							"operator": "match_regex"
						}
					],
					"on_match": [
						"block4"
					]
				}
			],
			"actions": [
				{
					"id": "block4",
					"type": "redirect_request",
					"parameters": {
						"status_code": 303,
						"location": ""
					}
				}
			]
		}
		`

		builder, err := NewBuilder("", "")
		require.NoError(t, err)

		dec := json.NewDecoder(bytes.NewReader([]byte(rulesJSON)))
		dec.UseNumber()

		var rules map[string]any
		require.NoError(t, dec.Decode(&rules))

		diag, err := builder.AddOrUpdateConfig("/", rules)
		require.NoError(t, err)
		diag.EachFeature(func(name string, feat *Feature) {
			assert.Empty(t, feat.Error, "feature %s has top-level error", name)
			assert.Empty(t, feat.Errors, "feature %s has errors", name)
			assert.Empty(t, feat.Warnings, "feature %s has warnings", name)
		})

		waf := builder.Build()
		require.NotNil(t, waf)
		defer waf.Close()

		ctx, err := waf.NewContext(timer.WithBudget(time.Hour))
		require.NoError(t, err)
		defer ctx.Close()

		res, err := ctx.Run(RunAddressData{
			Persistent: map[string]any{
				"server.request.headers.no_cookies": map[string][]string{
					"user-agent": {"Canary/v4 bazinga"},
				},
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, res.Events)
		assert.NotEmpty(t, res.Actions)
	})
}
