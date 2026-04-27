// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/internal/invariant"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireConfigPaths(t *testing.T, b *Builder, filter string, expected []string) {
	t.Helper()
	paths, err := b.ConfigPaths(filter)
	require.NoError(t, err)
	require.Equal(t, expected, paths)
}

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
		builder, err := NewBuilder()
		require.NoError(t, err)
		require.NotNil(t, builder)
		defer builder.Close()

		requireConfigPaths(t, builder, "", []string{})
		handle := builder.Build()
		require.Nil(t, handle)

		diag, err := builder.AddDefaultRecommendedRuleset()
		require.NoError(t, err)
		assert.NotEmpty(t, diag.Version)
		assert.NotEmpty(t, diag.Rules.Loaded)

		requireConfigPaths(t, builder, "", []string{defaultRecommendedRulesetPath})

		diag, err = builder.AddDefaultRecommendedRuleset()
		require.NoError(t, err)
		assert.NotEmpty(t, diag.Version)
		assert.NotEmpty(t, diag.Rules.Loaded)
		requireConfigPaths(t, builder, "", []string{defaultRecommendedRulesetPath})

		hdl := builder.Build()
		require.NotNil(t, hdl)
		hdl.Close()

		require.True(t, builder.RemoveDefaultRecommendedRuleset())
		requireConfigPaths(t, builder, "", []string{})
		hdl = builder.Build()
		require.Nil(t, hdl)

		require.False(t, builder.RemoveDefaultRecommendedRuleset())
		requireConfigPaths(t, builder, "", []string{})

		diag, err = builder.AddDefaultRecommendedRuleset()
		require.NoError(t, err)
		assert.NotEmpty(t, diag.Version)
		assert.NotEmpty(t, diag.Rules.Loaded)
		hdl = builder.Build()
		require.NotNil(t, hdl)
		hdl.Close()
	})

	t.Run("accepts a valid ruleset", func(t *testing.T) {
		builder, err := NewBuilder()
		require.NoError(t, err)
		require.NotNil(t, builder)
		defer builder.Close()

		requireConfigPaths(t, builder, "", []string{})
		handle := builder.Build()
		require.Nil(t, handle)

		rules := map[string]any{
			"version": "2.1",
			"rules":   []map[string]any{validRule},
		}
		diag, err := builder.AddOrUpdateConfig("test/config", rules)
		require.NoError(t, err)
		require.Equal(t, Diagnostics{Rules: &Feature{Loaded: []string{"ua0-600-12x"}}}, diag)

		requireConfigPaths(t, builder, "", []string{"test/config"})
		handle = builder.Build()
		require.NotNil(t, handle)
		defer handle.Close()

		ctx, err := handle.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, ctx)
		defer ctx.Close()

		res, err := ctx.Run(context.Background(), RunAddressData{Data: map[string]any{"server.request.headers.no_cookies": []string{"Arachni/v1"}}})
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
	})

	t.Run("accepts (and ignores) an unknown operator", func(t *testing.T) {
		builder, err := NewBuilder()
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
			builder, err := NewBuilder()
			require.NoError(t, err)
			require.NotNil(t, builder)
			_, err = builder.AddOrUpdateConfig("/", map[string]any{
				"version": "2.1",
				"rules":   []map[string]any{maps.Clone(validRule)},
			})
			require.NoError(t, err)

			t.Run(field, func(t *testing.T) {
				rules := map[string]any{"version": "2.1", field: 1337.42}
				_, err := builder.AddOrUpdateConfig("/broken", rules)
				require.ErrorIs(t, err, errUpdateFailed)
				waf := builder.Build()
				require.NotNil(t, waf)
				waf.Close()
			})
		}
	})

	t.Run("updating rules", func(t *testing.T) {
		runData := RunAddressData{
			Data: map[string]any{"my.input": "Arachni"},
		}

		builder, err := NewBuilder()
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

		waf := builder.Build()
		require.NotNil(t, waf)
		defer waf.Close()
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, ctx)
		defer ctx.Close()
		res, err := ctx.Run(context.Background(), runData)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
		require.Empty(t, res.Actions)

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

		waf = builder.Build()
		require.NotNil(t, waf)
		defer waf.Close()
		ctx, err = waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, ctx)
		defer ctx.Close()
		res, err = ctx.Run(context.Background(), runData)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)

		action, _ := res.Actions["block_request"].(map[string]any)
		require.NotNil(t, action)
		require.Equal(t, action["grpc_status_code"], uint64(10))
		require.Equal(t, action["status_code"], uint64(403))
		require.Equal(t, action["type"], "auto")
		require.NotEmpty(t, action["security_response_id"])
	})

	t.Run("DataDog/appsec-event-rules", func(t *testing.T) {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			builder, err := NewBuilder()
			require.NoError(t, err)
			defer builder.Close()

			diags, err := builder.AddDefaultRecommendedRuleset()
			require.NoError(t, err)
			t.Logf("diags (bundled ruleset): %#v", diags)

			handle := builder.Build()
			require.NotNil(t, handle)
			handle.Close()
			return
		}

		req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/DataDog/appsec-event-rules/releases/latest", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "failed to get latest release of DataDog/appsec-event-rules: %s", resp.Status)

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

		builder, err := NewBuilder()
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

		builder, err := NewBuilder()
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

		res, err := ctx.Run(context.Background(), RunAddressData{
			Data: map[string]any{
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

func TestBuilderConcurrentUsePanics(t *testing.T) {
	if !invariant.Active() {
		t.Skip("requires -tags=ci to verify concurrent-use detection")
	}
	if supported, err := Usable(); !supported || err != nil {
		t.Skipf("target is not supported by the WAF: %v", err)
	}

	builder, err := NewBuilder()
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()

	var wg sync.WaitGroup
	barrier := make(chan struct{})
	panicked := make(chan bool, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicked <- true
				}
			}()
			<-barrier
			builder.acquire()
			time.Sleep(10 * time.Millisecond)
			builder.release()
		}()
	}

	close(barrier)
	wg.Wait()
	close(panicked)

	count := 0
	for range panicked {
		count++
	}
	if count == 0 {
		t.Fatal("expected at least one panic for concurrent use")
	}
}

func TestBuilderSequentialUseOK(t *testing.T) {
	if supported, err := Usable(); !supported || err != nil {
		t.Skipf("target is not supported by the WAF: %v", err)
	}

	builder, err := NewBuilder()
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()

	builder.acquire()
	builder.release()
	builder.acquire()
	builder.release()
}
