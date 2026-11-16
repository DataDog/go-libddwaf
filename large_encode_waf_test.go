// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/timer"
)

// These tests send containers with more than 65,535 items to the real
// libddwaf library, in a config and in run data.
//
// Rule F (fresh contexts). libddwaf does not report a rule again in a context
// after it matched, and a subcontext shares the rule cache of its parent. So
// each match check uses a new context from the handle, and each subcontext case
// uses a new parent context. One handle for each configuration is fine. The only
// exception is TestLargeRunInputRetained, whose 2 runs depend on each other.

const largeWAFItems = 70_000 // More than math.MaxUint16

// largeIP returns the IP address of entry i. It is unique for i < 2^24.
func largeIP(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xff, i&0xff) }

func newLargeContext(t *testing.T, handle *Handle) *Context {
	t.Helper()
	ctx, err := handle.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	t.Cleanup(ctx.Close)
	return ctx
}

func eventsJSON(t *testing.T, res Result) string {
	t.Helper()
	b, err := json.Marshal(res.Events)
	require.NoError(t, err)
	return string(b)
}

// TestLargeRuleDataConfig sends rule data with 65,535 to 70,000 entries through
// Builder.AddOrUpdateConfig. Before large containers were encoded, the entries
// after the 65,535th were silently dropped.
func TestLargeRuleDataConfig(t *testing.T) {
	for _, n := range []int{65_535, 65_536, 70_000} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			data := make([]any, n)
			for i := range data {
				data[i] = map[string]any{"value": largeIP(i)}
			}
			config := map[string]any{
				"version": "2.1",
				"rules": []any{map[string]any{
					"id":   "blk-test",
					"name": "Block IP addresses",
					"tags": map[string]any{"type": "block_ip", "category": "security_response"},
					"conditions": []any{map[string]any{
						"operator": "ip_match",
						"parameters": map[string]any{
							"inputs": []any{map[string]any{"address": "http.client_ip"}},
							"data":   "blocked_ips",
						},
					}},
				}},
				"rules_data": []any{map[string]any{"id": "blocked_ips", "type": "ip_with_expiration", "data": data}},
			}

			builder, err := NewBuilder()
			require.NoError(t, err)
			t.Cleanup(builder.Close)
			diag, err := builder.AddOrUpdateConfig("/large", config)
			require.NoError(t, err)
			require.NotNil(t, diag.RulesData)
			require.Contains(t, diag.RulesData.Loaded, "blocked_ips")
			handle, err := builder.Build()
			require.NoError(t, err)
			t.Cleanup(handle.Close)

			check := func(t *testing.T, ip string) Result {
				ctx := newLargeContext(t, handle)
				res, err := ctx.Run(context.Background(), RunAddressData{Data: map[string]any{"http.client_ip": ip}})
				require.NoError(t, err)
				return res
			}
			t.Run("last", func(t *testing.T) {
				res := check(t, largeIP(n-1))
				require.True(t, res.HasEvents(), "last entry must match")
			})
			t.Run("first", func(t *testing.T) {
				res := check(t, largeIP(0))
				require.True(t, res.HasEvents(), "first entry must match")
			})
			t.Run("unlisted", func(t *testing.T) {
				res := check(t, "192.0.2.1")
				require.False(t, res.HasEvents(), "an address that is not listed must not match")
			})
		})
	}
}

// largeArrayInput is a run input with n strings. The string at index matchAt is
// "Arachni-<i>"; with matchAt < 0, no item matches.
//
// Encode returns the errors of the setters. The test must not call
// require.NoError in here: the failure would occur before the match asserts
// that name the missing feature, and a failed encoding would look like a bug of
// the fixture.
type largeArrayInput struct {
	n       int
	matchAt int
}

func (in largeArrayInput) Encode(enc *Encoder, obj *WAFObject, _ int) error {
	items := make([]WAFObject, in.n)
	for i := range items {
		value := fmt.Sprintf("safe-value-%d", i)
		if i == in.matchAt {
			value = fmt.Sprintf("Arachni-%d", i)
		}
		enc.WriteString(&items[i], value)
	}
	return obj.SetArrayData(enc.Config.Pinner, items)
}

// largeMapInput is the map version of largeArrayInput: the key of item i is "k<i>".
type largeMapInput struct {
	n       int
	matchAt int
}

func (in largeMapInput) Encode(enc *Encoder, obj *WAFObject, _ int) error {
	entries := make([]WAFObjectKV, in.n)
	for i := range entries {
		value := fmt.Sprintf("safe-value-%d", i)
		if i == in.matchAt {
			value = fmt.Sprintf("Arachni-%d", i)
		}
		enc.WriteString(&entries[i].Key, fmt.Sprintf("k%d", i))
		enc.WriteString(&entries[i].Val, value)
	}
	return obj.SetMapData(enc.Config.Pinner, entries)
}

// TestLargeRunInput sends a run input with 70,000 items, built with
// SetArrayData / SetMapData, to Context.Run and Subcontext.Run.
func TestLargeRunInput(t *testing.T) {
	handle, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(handle.Close)

	for _, kind := range []string{"array", "map"} {
		for _, path := range []string{"context", "subcontext"} {
			for _, match := range []bool{true, false} {
				name := "no-match"
				matchAt := -1
				if match {
					name, matchAt = "match", largeWAFItems-1
				}
				t.Run(fmt.Sprintf("%s/%s/%s", kind, path, name), func(t *testing.T) {
					var input Encodable = largeArrayInput{n: largeWAFItems, matchAt: matchAt}
					if kind == "map" {
						input = largeMapInput{n: largeWAFItems, matchAt: matchAt}
					}

					// A new context for this check, and a new parent for a subcontext.
					ctx := newLargeContext(t, handle)
					var runner Runner = ctx
					if path == "subcontext" {
						sub, err := ctx.NewSubcontext(context.Background())
						require.NoError(t, err)
						t.Cleanup(sub.Close)
						runner = sub
					}

					res, err := runner.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": input}})
					require.NoError(t, err)
					if !match {
						require.False(t, res.HasEvents(), "an input with no Arachni item must not match")
						return
					}
					require.Len(t, res.Events, 1, "item 69,999 must match")
					require.Contains(t, eventsJSON(t, res), fmt.Sprintf("Arachni-%d", largeWAFItems-1), "item 69,999 must match")
				})
			}
		}
	}
}

// retainedRule has 2 conditions, in this order: libddwaf stops at the first
// condition that fails. So a run with no my.trigger never reads my.input, and
// the first read of my.input is in a later run, from the object store.
func retainedRule() map[string]any {
	return map[string]any{
		"version": "2.1",
		"rules": []any{map[string]any{
			"id":   "retained-input",
			"name": "Retained input",
			"tags": map[string]any{"type": "security_scanner", "category": "attack_attempt"},
			"conditions": []any{
				map[string]any{"operator": "match_regex", "parameters": map[string]any{
					"inputs": []any{map[string]any{"address": "my.trigger"}}, "regex": "^go$",
				}},
				map[string]any{"operator": "match_regex", "parameters": map[string]any{
					"inputs": []any{map[string]any{"address": "my.input"}}, "regex": "^Arachni-match",
				}},
			},
			"transformers": []any{},
		}},
	}
}

// retainedInput is the input of run 1. Its strings are more than 14 bytes long,
// so that none is stored inline in the object, and are made at run time.
type retainedInput struct{ asMap bool }

func (in retainedInput) item(i int) string {
	if i == largeWAFItems-1 {
		return fmt.Sprintf("Arachni-match-%08d", i)
	}
	return fmt.Sprintf("safe-value-%08d", i)
}

func (in retainedInput) Encode(enc *Encoder, obj *WAFObject, _ int) error {
	if in.asMap {
		entries := make([]WAFObjectKV, largeWAFItems)
		for i := range entries {
			enc.WriteString(&entries[i].Key, fmt.Sprintf("key-%08d", i))
			enc.WriteString(&entries[i].Val, in.item(i))
		}
		return obj.SetMapData(enc.Config.Pinner, entries)
	}
	items := make([]WAFObject, largeWAFItems)
	for i := range items {
		enc.WriteString(&items[i], in.item(i))
	}
	return obj.SetArrayData(enc.Config.Pinner, items)
}

// runRetainedInput is a separate function, so that the test keeps no reference
// to the input after the run.
//
//go:noinline
func runRetainedInput(t *testing.T, runner Runner, asMap bool) {
	t.Helper()
	res, err := runner.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": retainedInput{asMap: asMap}}})
	require.NoError(t, err)
	require.False(t, res.HasEvents(), "run 1 has no my.trigger, so it must not match")
}

// TestLargeRunInputRetained is a retained-input regression test, plus an
// ownership review. It is not a proof of memory reuse.
//
// libddwaf keeps views of the run data (not copies) until the context closes,
// so run 2 reads the Go memory of run 1. Run 1 sends 70,000 items and no
// trigger, so that nothing reads them. Then the test drops every reference,
// runs the GC, and allocates replacement buffers with the same sizes as the
// freed objects (the strings and the container backing array). It keeps them
// alive until run 2 ends. A GC and a same-size allocation do not prove that
// libddwaf would read reused memory: the Go allocator can place the buffers
// elsewhere. The test does show that the item still matches in run 2 when the
// memory is under pressure, and the pinner in the context
// (context.go, subcontext.go) is what keeps it alive.
//
// Exception to rule F: the 2 runs of a case depend on each other, so they use
// the SAME context (or the same subcontext). Each case has its own new context,
// and its own new parent context for the subcontext cases.
func TestLargeRunInputRetained(t *testing.T) {
	handle, _, err := newDefaultHandle(t, retainedRule())
	require.NoError(t, err)
	t.Cleanup(handle.Close)

	for _, kind := range []string{"array", "map"} {
		for _, path := range []string{"context", "subcontext"} {
			t.Run(kind+"/"+path, func(t *testing.T) {
				asMap := kind == "map"
				ctx := newLargeContext(t, handle)
				var runner Runner = ctx
				if path == "subcontext" {
					sub, err := ctx.NewSubcontext(context.Background())
					require.NoError(t, err)
					t.Cleanup(sub.Close)
					runner = sub
				}

				runRetainedInput(t, runner, asMap)

				runtime.GC()
				runtime.GC()
				debug.FreeOSMemory()

				// Replacement buffers: same sizes as the freed objects.
				fill := func(b []byte) []byte {
					for i := range b {
						b[i] = 0xAA
					}
					return b
				}
				var replacement [][]byte
				for i := range largeWAFItems {
					size := len(retainedInput{}.item(i))
					replacement = append(replacement, fill(make([]byte, size)))
					if asMap {
						replacement = append(replacement, fill(make([]byte, len(fmt.Sprintf("key-%08d", i)))))
					}
				}
				itemSize, kvSize := 16, 32 // sizeof(ddwaf_object), sizeof(ddwaf_object_kv)
				if asMap {
					itemSize = kvSize
				}
				replacement = append(replacement, fill(make([]byte, largeWAFItems*itemSize)))
				// Allocate more, so that the GC runs while the buffers are live.
				runtime.GC()

				res, err := runner.Run(context.Background(), RunAddressData{Data: map[string]any{"my.trigger": "go"}})
				require.NoError(t, err)
				require.Len(t, res.Events, 1, "retained item must match in run 2")
				require.Contains(t, eventsJSON(t, res), fmt.Sprintf("Arachni-match-%08d", largeWAFItems-1), "retained item must match in run 2")

				runtime.KeepAlive(replacement)
			})
		}
	}
}

// TestTruncationsUnchanged checks that the run limits (256 items, 4,096 bytes,
// depth 20) and the truncation reports are the same as before large containers
// were encoded. The expected values were taken from the code before this
// change, and must be the same after it.
func TestTruncationsUnchanged(t *testing.T) {
	handle, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(handle.Close)

	nested := func(depth int) any {
		var v any = "leaf"
		for range depth {
			v = map[string]any{"k": v}
		}
		return v
	}

	for _, tc := range []struct {
		name  string
		input any
		want  Truncations
	}{
		{"items=256", make([]bool, 256), Truncations{}},
		{"items=257", make([]bool, 257), Truncations{ContainerTooLarge: []int{257}}},
		{"items=70000", make([]bool, largeWAFItems), Truncations{ContainerTooLarge: []int{largeWAFItems}}},
		{"string=4096", strings.Repeat("a", 4096), Truncations{}},
		{"string=4097", strings.Repeat("a", 4097), Truncations{StringTooLong: []int{4097}}},
		{"depth=20", nested(19), Truncations{}},
		{"depth=21", nested(20), Truncations{ObjectTooDeep: []int{21}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newLargeContext(t, handle)
			_, err := ctx.Run(context.Background(), RunAddressData{Data: map[string]any{"my.input": tc.input}})
			require.NoError(t, err)
			require.Equal(t, tc.want, ctx.Truncations())
		})
	}
}
