// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package bindings

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/lib"
)

// These tests run the code paths that turn C addresses into Go pointers
// ([WAFLib.Version] and [WAFLib.knownX]), so that "go test -race" (checkptr)
// and GOEXPERIMENT=cgocheck2 check them.

func loadForTest(t *testing.T) {
	t.Helper()
	ok, err := Load()
	require.NoError(t, err)
	require.True(t, ok)
}

// newKnownXTestHandle builds a WAF handle that has one rule with the inputs
// "my.first.input" and "my.second.input". When onMatch is not empty, the rule
// also has this action in "on_match". The handle is destroyed when the test
// ends. Each cleanup is registered before the assertion that can stop the test.
func newKnownXTestHandle(t *testing.T, onMatch string) WAFHandle {
	t.Helper()
	loadForTest(t)

	onMatchJSON := ""
	if onMatch != "" {
		onMatchJSON = fmt.Sprintf(`, "on_match": [%q]`, onMatch)
	}
	rules := fmt.Appendf(nil, `{
		"version": "2.1",
		"rules": [{
			"id": "known-x-test",
			"name": "known-x-test",
			"tags": {"type": "security_scanner", "category": "attack_attempt"},
			"conditions": [{
				"operator": "match_regex",
				"parameters": {
					"inputs": [{"address": "my.first.input"}, {"address": "my.second.input"}],
					"regex": "^Arachni"
				}
			}],
			"transformers": []%s
		}]
	}`, onMatchJSON)

	alloc := Lib.DefaultAllocator()

	cfg, ok := Lib.ObjectFromJSON(rules, alloc)
	defer Lib.ObjectDestroy(&cfg, alloc)
	require.True(t, ok)

	builder := Lib.BuilderInit()
	defer func() {
		if builder != 0 {
			Lib.BuilderDestroy(builder)
		}
	}()
	require.NotZero(t, builder)

	var diags WAFObject
	defer Lib.ObjectDestroy(&diags, alloc)
	require.True(t, Lib.BuilderAddOrUpdateConfig(builder, "/known-x-test", &cfg, &diags))

	handle := Lib.BuilderBuildInstance(builder)
	t.Cleanup(func() {
		if handle != 0 {
			Lib.Destroy(handle)
		}
	})
	require.NotZero(t, handle)

	return handle
}

func TestWAFLibVersion(t *testing.T) {
	loadForTest(t)
	require.Equal(t, lib.EmbeddedWAFVersion, Lib.Version())
}

func TestWAFLibKnownX(t *testing.T) {
	expectedAddresses := []string{"my.first.input", "my.second.input"}

	t.Run("with-actions", func(t *testing.T) {
		handle := newKnownXTestHandle(t, "block")
		// ddwaf.h does not promise an order, so only compare the content.
		require.ElementsMatch(t, expectedAddresses, Lib.KnownAddresses(handle))
		require.Equal(t, []string{"block_request"}, Lib.KnownActions(handle))
	})

	t.Run("no-actions", func(t *testing.T) {
		handle := newKnownXTestHandle(t, "")
		require.ElementsMatch(t, expectedAddresses, Lib.KnownAddresses(handle))
		// No action: knownX returns nil (empty branch).
		require.Nil(t, Lib.KnownActions(handle))
	})
}
