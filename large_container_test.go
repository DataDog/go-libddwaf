// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
)

const largeContainerItems = 70_000 // More than math.MaxUint16

// jsonList returns `item(0),item(1),...,item(n-1)`.
func jsonList(n int, item func(i int) string) string {
	var sb strings.Builder
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(item(i))
	}
	return sb.String()
}

// largeObjectFromJSON parses the JSON with libddwaf itself, so that the objects
// have the exact layout that the library makes for large containers.
func largeObjectFromJSON(t *testing.T, json string) *WAFObject {
	t.Helper()

	ok, err := bindings.Load()
	require.True(t, ok, "libddwaf must load: %v", err)

	obj, ok := bindings.Lib.ObjectFromJSON([]byte(json), bindings.Lib.DefaultAllocator())
	require.True(t, ok, "ddwaf_object_from_json failed")
	t.Cleanup(func() { bindings.Lib.ObjectDestroy(&obj, bindings.Lib.DefaultAllocator()) })
	return &obj
}

// TestDecodeLargeContainers checks that the diagnostics and the result decoders
// accept arrays and maps with more than 65,535 items (libddwaf 2.1.0 and later).
func TestDecodeLargeContainers(t *testing.T) {
	id := func(i int) string { return fmt.Sprintf(`"rule-%d"`, i) }

	t.Run("decodeDiagnostics", func(t *testing.T) {
		ids := jsonList(largeContainerItems, id)
		obj := largeObjectFromJSON(t, fmt.Sprintf(`{"rules":{"loaded":[%s],"errors":{"msg":[%s]}}}`, ids, ids))

		// Without the large types support, decoding failed on both the loaded list and the errors.
		rules, err := obj.MapEntries()
		require.NoError(t, err)
		require.Len(t, rules, 1)
		loaded, err := rules[0].Val.MapEntries()
		require.NoError(t, err)
		require.Equal(t, WAFLargeArrayType, loaded[0].Val.Type())

		diags, err := decodeDiagnostics(obj)
		require.NoError(t, err)
		require.NotNil(t, diags.Rules)
		require.Len(t, diags.Rules.Loaded, largeContainerItems)
		require.Equal(t, "rule-0", diags.Rules.Loaded[0])
		require.Equal(t, fmt.Sprintf("rule-%d", largeContainerItems-1), diags.Rules.Loaded[largeContainerItems-1])
		require.Len(t, diags.Rules.Errors, 1)
		require.Len(t, diags.Rules.Errors["msg"], largeContainerItems)
		require.Equal(t, fmt.Sprintf("rule-%d", largeContainerItems-1), diags.Rules.Errors["msg"][largeContainerItems-1])
	})

	t.Run("unwrapWafResult", func(t *testing.T) {
		// No "duration", "timeout" or "keep": the number types of the JSON parser do not matter here.
		obj := largeObjectFromJSON(t, fmt.Sprintf(`{"events":[%s],"actions":{%s},"attributes":{%s}}`,
			jsonList(largeContainerItems, func(i int) string { return fmt.Sprintf(`{"id":"event-%d"}`, i) }),
			jsonList(largeContainerItems, func(i int) string { return fmt.Sprintf(`"action-%d":{"type":"block"}`, i) }),
			jsonList(largeContainerItems, func(i int) string { return fmt.Sprintf(`"attr-%d":"value-%d"`, i, i) }),
		))

		res, _, err := unwrapWafResult(bindings.WAFOK, obj)
		require.NoError(t, err)

		require.Len(t, res.Events, largeContainerItems)
		require.Equal(t, map[string]any{"id": "event-0"}, res.Events[0])
		require.Equal(t, map[string]any{"id": fmt.Sprintf("event-%d", largeContainerItems-1)}, res.Events[largeContainerItems-1])

		require.Len(t, res.Actions, largeContainerItems)
		require.Equal(t, map[string]any{"type": "block"}, res.Actions[fmt.Sprintf("action-%d", largeContainerItems-1)])

		require.Len(t, res.Derivatives, largeContainerItems)
		require.Equal(t, fmt.Sprintf("value-%d", largeContainerItems-1), res.Derivatives[fmt.Sprintf("attr-%d", largeContainerItems-1)])
	})
}
