// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/waferrors"

	"github.com/stretchr/testify/require"
)

// benchResultObject builds a WAF result object with the same 7 keys as the
// result of BenchmarkRunOnly (benign request, no event).
func benchResultObject(tb testing.TB, p *runtime.Pinner) *WAFObject {
	tb.Helper()
	encoder, err := newEncoder(newEncoderConfig(p, WithUnlimitedLimits()))
	require.NoError(tb, err)
	obj, err := encoder.Encode(map[string]any{
		"actions":    map[string]any{},
		"attributes": map[string]any{},
		"duration":   uint64(1234),
		"evaluated":  true,
		"events":     []any{},
		"keep":       false,
		"timeout":    false,
	})
	require.NoError(tb, err)
	return obj
}

// BenchmarkUnwrapWafResult measures the decode of a result with 7 keys.
func BenchmarkUnwrapWafResult(b *testing.B) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	obj := benchResultObject(b, &pinner)

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := unwrapWafResult(bindings.WAFOK, obj); err != nil {
			b.Fatal(err)
		}
	}
}

// TestUnwrapWafResultKeysDoNotAllocate checks that the keys of a WAF result do
// not allocate. This needs the compiler to inline StringValue.
//
// This test covers the default build only. Other builds can inline differently:
// for example, a build with -pgo, or with -gcflags=-l. The test does not cover
// them.
func TestUnwrapWafResultKeysDoNotAllocate(t *testing.T) {
	// The check depends on the inliner, and CI also tests Go "tip".
	if strings.HasPrefix(runtime.Version(), "devel") {
		t.Skip("the allocation check needs a released Go version")
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	obj := benchResultObject(t, &pinner)

	allocs := testing.AllocsPerRun(100, func() {
		if _, _, err := unwrapWafResult(bindings.WAFOK, obj); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("unwrapWafResult allocates %v times per call, want 0", allocs)
	}
}

// TestUnwrapWafResultKeys checks the key paths of unwrapWafResult that the
// other tests do not cover: a key that is not a string, and keys that are
// ignored (empty, and longer than a small string).
func TestUnwrapWafResultKeys(t *testing.T) {
	t.Run("non-string-key", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var result WAFObject
		kvs := result.SetMap(&pinner, 1)
		kvs[0].Key.SetInt(1)
		kvs[0].Val.SetBool(true)
		result.SetMapSize(1)

		_, _, err := unwrapWafResult(bindings.WAFOK, &result)
		require.ErrorIs(t, err, waferrors.ErrResultInvalidType)
		require.ErrorIs(t, err, waferrors.ErrInvalidObjectType)
		require.EqualError(t, err, "unwrapWafResult: "+waferrors.ErrResultInvalidType.Error()+
			": failed to decode WAF result key: "+waferrors.ErrInvalidObjectType.Error()+": value is not a string but int")
	})

	t.Run("ignored-keys", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var result WAFObject
		kvs := result.SetMap(&pinner, 3)
		kvs[0].Key.SetString(&pinner, "")
		kvs[0].Val.SetBool(true)
		kvs[1].Key.SetString(&pinner, "timeout_but_longer_than_14_bytes")
		kvs[1].Val.SetBool(true)
		kvs[2].Key.SetString(&pinner, "keep")
		kvs[2].Val.SetBool(true)
		result.SetMapSize(3)

		res, dur, err := unwrapWafResult(bindings.WAFOK, &result)
		require.NoError(t, err)
		require.Zero(t, dur)
		require.Equal(t, Result{Keep: true}, res)
	})
}
