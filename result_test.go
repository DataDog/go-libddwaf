// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/require"
)

func TestUnwrapWafResult_Equivalence(t *testing.T) {
	rawRet, rawResult := evaluateRawWAFResult(t,
		newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, []string{"block"}),
		map[string]any{"my.input": "Arachni"},
	)

	optimized, optimizedDuration, optimizedErr := unwrapWafResult(rawRet, rawResult)
	reference, referenceDuration, referenceErr := unwrapWafResultReference(rawRet, rawResult)

	require.Equal(t, reference, optimized)
	require.Equal(t, referenceDuration, optimizedDuration)
	require.Equal(t, referenceErr, optimizedErr)
	require.NotEmpty(t, optimized.Events)
	require.Contains(t, optimized.Actions, "block_request")
	if action, ok := optimized.Actions["block_request"].(map[string]any); ok {
		require.NotEmpty(t, action["security_response_id"])
	}
}

func evaluateRawWAFResult(t *testing.T, rules any, data map[string]any) (bindings.WAFReturnCode, *WAFObject) {
	t.Helper()

	waf, _, err := newDefaultHandle(t, rules)
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	wafCtx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	t.Cleanup(func() { wafCtx.Close() })

	var pinner runtime.Pinner
	t.Cleanup(func() { pinner.Unpin() })
	encoder, err := newEncoder(newEncoderConfig(&pinner, WithUnlimitedLimits()))
	require.NoError(t, err)

	encoded, err := encoder.Encode(data)
	require.NoError(t, err)

	var resultPinner runtime.Pinner
	result := new(WAFObject)
	resultPinner.Pin(result)
	t.Cleanup(func() {
		bindings.Lib.ObjectDestroy(result, bindings.Lib.DefaultAllocator())
		resultPinner.Unpin()
	})

	ret := bindings.Lib.ContextEval(wafCtx.cContext, encoded, 0, result, uint64((5 * time.Second).Microseconds()))
	return ret, result
}

func unwrapWafResultReference(ret bindings.WAFReturnCode, result *WAFObject) (res Result, duration time.Duration, err error) {
	if !result.IsMap() {
		return Result{}, 0, waferrors.ErrResultInvalidType
	}
	entries, err := result.MapEntries()
	if err != nil {
		return Result{}, 0, err
	}
	var wafTimeout bool
	for _, entry := range entries {
		key, err := entry.Key.StringValue()
		if err != nil {
			return Result{}, 0, err
		}
		switch key {
		case "timeout", "keep", "duration":
			if wafTimeout, duration, err = decodeTimeoutKeepDuration(entry, key, wafTimeout, duration, &res); err != nil {
				return Result{}, 0, err
			}
		case "events":
			if err := decodeEvents(entry, &res); err != nil {
				return Result{}, 0, err
			}
		case "actions":
			if err := decodeActions(entry, &res); err != nil {
				return Result{}, 0, err
			}
		case "attributes":
			if err := decodeAttributes(entry, &res); err != nil {
				return Result{}, 0, err
			}
		}
	}
	if wafTimeout {
		return res, duration, waferrors.ErrTimeout
	}
	return res, duration, goRunError(ret)
}
