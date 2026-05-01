// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type wafResultMapBuilder struct {
	pinner runtime.Pinner
	enc    Encoder
	obj    WAFObject
	mb     *MapBuilder
}

func (b *wafResultMapBuilder) init() {
	if b.mb != nil {
		return
	}
	b.enc = Encoder{Config: newEncoderConfig(&b.pinner, WithUnlimitedLimits())}
	b.mb = b.enc.Map(&b.obj)
}

func (b *wafResultMapBuilder) addBoolEntry(key string, val bool) {
	b.init()
	b.mb.NextValue(key).SetBool(val)
}

func (b *wafResultMapBuilder) addUintEntry(key string, val uint64) {
	b.init()
	b.mb.NextValue(key).SetUint(val)
}

func (b *wafResultMapBuilder) addStringEntry(key string, val string) {
	b.init()
	b.mb.NextValue(key).SetString(&b.pinner, val)
}

func (b *wafResultMapBuilder) addEmptyArrayEntry(key string) {
	b.init()
	b.mb.NextValue(key).SetArray(&b.pinner, 0)
}

func (b *wafResultMapBuilder) addArrayEntry(key string, items []WAFObject) {
	b.init()
	_ = b.mb.NextValue(key).SetArrayData(&b.pinner, items)
}

func (b *wafResultMapBuilder) addEmptyMapEntry(key string) {
	b.init()
	b.mb.NextValue(key).SetMap(&b.pinner, 0)
}

func (b *wafResultMapBuilder) addMapEntry(key string, items []WAFObjectKV) {
	b.init()
	_ = b.mb.NextValue(key).SetMapData(&b.pinner, items)
}

func (b *wafResultMapBuilder) build() WAFObject {
	b.init()
	b.mb.Close()
	return b.obj
}

func TestUnwrapWafResult(t *testing.T) {
	t.Run("result-not-a-map", func(t *testing.T) {
		var result WAFObject
		result.SetInvalid()
		_, _, err := unwrapWafResult(bindings.WAFOK, &result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid WAF result object type: expected map, got invalid")
	})

	t.Run("empty-map-return-codes", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			ret    bindings.WAFReturnCode
			expErr error
			errMsg string
		}{
			{name: "WAFOK", ret: bindings.WAFOK, expErr: nil},
			{name: "WAFMatch", ret: bindings.WAFMatch, expErr: nil},
			{name: "WAFErrInternal", ret: bindings.WAFErrInternal, expErr: waferrors.ErrInternal},
			{name: "WAFErrInvalidObject", ret: bindings.WAFErrInvalidObject, expErr: waferrors.ErrInvalidObject},
			{name: "WAFErrInvalidArgument", ret: bindings.WAFErrInvalidArgument, expErr: waferrors.ErrInvalidArgument},
			{name: "unknown-return-code", ret: bindings.WAFReturnCode(42), errMsg: "unknown WAF return code: 42"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var b wafResultMapBuilder
				defer b.pinner.Unpin()
				result := b.build()

				res, dur, err := unwrapWafResult(tc.ret, &result)
				if tc.errMsg != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.errMsg)
				} else if tc.expErr != nil {
					require.ErrorIs(t, err, tc.expErr)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, Result{}, res)
				assert.Equal(t, time.Duration(0), dur)
			})
		}
	})

	t.Run("timeout", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			val    bool
			ret    bindings.WAFReturnCode
			expErr error
		}{
			{name: "true-WAFOK", val: true, ret: bindings.WAFOK, expErr: waferrors.ErrTimeout},
			{name: "true-WAFMatch", val: true, ret: bindings.WAFMatch, expErr: waferrors.ErrTimeout},
			{name: "false-WAFOK", val: false, ret: bindings.WAFOK, expErr: nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var b wafResultMapBuilder
				defer b.pinner.Unpin()
				b.addBoolEntry("timeout", tc.val)
				result := b.build()

				_, _, err := unwrapWafResult(tc.ret, &result)
				if tc.expErr != nil {
					require.ErrorIs(t, err, tc.expErr)
				} else {
					require.NoError(t, err)
				}
			})
		}

		t.Run("wrong-type", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addStringEntry("timeout", "not-a-bool")
			result := b.build()

			_, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to decode timeout")
		})
	})

	t.Run("keep", func(t *testing.T) {
		t.Run("true", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addBoolEntry("keep", true)
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			assert.True(t, res.Keep)
		})

		t.Run("wrong-type", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addStringEntry("keep", "not-a-bool")
			result := b.build()

			_, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to decode keep")
		})
	})

	t.Run("duration", func(t *testing.T) {
		t.Run("value", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addUintEntry("duration", 12345)
			result := b.build()

			_, dur, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			assert.Equal(t, 12345*time.Nanosecond, dur)
		})

		t.Run("wrong-type", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addStringEntry("duration", "not-a-uint")
			result := b.build()

			_, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to decode duration")
		})
	})

	t.Run("events", func(t *testing.T) {
		t.Run("non-empty-array", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()

			var item WAFObject
			item.SetString(&b.pinner, "event-1")
			b.addArrayEntry("events", []WAFObject{item})
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			require.NotNil(t, res.Events)
			require.Len(t, res.Events, 1)
			assert.Equal(t, "event-1", res.Events[0])
		})

		t.Run("empty-array", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addEmptyArrayEntry("events")
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			assert.Nil(t, res.Events)
		})

		t.Run("wrong-type", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addStringEntry("events", "not-an-array")
			result := b.build()

			_, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid WAF result object type: expected array for events, got small_string")
		})
	})

	t.Run("actions", func(t *testing.T) {
		t.Run("non-empty-map", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()

			var item WAFObjectKV
			item.Key.SetString(&b.pinner, "block_request")
			item.Val.SetString(&b.pinner, "blocked")
			b.addMapEntry("actions", []WAFObjectKV{item})
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			require.NotNil(t, res.Actions)
			assert.Equal(t, "blocked", res.Actions["block_request"])
		})

		t.Run("empty-map", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addEmptyMapEntry("actions")
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			assert.Nil(t, res.Actions)
		})

		t.Run("wrong-type", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addStringEntry("actions", "not-a-map")
			result := b.build()

			_, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid WAF result object type: expected map for actions, got small_string")
		})
	})

	t.Run("attributes", func(t *testing.T) {
		t.Run("non-empty-map", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()

			var item WAFObjectKV
			item.Key.SetString(&b.pinner, "derivative-key")
			item.Val.SetString(&b.pinner, "derivative-value")
			b.addMapEntry("attributes", []WAFObjectKV{item})
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			require.NotNil(t, res.Derivatives)
			assert.Equal(t, "derivative-value", res.Derivatives["derivative-key"])
		})

		t.Run("empty-map", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addEmptyMapEntry("attributes")
			result := b.build()

			res, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.NoError(t, err)
			assert.Nil(t, res.Derivatives)
		})

		t.Run("wrong-type", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()
			b.addStringEntry("attributes", "not-a-map")
			result := b.build()

			_, _, err := unwrapWafResult(bindings.WAFOK, &result)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid WAF result object type: expected map for attributes, got small_string")
		})
	})

	t.Run("combined-timeout-events-actions", func(t *testing.T) {
		var b wafResultMapBuilder
		defer b.pinner.Unpin()

		b.addBoolEntry("timeout", true)

		var event WAFObject
		event.SetString(&b.pinner, "matched-rule")
		b.addArrayEntry("events", []WAFObject{event})

		var action WAFObjectKV
		action.Key.SetString(&b.pinner, "block_request")
		action.Val.SetString(&b.pinner, "blocked")
		b.addMapEntry("actions", []WAFObjectKV{action})

		result := b.build()

		res, _, err := unwrapWafResult(bindings.WAFMatch, &result)
		require.ErrorIs(t, err, waferrors.ErrTimeout)
		require.NotNil(t, res.Events)
		require.Len(t, res.Events, 1)
		assert.Equal(t, "matched-rule", res.Events[0])
		require.NotNil(t, res.Actions)
		assert.Equal(t, "blocked", res.Actions["block_request"])
	})

	t.Run("unknown-key-ignored", func(t *testing.T) {
		var b wafResultMapBuilder
		defer b.pinner.Unpin()
		b.addStringEntry("unknown_field", "should-be-ignored")
		b.addBoolEntry("keep", true)
		result := b.build()

		res, _, err := unwrapWafResult(bindings.WAFOK, &result)
		require.NoError(t, err)
		assert.True(t, res.Keep)
	})
}

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

	encoder, err := newEncoder(newEncoderConfig(&wafCtx.pinner, WithUnlimitedLimits()))
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
