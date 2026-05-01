// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func concurrentPinnerClosed(p *pin.ConcurrentPinner) bool {
	field := reflect.ValueOf(p).Elem().FieldByName("closed")
	return (*atomic.Bool)(unsafe.Pointer(field.UnsafeAddr())).Load()
}

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

func TestPoolInvariants_Context(t *testing.T) {
	pooled := contextPool.Get().(*Context)
	pooledTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Second), timer.WithComponents("waf"))
	require.NoError(t, err)
	pooled.Timer = timer.WrapOwnedNodeTimer(pooledTimer)
	timerAlias := pooled.Timer
	pooled.handle = &Handle{}
	pooled.closedHint.Store(true)
	pooled.cContext = bindings.WAFContext(42)
	pooled.truncations.StringTooLong = make([]int, 3, 33)
	copy(pooled.truncations.StringTooLong, []int{11, 22, 33})
	pooled.truncations.ContainerTooLarge = make([]int, 2, 16)
	copy(pooled.truncations.ContainerTooLarge, []int{44, 55})
	pooled.truncations.ObjectTooDeep = make([]int, 2, 40)
	copy(pooled.truncations.ObjectTooDeep, []int{66, 77})
	pooled.pinner.Close()
	require.True(t, concurrentPinnerClosed(&pooled.pinner))

	timer.PutNodeTimer(timerAlias)
	contextPool.Put(pooled)

	reused := contextPool.Get().(*Context)
	t.Cleanup(func() {
		contextPool.Put(reused)
	})

	require.Nil(t, reused.Timer)
	require.Nil(t, reused.handle)
	require.False(t, reused.closedHint.Load())
	reused.evalsInFlight.Add(1)
	reused.evalsInFlight.Done()
	reused.mu.Lock()
	reused.mu.Unlock()
	require.Zero(t, reused.cContext)
	reused.truncationsMu.Lock()
	reused.truncationsMu.Unlock()
	require.Nil(t, reused.truncations.StringTooLong)
	require.Len(t, reused.truncations.ContainerTooLarge, 0)
	require.LessOrEqual(t, cap(reused.truncations.ContainerTooLarge), 32)
	if reused.truncations.ContainerTooLarge != nil {
		require.Equal(t, make([]int, cap(reused.truncations.ContainerTooLarge)), reused.truncations.ContainerTooLarge[:cap(reused.truncations.ContainerTooLarge)])
	}
	require.Nil(t, reused.truncations.ObjectTooDeep)
	require.False(t, concurrentPinnerClosed(&reused.pinner))
}

func TestRun_ContextPoolReuse(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	for range 100 {
		ctx, err := waf.NewContext(context.Background(), timer.WithBudget(time.Hour), timer.WithComponents("waf"))
		require.NoError(t, err)

		_, err = ctx.Run(context.Background(), RunAddressData{
			Data:     map[string]any{"my.input": "Arachni"},
			TimerKey: "waf",
		})
		require.NoError(t, err)
		require.False(t, ctx.closedHint.Load())
		require.Empty(t, ctx.Truncations().StringTooLong)
		ctx.Close()
	}
}
