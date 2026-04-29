// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wafResultMapBuilder is a helper for constructing WAFObject maps used as
// input to the unwrapWafResult function in tests. It tracks a runtime.Pinner
// that must be unpinned by the caller when the objects are no longer needed.
type wafResultMapBuilder struct {
	pinner  runtime.Pinner
	entries []WAFObjectKV
}

func (b *wafResultMapBuilder) addBoolEntry(key string, val bool) {
	var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	entry.Value().SetBool(val)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) addUintEntry(key string, val uint64) {
	var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	entry.Value().SetUint(val)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) addStringEntry(key string, val string) {
	var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	entry.Value().SetString(&b.pinner, val)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) addEmptyArrayEntry(key string) {
	var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	entry.Value().SetArray(&b.pinner, 0)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) addArrayEntry(key string, items []WAFObject) {
	var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	_ = entry.Value().SetArrayData(&b.pinner, items)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) addEmptyMapEntry(key string) {
		var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	entry.Value().SetMap(&b.pinner, 0)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) addMapEntry(key string, items []WAFObjectKV) {
	var entry WAFObjectKV
	entry.Key().SetString(&b.pinner, key)
	_ = entry.Value().SetMapData(&b.pinner, items)
	b.entries = append(b.entries, entry)
}

func (b *wafResultMapBuilder) build() WAFObject {
	var obj WAFObject
	obj.SetMapData(&b.pinner, b.entries)
	return obj
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
			require.Contains(t, err.Error(), "invalid WAF result object type: expected array for events, got string")
		})
	})

	t.Run("actions", func(t *testing.T) {
		t.Run("non-empty-map", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()

			var item WAFObjectKV
			item.Key().SetString(&b.pinner, "block_request")
			item.Value().SetString(&b.pinner, "blocked")
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
			require.Contains(t, err.Error(), "invalid WAF result object type: expected map for actions, got string")
		})
	})

	t.Run("attributes", func(t *testing.T) {
		t.Run("non-empty-map", func(t *testing.T) {
			var b wafResultMapBuilder
			defer b.pinner.Unpin()

			var item WAFObjectKV
			item.Key().SetString(&b.pinner, "derivative-key")
			item.Value().SetString(&b.pinner, "derivative-value")
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
			require.Contains(t, err.Error(), "invalid WAF result object type: expected map for attributes, got string")
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
		action.Key().SetString(&b.pinner, "block_request")
		action.Value().SetString(&b.pinner, "blocked")
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
