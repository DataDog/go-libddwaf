package libddwaf

import (
	"runtime"
	"testing"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationSpike(t *testing.T) {
	t.Run("map-with-encoder-and-mapbuilder", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		enc := &Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}

		var obj WAFObject
		mb := enc.Map(&obj, 3)

		slot := mb.NextValue("name")
		require.NotNil(t, slot)
		slot.SetString(&pinner, "test-user")

		slot = mb.NextValue("age")
		require.NotNil(t, slot)
		slot.SetUint(42)

		slot = mb.NextValue("active")
		require.NotNil(t, slot)
		slot.SetBool(true)

		mb.Close()

		require.True(t, obj.IsMap())
		size, err := obj.MapSize()
		require.NoError(t, err)
		assert.Equal(t, uint16(3), size)

		m, err := obj.MapValue()
		require.NoError(t, err)
		assert.Equal(t, "test-user", m["name"])
		assert.Equal(t, uint64(42), m["age"])
		assert.Equal(t, true, m["active"])
	})

	t.Run("array-with-encoder-and-arraybuilder", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		enc := &Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}

		var obj WAFObject
		ab := enc.Array(&obj, 3)

		for _, s := range []string{"a", "b", "c"} {
			slot := ab.NextValue()
			require.NotNil(t, slot)
			slot.SetString(&pinner, s)
		}

		ab.Close()

		require.True(t, obj.IsArray())
		arr, err := obj.ArrayValue()
		require.NoError(t, err)
		assert.Equal(t, []any{"a", "b", "c"}, arr)
	})

	t.Run("nested-map-with-array-values", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		enc := &Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}

		var obj WAFObject
		mb := enc.Map(&obj, 1)

		tagsSlot := mb.NextValue("tags")
		require.NotNil(t, tagsSlot)

		ab := enc.Array(tagsSlot, 2)
		ab.NextValue().SetString(&pinner, "urgent")
		ab.NextValue().SetString(&pinner, "security")
		ab.Close()

		mb.Close()

		m, err := obj.MapValue()
		require.NoError(t, err)
		tags, ok := m["tags"].([]any)
		require.True(t, ok)
		assert.Equal(t, []any{"urgent", "security"}, tags)
	})

	t.Run("truncation-recording", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		enc := &Encoder{Config: EncoderConfig{
			Pinner:           &pinner,
			MaxStringSize:    5,
			MaxContainerSize: 2,
		}}

		var obj WAFObject
		mb := enc.Map(&obj, 10)

		slot := mb.NextValue("longkey-exceeds-max")
		require.NotNil(t, slot)
		slot.SetBool(true)

		slot = mb.NextValue("k2")
		require.NotNil(t, slot)
		slot.SetBool(false)

		require.Nil(t, mb.NextValue("overflow"))
		mb.Skip()

		mb.Close()

		assert.False(t, enc.Truncations.IsEmpty())
		assert.NotEmpty(t, enc.Truncations.StringTooLong)
		assert.NotEmpty(t, enc.Truncations.ContainerTooLarge)
	})

	t.Run("encodable-best-effort-pattern", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		enc := &Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}

		var obj WAFObject
		mb := enc.Map(&obj, 2)

		slot := mb.NextValue("good-key")
		require.NotNil(t, slot)
		slot.SetString(&pinner, "good-value")

		slot = mb.NextValue("bad-key")
		require.NotNil(t, slot)
		slot.SetInvalid()

		mb.Close()

		size, err := obj.MapSize()
		require.NoError(t, err)
		assert.Equal(t, uint16(2), size)

		entries, err := obj.MapEntries()
		require.NoError(t, err)
		key1, _ := entries[0].Key.StringValue()
		assert.Equal(t, "good-key", key1)
		assert.False(t, entries[0].Val.IsInvalid())

		key2, _ := entries[1].Key.StringValue()
		assert.Equal(t, "bad-key", key2)
		assert.True(t, entries[1].Val.IsInvalid())
	})

	t.Run("encodable-interface-implementation", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		enc := &Encoder{Config: newEncoderConfig(&pinner, WithUnlimitedLimits())}

		var obj WAFObject
		err := spikeEncodable{}.Encode(enc, &obj, 5)
		require.NoError(t, err)

		require.True(t, obj.IsMap())
		m, err := obj.MapValue()
		require.NoError(t, err)
		assert.Equal(t, "hello", m["greeting"])
		assert.Equal(t, int64(42), m["number"])
	})
}

type spikeEncodable struct{}

func (s spikeEncodable) Encode(enc *Encoder, obj *WAFObject, depth int) error {
	if enc.Timeout() {
		return waferrors.ErrTimeout
	}
	if depth < 0 {
		return waferrors.ErrMaxDepthExceeded
	}

	mb := enc.Map(obj, 2)
	defer mb.Close()

	slot := mb.NextValue("greeting")
	if slot != nil {
		enc.WriteString(slot, "hello")
	}

	slot = mb.NextValue("number")
	if slot != nil {
		slot.SetInt(42)
	}

	return nil
}
