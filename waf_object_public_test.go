package libddwaf

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicWAFObjectMethods(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	t.Run("scalar accessors", func(t *testing.T) {
		var obj WAFObject
		obj.SetString(&pinner, "hello")

		require.Equal(t, "string", obj.Type())
		require.True(t, obj.IsString())

		value, err := obj.StringValue()
		require.NoError(t, err)
		require.Equal(t, "hello", value)
	})

	t.Run("map container wrappers", func(t *testing.T) {
		var obj WAFObject
		entries := obj.SetMap(&pinner, 1)
		require.Len(t, entries, 1)

		entries[0].Key().SetString(&pinner, "k")
		entries[0].Value().SetBool(true)
		obj.SetMapSize(1)

		require.True(t, obj.IsMap())
		require.Equal(t, "map", obj.Type())

		size, err := obj.MapSize()
		require.NoError(t, err)
		require.EqualValues(t, 1, size)

		wrappedEntries, err := obj.MapEntries()
		require.NoError(t, err)
		require.Len(t, wrappedEntries, 1)

		key, err := wrappedEntries[0].Key().StringValue()
		require.NoError(t, err)
		require.Equal(t, "k", key)

		value, err := wrappedEntries[0].Value().BoolValue()
		require.NoError(t, err)
		require.True(t, value)
	})

	t.Run("array container wrappers", func(t *testing.T) {
		var obj WAFObject
		items := obj.SetArray(&pinner, 2)
		require.Len(t, items, 2)

		items[0].SetInt(1)
		items[1].SetInt(2)
		obj.SetArraySize(2)

		values, err := obj.ArrayValues()
		require.NoError(t, err)
		require.Len(t, values, 2)

		first, err := values[0].IntValue()
		require.NoError(t, err)
		require.EqualValues(t, 1, first)
	})
}
