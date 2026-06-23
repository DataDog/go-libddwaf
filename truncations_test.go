package libddwaf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTruncationsRecord_AppendsSize(t *testing.T) {
	var tr Truncations
	tr.Record(StringTooLong, 100)
	require.Equal(t, []int{100}, tr.StringTooLong)
	require.Nil(t, tr.ContainerTooLarge)
	require.Nil(t, tr.ObjectTooDeep)

	tr.Record(ContainerTooLarge, 200)
	require.Equal(t, []int{200}, tr.ContainerTooLarge)

	tr.Record(ObjectTooDeep, 300)
	require.Equal(t, []int{300}, tr.ObjectTooDeep)

	tr.Record(StringTooLong, 150)
	require.Equal(t, []int{100, 150}, tr.StringTooLong)
}

func TestTruncationsRecord_NilSafe(t *testing.T) {
	tr := Truncations{}
	require.NotPanics(t, func() {
		tr.Record(StringTooLong, 42)
		tr.Record(ContainerTooLarge, 43)
		tr.Record(ObjectTooDeep, 44)
	})
	require.Equal(t, []int{42}, tr.StringTooLong)
	require.Equal(t, []int{43}, tr.ContainerTooLarge)
	require.Equal(t, []int{44}, tr.ObjectTooDeep)
}

func TestTruncationsMerge_Concatenates(t *testing.T) {
	a := Truncations{
		StringTooLong:     []int{1, 2},
		ContainerTooLarge: []int{3},
		ObjectTooDeep:     nil,
	}
	b := Truncations{
		StringTooLong:     []int{4},
		ContainerTooLarge: nil,
		ObjectTooDeep:     []int{5, 6},
	}
	a.Merge(b)
	require.Equal(t, []int{1, 2, 4}, a.StringTooLong)
	require.Equal(t, []int{3}, a.ContainerTooLarge)
	require.Equal(t, []int{5, 6}, a.ObjectTooDeep)
}

func TestTruncationsMerge_EmptyDoesNothing(t *testing.T) {
	a := Truncations{
		StringTooLong: []int{10, 20},
	}
	original := []int{10, 20}
	a.Merge(Truncations{})
	require.Equal(t, original, a.StringTooLong)
	require.Nil(t, a.ContainerTooLarge)
	require.Nil(t, a.ObjectTooDeep)
}

func TestTruncationsIsEmpty_AllPaths(t *testing.T) {
	require.True(t, Truncations{}.IsEmpty())
	require.False(t, Truncations{StringTooLong: []int{1}}.IsEmpty())
	require.False(t, Truncations{ContainerTooLarge: []int{2}}.IsEmpty())
	require.False(t, Truncations{ObjectTooDeep: []int{3}}.IsEmpty())
	require.False(t, Truncations{
		StringTooLong:     []int{1},
		ContainerTooLarge: []int{2},
		ObjectTooDeep:     []int{3},
	}.IsEmpty())
}

func TestTruncationsAsMap_RoundTrip(t *testing.T) {
	tr := Truncations{
		StringTooLong:     []int{10, 20},
		ContainerTooLarge: []int{30},
		ObjectTooDeep:     []int{40, 50, 60},
	}
	m := tr.AsMap()
	require.NotNil(t, m)
	require.Equal(t, []int{10, 20}, m[StringTooLong])
	require.Equal(t, []int{30}, m[ContainerTooLarge])
	require.Equal(t, []int{40, 50, 60}, m[ObjectTooDeep])
}

func TestTruncationsAsMap_EmptyReturnsNil(t *testing.T) {
	m := Truncations{}.AsMap()
	require.Nil(t, m)
}
