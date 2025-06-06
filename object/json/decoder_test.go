// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package json

import (
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	var (
		pinner runtime.Pinner
		v      bindings.WAFObject
	)
	defer pinner.Unpin()

	dec := NewDecoder(strings.NewReader(`{
			"array": [1, -1, 3.14],
			"bool": true,
			"string": "hello",
			"": null
		}`), &pinner)
	require.NoError(t, dec.Decode(&v))

	actual, err := v.AnyValue()
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"array":  []any{uint64(1), int64(-1), float64(3.14)},
		"bool":   true,
		"string": "hello",
		"":       nil,
	}, actual)
}
