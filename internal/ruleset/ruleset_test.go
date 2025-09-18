// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux || darwin

package ruleset

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultRuleset(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	rs, err := DefaultRuleset()
	require.NoError(t, err)
	require.NotNil(t, rs)

	obj, err := rs.MapValue()
	require.NoError(t, err)
	useJSONNumber(obj) // So we can easily compare the result with the expected JSON.

	rd, err := gzip.NewReader(bytes.NewReader(defaultRuleset))
	require.NoError(t, err)
	dec := json.NewDecoder(rd)
	dec.UseNumber()
	var expected map[string]any
	require.NoError(t, dec.Decode(&expected))
	require.Equal(t, expected, obj)
}

func useJSONNumber(obj map[string]any) {
	for k, v := range obj {
		switch v := v.(type) {
		case float64:
			obj[k] = json.Number(strconv.FormatFloat(v, 'f', -1, 64))
		case int64:
			obj[k] = json.Number(strconv.FormatInt(v, 10))
		case uint64:
			obj[k] = json.Number(strconv.FormatUint(v, 10))
		case map[string]any:
			useJSONNumber(v)
		case []any:
			for _, v := range v {
				if v, ok := v.(map[string]any); ok {
					useJSONNumber(v)
				}
			}
		}
	}
}
