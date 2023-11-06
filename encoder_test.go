// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeNilMap(t *testing.T) {
	var nilMap map[string]any = nil

	encoder := newMaxEncoder()
	wo, err := encoder.Encode(nilMap)
	assert.NoError(t, err)

	assert.True(t, wo.isMap())
	assert.Equal(t, uint64(0), wo.nbEntries)
}
