// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64)) || (windows && (amd64 || 386))) && !go1.22

package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionHasCorrectFormat(t *testing.T) {
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, EmbeddedWAFVersion)
}
