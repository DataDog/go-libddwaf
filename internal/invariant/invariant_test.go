// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package invariant_test

import (
	"testing"

	"github.com/DataDog/go-libddwaf/v5/internal/invariant"
)

func TestInvariantPanics(t *testing.T) {
	invariant.Assert(false, "test %s", "message")
}

func TestInvariantNoopInProd(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Assert(false, ...) panicked in production build: %v", r)
		}
	}()
	invariant.Assert(false, "should not panic")
}
