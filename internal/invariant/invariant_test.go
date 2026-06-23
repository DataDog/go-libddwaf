// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package invariant_test

import (
	"testing"

	"github.com/DataDog/go-libddwaf/v5/internal/invariant"
)

func TestAssertMatchesActive(t *testing.T) {
	didPanic := func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		invariant.Assert(false, "test %s", "message")
		return
	}()

	if invariant.Active() && !didPanic {
		t.Fatal("Assert(false, ...) must panic when invariant.Active() is true (ci build)")
	}
	if !invariant.Active() && didPanic {
		t.Fatal("Assert(false, ...) must be a no-op when invariant.Active() is false (production build)")
	}
}

func TestAssertTrueNeverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Assert(true, ...) must never panic: %v", r)
		}
	}()
	invariant.Assert(true, "condition holds")
}
