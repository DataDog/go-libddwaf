// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ci

package libddwaf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleRefcountUnderflowPanicsUnderCI(t *testing.T) {
	handle := &Handle{}
	handle.refCounter.Store(1)

	defer func() {
		r := recover()
		require.NotNil(t, r, "expected panic but got none")

		msg := fmt.Sprint(r)
		require.Contains(t, msg, "invariant violated")
		require.Contains(t, msg, "refCounter went negative")
		require.Zero(t, handle.refCounter.Load())
	}()

	result := handle.addRefCounter(-2)
	t.Fatalf("expected panic, got result=%d", result)
}
