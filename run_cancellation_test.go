// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.28 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	stdcontext "context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/timer"
)

func TestContextRunCanceledDoesNotEvaluate(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	wafCtx, err := waf.NewContext(stdcontext.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	defer wafCtx.Close()

	canceledCtx, cancel := stdcontext.WithCancel(stdcontext.Background())
	cancel()

	res, err := wafCtx.Run(canceledCtx, RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
	require.ErrorIs(t, err, stdcontext.Canceled)
	require.False(t, res.HasEvents(), "a canceled Context.Run must not evaluate the WAF or persist data")
}

func TestSubcontextRunCanceledDoesNotEvaluate(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	wafCtx, err := waf.NewContext(stdcontext.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	defer wafCtx.Close()

	subCtx, err := wafCtx.NewSubcontext(stdcontext.Background())
	require.NoError(t, err)
	defer subCtx.Close()

	canceledCtx, cancel := stdcontext.WithCancel(stdcontext.Background())
	cancel()

	res, err := subCtx.Run(canceledCtx, RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
	require.ErrorIs(t, err, stdcontext.Canceled)
	require.False(t, res.HasEvents(), "a canceled Subcontext.Run must not evaluate the WAF or persist data")
}
