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

func TestRunnerInterfaceSatisfied(t *testing.T) {
	handle, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	defer handle.Close()

	ctx, err := handle.NewContext(stdcontext.Background(), timer.WithUnlimitedBudget(), timer.WithComponents("waf"))
	require.NoError(t, err)
	defer ctx.Close()

	runner := Runner(ctx)
	res, err := runner.Run(stdcontext.Background(), RunAddressData{})
	require.NoError(t, err)
	require.Empty(t, res.Events)
	require.Empty(t, res.Derivatives)
	require.Empty(t, res.Actions)
	require.False(t, res.Keep)

	subctx, err := ctx.NewSubcontext(stdcontext.Background())
	require.NoError(t, err)
	defer subctx.Close()

	runner = Runner(subctx)
	res, err = runner.Run(stdcontext.Background(), RunAddressData{})
	require.NoError(t, err)
	require.Empty(t, res.Events)
	require.Empty(t, res.Derivatives)
	require.Empty(t, res.Actions)
	require.False(t, res.Keep)
}
