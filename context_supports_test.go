// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.28 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/timer"
)

func TestContextSupports(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	require.True(t, ctx.Supports("my.input"))
	require.False(t, ctx.Supports("nope"))
}

func TestSubcontextSupports(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	t.Cleanup(func() { ctx.Close() })

	subCtx, err := ctx.NewSubcontext(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { subCtx.Close() })

	require.True(t, subCtx.Supports("my.input"))
	require.False(t, subCtx.Supports("nope"))
}
