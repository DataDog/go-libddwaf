// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/require"
)

func TestHandleRefcountStress(t *testing.T) {
	handle := &Handle{}
	handle.refCounter.Store(1)

	var wg sync.WaitGroup
	barrier := make(chan struct{})

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier
			for j := 0; j < 100; j++ {
				if handle.retain() {
					handle.Close()
				}
			}
		}()
	}

	close(barrier)
	wg.Wait()

	require.EqualValues(t, 1, handle.refCounter.Load())
	require.Zero(t, handle.addRefCounter(-1))
	require.Zero(t, handle.refCounter.Load())
}

func TestHandleRefcountUnderflowSilentInProd(t *testing.T) {
	handle := &Handle{}
	handle.refCounter.Store(1)

	result := handle.addRefCounter(-2)

	require.Zero(t, result)
	require.Zero(t, handle.refCounter.Load())
}

func TestHandleNewContext(t *testing.T) {
	waf, _, err := newDefaultHandle(testArachniRule)
	require.NoError(t, err)
	defer waf.Close()

	t.Run("nil-context-returns-ErrNilContext", func(t *testing.T) {
		wafCtx, err := waf.NewContext(nil)
		require.Nil(t, wafCtx)
		require.EqualError(t, err, "Handle.NewContext: nil context.Context")
		require.ErrorIs(t, err, waferrors.ErrNilContext)
	})

	t.Run("cancelled-context-returns-context-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		wafCtx, err := waf.NewContext(ctx)
		require.Nil(t, wafCtx)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("deadline-exceeded-context-returns-context-error", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		wafCtx, err := waf.NewContext(ctx)
		require.Nil(t, wafCtx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}
