// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/require"
)

func TestContextRunCloseRace(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)

	subCtx, err := ctx.SubContext(context.Background())
	require.NoError(t, err)

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	const (
		nbWorkers = 100
		nbRuns    = 100
	)

	errCh := make(chan error, nbWorkers)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for worker := range nbWorkers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start

			for run := range nbRuns {
				_, err := subCtx.Run(context.Background(), data)
				if err != nil && !errors.Is(err, waferrors.ErrContextClosed) {
					errCh <- fmt.Errorf("worker %d run %d: %w", worker, run, err)
					return
				}
			}
		}(worker)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		time.Sleep(time.Millisecond)
		ctx.Close()
	}()

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	subCtx.Close()
}

func TestContextCloseWaitsForActiveRun(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)

	ctx.root.activeRuns.Add(1)

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		ctx.Close()
	}()

	select {
	case <-closed:
		t.Fatal("Close returned while activeRuns was non-zero")
	case <-time.After(10 * time.Millisecond):
	}

	ctx.root.activeRuns.Add(-1)

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after activeRuns reached zero")
	}
}
