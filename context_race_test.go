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
	"runtime"
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
	t.Cleanup(func() { waf.Close() })

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
	t.Cleanup(func() { waf.Close() })

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

func TestContextRunClosePinnedPointerLeakRegression(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string][]string{
			"user-agent":      {"Arachni/test", "curl/8.0"},
			"accept":          {"application/json", "text/html", "*/*"},
			"accept-encoding": {"gzip", "deflate", "br"},
			"x-forwarded-for": {"1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"},
			"x-custom":        {"a", "b", "c", "d", "e", "f", "g", "h"},
		},
	}}

	const iterations = 1000
	for range iterations {
		ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-start
			_, err := ctx.Run(context.Background(), data)
			if err != nil && !errors.Is(err, waferrors.ErrContextClosed) {
				t.Errorf("Run returned unexpected error: %v", err)
			}
		}()

		go func() {
			defer wg.Done()
			<-start
			ctx.Close()
		}()

		close(start)
		wg.Wait()
		runtime.Gosched()
	}

	runtime.GC()
	runtime.GC()
	runtime.GC()
}

func TestConcurrentSiblingSubcontextsRun(t *testing.T) {
	waf, _, err := newDefaultHandle(t, newArachniTestRule(t, []ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { waf.Close() })

	ctx, err := waf.NewContext(context.Background(), timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)

	const (
		nbWorkers = 8
		nbRuns    = 100
	)

	subCtxs := make([]*Context, 0, nbWorkers)
	for range nbWorkers {
		subCtx, err := ctx.SubContext(context.Background())
		require.NoError(t, err)
		subCtxs = append(subCtxs, subCtx)
	}

	data := RunAddressData{Data: map[string]any{
		"server.request.headers.no_cookies": map[string]string{
			"user-agent": "Arachni/test",
		},
	}}

	errCh := make(chan error, nbWorkers)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for worker, subCtx := range subCtxs {
		wg.Add(1)
		go func(worker int, subCtx *Context) {
			defer wg.Done()
			<-start

			for run := range nbRuns {
				_, err := subCtx.Run(context.Background(), data)
				if err != nil && !errors.Is(err, waferrors.ErrContextClosed) {
					errCh <- fmt.Errorf("worker %d run %d: %w", worker, run, err)
					return
				}
			}
		}(worker, subCtx)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	for _, subCtx := range subCtxs {
		subCtx.Close()
	}
	ctx.Close()
}
