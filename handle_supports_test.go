// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.28 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleSupports(t *testing.T) {
	rule := newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil)
	h, _, err := newDefaultHandle(t, rule)
	require.NoError(t, err)

	t.Run("known address returns true", func(t *testing.T) {
		require.True(t, h.Supports("my.input"))
	})

	t.Run("unknown address returns false", func(t *testing.T) {
		require.False(t, h.Supports("not.an.address"))
	})

	t.Run("repeated calls are consistent (lazy cache hit)", func(t *testing.T) {
		require.True(t, h.Supports("my.input"))
		require.False(t, h.Supports("not.an.address"))
	})

	// Exercise the closed-handle guard on a handle that has NEVER had Supports
	// called before Close, so the addrSet cache is definitely cold.
	t.Run("closed handle guard (cold cache)", func(t *testing.T) {
		rule2 := newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil)
		h2, _, err := newDefaultHandle(t, rule2)
		require.NoError(t, err)
		h2.Close()
		// refCounter <= 0 now; must return false without crashing
		require.False(t, h2.Supports("not_yet_cached_addr"))
	})

	h.Close()
}

// TestHandleSupportsConcurrentClose exercises the fix for the use-after-free
// and data race that existed when a concurrent final Close could destroy the
// C handle between the nil-guard check and the KnownAddresses call inside
// addrOnce.Do.
//
// The test spawns N goroutines that call Supports concurrently with one
// goroutine that calls Close. It makes no assertion on the boolean return
// value (either true or false is valid depending on scheduling); the only
// assertion is that there is no panic and that go test -race reports no
// data race.
func TestHandleSupportsConcurrentClose(t *testing.T) {
	rule := newArachniTestRule(t, []ruleInput{{Address: "my.input"}}, nil)
	h, _, err := newDefaultHandle(t, rule)
	require.NoError(t, err)

	const n = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n + 1)

	for range n {
		go func() {
			defer wg.Done()
			<-start
			// Tolerate true or false — the assertion is no data race / no panic.
			_ = h.Supports("my.input")
		}()
	}

	go func() {
		defer wg.Done()
		<-start
		h.Close()
	}()

	close(start)
	wg.Wait()
}
