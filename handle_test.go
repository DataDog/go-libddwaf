// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"sync"
	"testing"

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
