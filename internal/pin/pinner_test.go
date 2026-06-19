// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package pin

import (
	"runtime"
	"sync"
	"testing"
)

// TestConcurrentPinnerPinAfterCloseIsNoop asserts that once Close has put the
// pinner into its terminal state, any subsequent Pin call is a silent no-op
// that does not leak onto the pinner. If the no-op were missing, the pinned
// value would survive the Close's Unpin and the runtime.Pinner finalizer
// would panic with "found leaking pinned pointer" when the pinner is GC'd.
func TestConcurrentPinnerPinAfterCloseIsNoop(t *testing.T) {
	p := &ConcurrentPinner{}

	payload := make([]byte, 64)
	p.Pin(&payload[0])
	p.Close()

	later := make([]byte, 64)
	p.Pin(&later[0]) // terminal state: no-op, does not panic

	// Drop all references and verify the pinner is safely collectable. A
	// regression that pinned after Close would surface here as a finalizer
	// panic that kills the test process.
	p = nil
	runtime.GC()
	runtime.GC()
	runtime.GC()
}

// TestConcurrentPinnerDoubleClose guards against regressions where Close is
// not idempotent. Closing a ConcurrentPinner twice must be safe; the second
// call is a no-op (Unpin on an empty runtime.Pinner is fine, and closed is
// already true).
func TestConcurrentPinnerDoubleClose(t *testing.T) {
	p := &ConcurrentPinner{}

	payload := make([]byte, 16)
	p.Pin(&payload[0])

	p.Close()
	p.Close() // must not panic, must not re-unpin anything

	runtime.GC()
	runtime.GC()
}

// TestConcurrentPinnerCloseRaceNoLeak is the unit-level analog of the
// context_race_test.go integration test. Many goroutines call Pin on the
// shared pinner while one goroutine calls Close. If the terminal-state
// gate in Pin is missing or racy, Pin calls landing after Close.Unpin
// leak values onto the runtime.Pinner and the finalizer panics on the
// subsequent GC. With the gate in place this test passes cleanly under
// -race as well.
func TestConcurrentPinnerCloseRaceNoLeak(t *testing.T) {
	const iterations = 2000
	const pinnersPerIter = 8

	for range iterations {
		p := &ConcurrentPinner{}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(pinnersPerIter + 1)

		for range pinnersPerIter {
			buf := make([]byte, 32)
			go func(b []byte) {
				defer wg.Done()
				<-start
				p.Pin(&b[0])
			}(buf)
		}

		go func() {
			defer wg.Done()
			<-start
			p.Close()
		}()

		close(start)
		wg.Wait()

		// Encourage scheduler interleaving before the next iteration.
		runtime.Gosched()
	}

	// Force the finalizer goroutine to run. Any pinner that ended up with
	// post-Close leaked values would panic here.
	runtime.GC()
	runtime.GC()
	runtime.GC()
}
