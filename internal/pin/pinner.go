// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package pin

import (
	"runtime"
	"sync"
)

// A Pinner is a set of Go objects each pinned to a fixed location in memory.
// The [Pinner.Pin] method pins one object, while [Pinner.Unpin] unpins all
// pinned objects. See their comments for more information.
type Pinner interface {
	// Pin pins a Go object, preventing it from being moved or freed by the
	// garbage collector until the [Pinner.Unpin] method has been called.
	//
	// A pointer to a pinned object can be directly stored in C memory or can be
	// contained in Go memory passed to C functions. If the pinned object itself
	// contains pointers to Go objects, these objects must be pinned separately if
	// they are going to be accessed from C code.
	//
	// The argument must be a pointer of any type or an [unsafe.Pointer].
	// It's safe to call Pin on non-Go pointers, in which case Pin will do
	// nothing.
	Pin(any)

	// Unpin unpins all pinned objects of the [Pinner].
	Unpin()
}

var _ Pinner = (*runtime.Pinner)(nil)

// ConcurrentPinner is a [Pinner] that is safe for concurrent use by multiple
// goroutines. Once [ConcurrentPinner.Close] has been called, the pinner is in
// a terminal state and any subsequent [ConcurrentPinner.Pin] call is a no-op.
// A closed pinner cannot be reused.
type ConcurrentPinner struct {
	runtime.Pinner
	sync.Mutex
	closed bool
}

// Pin pins v unless the pinner has already been closed, in which case it is
// a no-op. This terminal-state behavior prevents a race where [Pin] calls
// arriving after a concurrent [Close] would leak onto the already-released
// pinner and trigger the runtime.Pinner finalizer panic on the next GC.
func (p *ConcurrentPinner) Pin(v any) {
	p.Lock()
	defer p.Unlock()
	if p.closed {
		return
	}
	p.Pinner.Pin(v)
}

// Unpin unpins every currently-pinned object. It does not put the pinner
// into the terminal state; future Pin calls are still accepted. Use [Close]
// when the pinner is being torn down for good.
func (p *ConcurrentPinner) Unpin() {
	p.Lock()
	defer p.Unlock()
	p.Pinner.Unpin()
}

// Close unpins every currently-pinned object and puts the pinner into a
// terminal state where future [Pin] calls are no-ops. A closed pinner
// cannot be reused. Calling Close multiple times is safe.
func (p *ConcurrentPinner) Close() {
	p.Lock()
	defer p.Unlock()
	p.closed = true
	p.Pinner.Unpin()
}
