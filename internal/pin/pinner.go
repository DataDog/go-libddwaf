// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package pin

import (
	"runtime"
	"sync"
	"sync/atomic"
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
// goroutines.
type ConcurrentPinner struct {
	pinner runtime.Pinner
	mu     sync.Mutex
	closed atomic.Bool
}

func (p *ConcurrentPinner) Pin(v any) {
	if p.closed.Load() {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return
	}
	p.pinner.Pin(v)
}

func (p *ConcurrentPinner) Unpin() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pinner.Unpin()
}

func (p *ConcurrentPinner) Close() {
	p.closed.Store(true)
	p.Unpin()
}
