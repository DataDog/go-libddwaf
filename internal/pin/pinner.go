// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package pin

import (
	"runtime"
	"sync"
	"sync/atomic"
	_ "unsafe"
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

const (
	minShardCount = 4
	maxShardCount = 64
)

var (
	shardCount = selectShardCount(runtime.NumCPU())
	shardMask  = shardCount - 1
)

type shard struct {
	mu     sync.Mutex
	pinner runtime.Pinner
}

// ConcurrentPinner is a [Pinner] that is safe for concurrent use by multiple
// goroutines.
type ConcurrentPinner struct {
	shards [maxShardCount]shard
	closed atomic.Bool
}

var shardFallbackCounter atomic.Uint64

func selectShardCount(cpuCount int) int {
	if cpuCount < minShardCount {
		return minShardCount
	}
	if cpuCount > maxShardCount {
		cpuCount = maxShardCount
	}

	count := minShardCount
	for count < cpuCount {
		count <<= 1
	}
	if count > maxShardCount {
		return maxShardCount
	}
	return count
}

func cheapShardIndex() int {
	if idx := procPinShardIndex(); idx >= 0 {
		return idx
	}
	return fallbackShardIndex()
}

func procPinShardIndex() int {
	idx := runtimeProcPin()
	runtimeProcUnpin()
	return idx & shardMask
}

func fallbackShardIndex() int {
	return int(shardFallbackCounter.Add(1)-1) & shardMask
}

//go:linkname runtimeProcPin sync.runtime_procPin
func runtimeProcPin() int

//go:linkname runtimeProcUnpin sync.runtime_procUnpin
func runtimeProcUnpin()

func (p *ConcurrentPinner) Pin(v any) {
	if p.closed.Load() {
		return
	}

	s := &p.shards[cheapShardIndex()]
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.closed.Load() {
		return
	}
	s.pinner.Pin(v)
}

func (p *ConcurrentPinner) Unpin() {
	for i := range shardCount {
		p.shards[i].mu.Lock()
	}
	for i := range shardCount {
		p.shards[i].pinner.Unpin()
	}
	for i := range shardCount {
		p.shards[i].mu.Unlock()
	}
}

func (p *ConcurrentPinner) Close() {
	p.closed.Store(true)
	p.Unpin()
}
