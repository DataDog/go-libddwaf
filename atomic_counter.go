// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
package waf

import "go.uber.org/atomic"

// Atomic reference counter helper initialized at 1 so that 0 is the special
// value meaning that the object was released and is no longer usable.
type atomicRefCounter atomic.Uint32

func (c *atomicRefCounter) unwrap() *atomic.Uint32 {
	return (*atomic.Uint32)(c)
}

// Add delta to reference counter.
// It relies on a CAS spin-loop implementation in order to avoid changing the
// counter when 0 has been reached.
func (c *atomicRefCounter) add(delta uint32) uint32 {
	addr := c.unwrap()
	for {
		current := addr.Load()
		if current == 0 {
			// The object was released
			return 0
		}
		new := current + delta
		if swapped := addr.CompareAndSwap(current, new); swapped {
			return new
		}
	}
}

// Increment the reference counter.
// CAS spin-loop implementation in order to enforce +1 cannot happen when 0 has
// been reached.
func (c *atomicRefCounter) increment() uint32 {
	return c.add(1)
}

// Decrement the reference counter.
// CAS spin-loop implementation in order to enforce +1 cannot happen when 0 has
// been reached.
func (c *atomicRefCounter) decrement() uint32 {
	const d = ^uint32(0)
	return c.add(d)
}
