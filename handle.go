// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"fmt"
	"sync/atomic"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/invariant"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// Handle represents an instance of the WAF for a given ruleset. It is obtained
// from [Builder.Build]; and must be disposed of by calling [Handle.Close]
// once no longer in use.
//
// Library lifetime boundary: [Handle.retain] and [Handle.Close] only govern the
// lifetime of the underlying C ddwaf_handle. They do not keep the libddwaf
// shared library loaded. That shared library is a process-wide singleton
// loaded once via purego.Dlopen (see internal/bindings) and is never Dlclosed
// during normal operation. As a consequence, symbols such as
// bindings.Lib.ContextDestroy or bindings.Lib.SubcontextDestroy remain
// resolvable for the entire lifetime of the process, and Context/SubContext
// teardown paths that call into bindings.Lib after the Handle's refcount has
// reached zero are safe with respect to the library itself.
type Handle struct {
	// Lock-less reference counter avoiding blocking calls to the [Handle.Close]
	// method while WAF [Context]s are still using the WAF handle. Instead, we let
	// the release actually happen only when the reference counter reaches 0.
	// This can happen either from a request handler calling its WAF context's
	// [Context.Close] method, or either from the appsec instance calling the WAF
	// [Handle.Close] method when creating a new WAF handle with new rules.
	// Note that this means several instances of the WAF can exist at the same
	// time with their own set of rules. This choice was done to be able to
	// efficiently update the security rules concurrently, without having to
	// block the request handlers for the time of the security rules update.
	refCounter atomic.Int32

	cHandle bindings.WAFHandle
}

// wrapHandle wraps the provided C handle into a [Handle]. The caller is
// responsible to ensure the cHandle value is not 0 (NULL). The returned
// [Handle] has a reference count of 1, so callers need not call [Handle.retain]
// on it.
func wrapHandle(cHandle bindings.WAFHandle) *Handle {
	handle := &Handle{cHandle: cHandle}
	handle.refCounter.Store(1)
	return handle
}

// NewContext returns a new WAF context for the given WAF handle.
// An error is returned when the WAF handle was released or when the WAF context
// couldn't be created.
func (handle *Handle) NewContext(timerOptions ...timer.Option) (*Context, error) {
	if !handle.retain() {
		return nil, waferrors.ErrHandleReleased
	}

	cContext := bindings.Lib.ContextInit(handle.cHandle, bindings.Lib.DefaultAllocator())
	if cContext == 0 {
		handle.Close() // We couldn't get a context, so we no longer have an implicit reference to the Handle in it...
		return nil, fmt.Errorf("%w: ddwaf_context_init returned null", waferrors.ErrContextInitFailed)
	}

	rootTimer, err := timer.NewTreeTimer(timerOptions...)
	if err != nil {
		bindings.Lib.ContextDestroy(cContext)
		handle.Close()
		return nil, fmt.Errorf("failed to create WAF context timer: %w", err)
	}

	return &Context{
		handle:      handle,
		root:        &contextRoot{cContext: cContext},
		Timer:       rootTimer,
		truncations: make(map[TruncationReason][]int, numTruncationReasons),
	}, nil
}

// Addresses returns the list of addresses the WAF has been configured to monitor based on the input
// ruleset.
func (handle *Handle) Addresses() []string {
	return bindings.Lib.KnownAddresses(handle.cHandle)
}

// Actions returns the list of actions the WAF has been configured to monitor based on the input
// ruleset.
func (handle *Handle) Actions() []string {
	return bindings.Lib.KnownActions(handle.cHandle)
}

// Close decrements the reference counter of this [Handle], possibly allowing it to be destroyed
// and all the resources associated with it to be released.
func (handle *Handle) Close() {
	if handle.addRefCounter(-1) != 0 {
		return
	}

	bindings.Lib.Destroy(handle.cHandle)
	handle.cHandle = 0
}

// retain increments the reference counter of this [Handle]. Returns true if the
// [Handle] is still valid, false if it is no longer usable. Calls to
// [Handle.retain] must be balanced with calls to [Handle.Close] in order to
// avoid leaking [Handle]s.
func (handle *Handle) retain() bool {
	return handle.addRefCounter(1) > 0
}

// addRefCounter adds x to Handle.refCounter. The return valid indicates whether the refCounter
// reached 0 as part of this call or not, which can be used to perform "only-once" activities:
//
// * result > 0    => the Handle is still usable
// * result == 0   => the handle is no longer usable, ref counter reached 0 as part of this call
// * result == -1  => the handle is no longer usable, ref counter was already 0 previously
func (handle *Handle) addRefCounter(x int32) int32 {
	// We use a CAS loop to avoid setting the refCounter to a negative value.
	for {
		current := handle.refCounter.Load()
		if current <= 0 {
			// The object had already been released
			return -1
		}

		next := current + x
		if next < 0 {
			if swapped := handle.refCounter.CompareAndSwap(current, 0); swapped {
				// Refcount underflow is surfaced via internal/invariant under ci builds (see ADR-003).
				invariant.Assert(false, "refCounter went negative: current=%d, delta=%d", current, x)
				return 0
			}
			continue
		}

		if swapped := handle.refCounter.CompareAndSwap(current, next); swapped {
			return next
		}
	}
}

func goRunError(rc bindings.WAFReturnCode) error {
	switch rc {
	case bindings.WAFErrInternal:
		return waferrors.ErrInternal
	case bindings.WAFErrInvalidObject:
		return waferrors.ErrInvalidObject
	case bindings.WAFErrInvalidArgument:
		return waferrors.ErrInvalidArgument
	case bindings.WAFOK, bindings.WAFMatch:
		return nil
	default:
		return fmt.Errorf("%w: %d", waferrors.ErrUnknownReturnCode, int(rc))
	}
}
