// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/DataDog/go-libddwaf/v4/errors"
	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/timer"
)

// Handle represents an instance of the WAF for a given ruleset. It is obtained
// from [Builder.Build]; and must be disposed of by calling [Handle.Close]
// once no longer in use.
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

	// Instance of the WAF
	cHandle bindings.WafHandle
}

// wrapHandle wraps the provided C handle into a [Handle]. The caller is
// responsible to ensure the cHandle value is not 0 (NULL). The returned
// [Handle] has a reference count of 1, so callers need not call [Handle.retain]
// on it.
func wrapHandle(cHandle bindings.WafHandle) *Handle {
	handle := &Handle{cHandle: cHandle}
	handle.refCounter.Store(1) // We count the handle itself in the counter
	return handle
}

// NewContextWithBudget returns a new WAF context for the given WAF handle.
// A nil value is returned when the WAF handle was released or when the
// WAF context couldn't be created.
func (handle *Handle) NewContextWithBudget(budget time.Duration) (*Context, error) {
	// Handle has been released
	if !handle.retain() {
		return nil, fmt.Errorf("handle was released")
	}

	cContext := wafLib.WafContextInit(handle.cHandle)
	if cContext == 0 {
		handle.Close() // We couldn't get a context, so we no longer have an implicit reference to the Handle in it...
		return nil, fmt.Errorf("could not get C context")
	}

	timer, err := timer.NewTreeTimer(timer.WithBudget(budget), timer.WithComponents(wafRunTag))
	if err != nil {
		return nil, err
	}

	return &Context{
		handle:      handle,
		cContext:    cContext,
		timer:       timer,
		metrics:     metricsStore{data: make(map[metricKey]time.Duration, 5)},
		truncations: make(map[Scope]map[TruncationReason][]int, 2),
		timeoutCount: map[Scope]*atomic.Uint64{
			DefaultScope: new(atomic.Uint64),
			RASPScope:    new(atomic.Uint64),
		},
	}, nil
}

// Addresses returns the list of addresses the WAF has been configured to monitor based on the input
// ruleset.
func (handle *Handle) Addresses() []string {
	return wafLib.WafKnownAddresses(handle.cHandle)
}

// Actions returns the list of actions the WAF has been configured to monitor based on the input
// ruleset.
func (handle *Handle) Actions() []string {
	return wafLib.WafKnownActions(handle.cHandle)
}

// Close decrements the reference counter of this [Handle], possibly allowing it to be destroyed
// and all the resources associated with it to be released.
func (handle *Handle) Close() {
	if handle.addRefCounter(-1) != 0 {
		// Either the counter is still positive (this Handle is still referenced), or it had previously
		// reached 0 and some other call has done the cleanup already.
		return
	}

	wafLib.WafDestroy(handle.cHandle)
	handle.cHandle = 0 // Makes it easy to spot use-after-free/double-free issues
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
		if swapped := handle.refCounter.CompareAndSwap(current, next); swapped {
			if next < 0 {
				// TODO(romain.marcadier): somehow signal unexpected behavior to the
				// caller (panic? error?). We currently clamp to 0 in order to avoid
				// causing a customer program crash, but this is the symptom of a bug
				// and should be investigated (however this clamping hides the issue).
				return 0
			}
			return next
		}
	}
}

func newConfig(pinner *runtime.Pinner, keyObfuscatorRegex string, valueObfuscatorRegex string) *bindings.WafConfig {
	return &bindings.WafConfig{
		Limits: bindings.WafConfigLimits{
			MaxContainerDepth: bindings.WafMaxContainerDepth,
			MaxContainerSize:  bindings.WafMaxContainerSize,
			MaxStringLength:   bindings.WafMaxStringLength,
		},
		Obfuscator: bindings.WafConfigObfuscator{
			KeyRegex:   cString(pinner, keyObfuscatorRegex),
			ValueRegex: cString(pinner, valueObfuscatorRegex),
		},
		// Prevent libddwaf from freeing our Go-memory-allocated ddwaf_objects
		FreeFn: 0,
	}
}

// cString allocates a C-string with the contents of str and pins it using the
// provided [*runtime.Pinner].
func cString(pinner *runtime.Pinner, str string) uintptr {
	cstr := make([]byte, len(str)+1)
	copy(cstr, []byte(str))
	data := unsafe.Pointer(unsafe.SliceData(cstr))
	pinner.Pin(data)
	return uintptr(data)
}

func goRunError(rc bindings.WafReturnCode) error {
	switch rc {
	case bindings.WafErrInternal:
		return errors.ErrInternal
	case bindings.WafErrInvalidObject:
		return errors.ErrInvalidObject
	case bindings.WafErrInvalidArgument:
		return errors.ErrInvalidArgument
	case bindings.WafOK, bindings.WafMatch:
		// No error...
		return nil
	default:
		return fmt.Errorf("unknown waf return code %d", int(rc))
	}
}
