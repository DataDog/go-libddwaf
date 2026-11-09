// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waferrors

import (
	"errors"
	"fmt"
)

var (
	// ErrContextClosed is returned when an operation is attempted on a
	// [github.com/DataDog/go-libddwaf/v5.Context] that has already been closed.
	ErrContextClosed = errors.New("closed WAF context")

	// ErrMaxDepthExceeded is returned when the WAF encounters a value that
	// exceeds the maximum depth.
	ErrMaxDepthExceeded = errors.New("max depth exceeded")
	// ErrUnsupportedValue is returned when the WAF encounters a value that
	// is not supported by the encoder or decoder.
	ErrUnsupportedValue = errors.New("unsupported Go value")
	// ErrInvalidMapKey is returned when the WAF encounters an invalid map key.
	ErrInvalidMapKey = errors.New("invalid WAF object map key")
	// ErrNilObjectPtr is returned when the WAF encounters a nil object pointer at
	// an unexpected location.
	ErrNilObjectPtr = errors.New("nil WAF object pointer")
	// ErrInvalidObjectType is returned when the WAF encounters an invalid type
	// when decoding a value.
	ErrInvalidObjectType = errors.New("invalid type encountered when decoding")
	// ErrTooManyIndirections is returned when the WAF encounters a value that
	// exceeds the maximum number of indirections (pointer to pointer to...).
	ErrTooManyIndirections = errors.New("too many indirections")
	// ErrHandleReleased is returned when an operation is attempted on a
	// [github.com/DataDog/go-libddwaf/v5.Handle] whose reference count has
	// reached zero.
	ErrHandleReleased = errors.New("WAF handle has been released")

	// ErrBuilderInitFailed is returned when the C library fails to allocate
	// a WAF builder.
	ErrBuilderInitFailed = errors.New("failed to initialize the WAF builder")

	// ErrContextInitFailed is returned when the C library fails to allocate
	// a WAF context.
	ErrContextInitFailed = errors.New("failed to initialize WAF context")

	// ErrUnknownReturnCode wraps an unexpected return code from the C library.
	ErrUnknownReturnCode = errors.New("unknown WAF return code")

	// ErrResultInvalidType is returned when unwrapping a WAF result encounters
	// an object whose type is not expected for that field.
	ErrResultInvalidType = errors.New("invalid WAF result object type")

	// ErrNilContext is returned when a nil context.Context is passed where a
	// non-nil one is required.
	ErrNilContext = errors.New("nil context.Context")

	// ErrBinaryNotString is returned by the decoder when a value expected to be
	// a string is not actually a string/[]byte.
	ErrBinaryNotString = errors.New("WAF object value is not a string")
)

// RunError represents an error returned by the WAF during a run.
type RunError int

// RunError values returned by the WAF.
const (
	// ErrInternal denotes a WAF internal error.
	ErrInternal RunError = iota + 1
	// ErrInvalidObject is returned when the WAF received an invalid object.
	ErrInvalidObject
	// ErrInvalidArgument is returned when the WAF received an invalid argument.
	ErrInvalidArgument
	// ErrTimeout is returned when the WAF ran out of time budget to spend.
	ErrTimeout
	// ErrOutOfMemory is returned when the WAF ran out of memory when trying to
	// allocate a result object.
	ErrOutOfMemory
	// ErrEmptyRuleAddresses is returned when the WAF received an empty list of
	// rule addresses.
	ErrEmptyRuleAddresses
)

// Error returns the string representation of the [RunError].
func (e RunError) Error() string {
	switch e {
	case ErrInternal:
		return "internal waf error"
	case ErrInvalidObject:
		return "invalid waf object"
	case ErrInvalidArgument:
		return "invalid waf argument"
	case ErrTimeout:
		return "waf timeout"
	case ErrOutOfMemory:
		return "out of memory"
	case ErrEmptyRuleAddresses:
		return "empty rule addresses"
	default:
		return fmt.Sprintf("unknown waf error %d", int(e))
	}
}

// ToWafErrorCode converts an error to a WAF error code, returns zero if the
// error is not a [RunError]. To get the ddwaf_run return code, use
// [ToWafReturnCode].
func ToWafErrorCode(in error) int {
	var runError RunError
	if !errors.As(in, &runError) {
		return 0
	}
	return int(runError)
}

// bindingErrorCode is the reporting fallback when an error has no recognized
// ddwaf_run return code. libddwaf never returns it. The Datadog tracers report
// it for errors from the bindings (RFC-1012).
const bindingErrorCode = -127

// ToWafReturnCode returns the error code to report for an error from
// go-libddwaf.
//
// Recognized errors use the native ddwaf_run return codes (DDWAF_RET_CODE):
// -3 for [ErrInternal], -2 for [ErrInvalidObject] and -1 for
// [ErrInvalidArgument]. -127 is the reporting fallback when no recognized code
// is available: for any other error, including an unknown return code of
// libddwaf ([ErrUnknownReturnCode] keeps that code only in its message).
//
// A timeout ([ErrTimeout]) is not an error code: on a timeout, ddwaf_run
// returns DDWAF_OK or DDWAF_MATCH. A timeout gives no code, and it never hides
// another error of the tree. ToWafReturnCode returns zero when there is no
// error to report: a nil error, or an error tree that holds only timeouts.
// Zero means no error to report; it does not distinguish DDWAF_OK from
// DDWAF_MATCH. To know if a timeout occurred, use errors.Is(err, [ErrTimeout]).
// It finds the timeout errors that go-libddwaf returns, but not a custom error
// that only has an As method. A timeout can also happen in Go before ddwaf_run
// is called, when the time budget is already used up.
//
// It looks at every error of the tree: the error itself, and the errors of its
// Unwrap() error or Unwrap() []error method (for example [errors.Join]). An
// error matches a [RunError] with the same rules as one step of [errors.As]
// (its type, or its As(any) bool method). Unlike [errors.As], a match does not
// stop the search: the errors that it wraps are looked at too. It visits the
// errors in the same order as [errors.As]: an error before the errors that it
// wraps, and the errors of Unwrap() []error from left to right. When the tree
// holds more than one code, it returns the highest one (the closest to zero).
// Like [errors.As], it does not detect a cycle in the tree.
//
// [ToWafErrorCode] returns the positive [RunError] value instead.
func ToWafReturnCode(in error) int {
	best, found := 0, false
	keep := func(code int) {
		if !found || code > best {
			best, found = code, true
		}
	}

	work := []error{in}
	for len(work) > 0 {
		err := work[len(work)-1]
		work = work[:len(work)-1]
		if err == nil {
			continue
		}

		var runErr RunError
		matched := asRunError(err, &runErr)
		if matched {
			switch runErr {
			case ErrInternal:
				keep(-3) // DDWAF_ERR_INTERNAL
			case ErrInvalidObject:
				keep(-2) // DDWAF_ERR_INVALID_OBJECT
			case ErrInvalidArgument:
				keep(-1) // DDWAF_ERR_INVALID_ARGUMENT
			case ErrTimeout:
				// A timeout gives no code, but the errors it wraps still count.
			default:
				keep(bindingErrorCode)
			}
		}

		children := false
		switch x := err.(type) { //nolint:errorlint // one step of the walk: the loop visits the wrapped errors itself
		case interface{ Unwrap() error }:
			if inner := x.Unwrap(); inner != nil {
				work = append(work, inner)
				children = true
			}
		case interface{ Unwrap() []error }:
			// Push in reverse order, so that the errors are visited from left to right.
			inners := x.Unwrap()
			for i := len(inners) - 1; i >= 0; i-- {
				if inners[i] != nil {
					work = append(work, inners[i])
					children = true
				}
			}
		}

		if !matched && !children {
			keep(bindingErrorCode) // a leaf that is not a RunError
		}
	}

	if !found {
		return 0
	}
	return best
}

// asRunError reports whether err itself (not the errors it wraps) is a
// [RunError], with the same rules as one step of [errors.As].
func asRunError(err error, target *RunError) bool {
	if r, ok := err.(RunError); ok { //nolint:errorlint // one step of errors.As: the caller visits the wrapped errors itself
		*target = r
		return true
	}
	if x, ok := err.(interface{ As(any) bool }); ok && x.As(target) {
		return true
	}
	return false
}

// PanicError is an error type wrapping a recovered panic value that happened
// during a function call. Such error must be considered unrecoverable and be
// used to try to gracefully abort. Keeping using this package after such an
// error is unreliable and the caller must rather stop using the library.
// Examples include safety checks errors.
type PanicError struct {
	// The recovered panic error while executing the function `in`.
	Err error
	// The function symbol name that was given to `tryCall()`.
	In string
}

// Unwrap the error and return it.
// Required by errors.Is and errors.As functions.
func (e *PanicError) Unwrap() error {
	return e.Err
}

// Error returns the error string representation.
func (e *PanicError) Error() string {
	return fmt.Sprintf("panic while executing %s: %v", e.In, e.Err)
}
