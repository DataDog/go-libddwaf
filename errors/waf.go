package errors

import (
	"errors"
	"fmt"
)

// Encoder/Decoder errors
var (
	ErrMaxDepthExceeded    = errors.New("max depth exceeded")
	ErrUnsupportedValue    = errors.New("unsupported Go value")
	ErrInvalidMapKey       = errors.New("invalid WAF object map key")
	ErrNilObjectPtr        = errors.New("nil WAF object pointer")
	ErrInvalidObjectType   = errors.New("invalid type encountered when decoding")
	ErrTooManyIndirections = errors.New("too many indirections")
)

// RunError the WAF can return when running it.
type RunError int

// Errors the WAF can return when running it.
const (
	ErrInternal RunError = iota + 1
	ErrInvalidObject
	ErrInvalidArgument
	ErrTimeout
	ErrOutOfMemory
	ErrEmptyRuleAddresses
)

// Error returns the string representation of the RunError.
func (e RunError) Error() string {
	switch e {
	case ErrInternal:
		return "internal waf error"
	case ErrTimeout:
		return "waf timeout"
	case ErrInvalidObject:
		return "invalid waf object"
	case ErrInvalidArgument:
		return "invalid waf argument"
	case ErrOutOfMemory:
		return "out of memory"
	case ErrEmptyRuleAddresses:
		return "empty rule addresses"
	default:
		return fmt.Sprintf("unknown waf error %d", e)
	}
}
