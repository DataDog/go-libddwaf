package waferrors_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

func TestPanicErrorFormat(t *testing.T) {
	inner := errors.New("out of memory")
	pe := &waferrors.PanicError{Err: inner, In: "ddwaf_run"}

	got := pe.Error()
	want := "panic while executing ddwaf_run: out of memory"
	if got != want {
		t.Errorf("PanicError.Error() = %q, want %q", got, want)
	}
}

func TestPanicErrorUnwrap(t *testing.T) {
	inner := errors.New("out of memory")
	pe := &waferrors.PanicError{Err: inner, In: "ddwaf_run"}

	if !errors.Is(pe, inner) {
		t.Errorf("errors.Is(PanicError, inner) = false, want true")
	}
}

func TestGoRunErrorUnknownCode(t *testing.T) {
	code := waferrors.RunError(99)
	err := error(code)

	if !errors.As(err, &code) {
		t.Errorf("errors.As(unknown RunError, &code) = false, want true")
	}
	if waferrors.ToWafErrorCode(err) != 99 {
		t.Errorf("ToWafErrorCode(RunError(99)) = %d, want 99", waferrors.ToWafErrorCode(err))
	}
}

func TestRunErrorString(t *testing.T) {
	for _, tc := range []struct {
		err  waferrors.RunError
		want string
	}{
		{waferrors.ErrInternal, "internal waf error"},
		{waferrors.ErrInvalidObject, "invalid waf object"},
		{waferrors.ErrInvalidArgument, "invalid waf argument"},
		{waferrors.ErrTimeout, "waf timeout"},
		{waferrors.ErrOutOfMemory, "out of memory"},
		{waferrors.ErrEmptyRuleAddresses, "empty rule addresses"},
		{waferrors.RunError(123), "unknown waf error 123"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("RunError(%d).Error() = %q, want %q", int(tc.err), got, tc.want)
		}
	}
}

func TestToWafErrorCode(t *testing.T) {
	if code := waferrors.ToWafErrorCode(errors.New("not a run error")); code != 0 {
		t.Errorf("ToWafErrorCode(non-RunError) = %d, want 0", code)
	}
	if code := waferrors.ToWafErrorCode(nil); code != 0 {
		t.Errorf("ToWafErrorCode(nil) = %d, want 0", code)
	}
	if code := waferrors.ToWafErrorCode(waferrors.ErrTimeout); code != int(waferrors.ErrTimeout) {
		t.Errorf("ToWafErrorCode(ErrTimeout) = %d, want %d", code, int(waferrors.ErrTimeout))
	}

	wrapped := fmt.Errorf("during run: %w", waferrors.ErrInternal)
	if code := waferrors.ToWafErrorCode(wrapped); code != int(waferrors.ErrInternal) {
		t.Errorf("ToWafErrorCode(wrapped) = %d, want %d", code, int(waferrors.ErrInternal))
	}
}

// adapter is an error whose As method gives the RunError in as, and that wraps inner.
// It has no Is method.
type adapter struct {
	as    error
	inner error
}

func (a adapter) Error() string { return "adapter" }

func (a adapter) Unwrap() error { return a.inner }

func (a adapter) As(target any) bool {
	p, ok := target.(*waferrors.RunError)
	if !ok {
		return false
	}
	r, ok := a.as.(waferrors.RunError) //nolint:errorlint // a.as is a test value, not a wrapped error
	if !ok {
		return false
	}
	*p = r
	return true
}

// asWithoutTarget is an error whose As method returns true without setting the target.
type asWithoutTarget struct{}

func (asWithoutTarget) Error() string { return "as without target" }

func (asWithoutTarget) As(any) bool { return true }

// wrapper is an error with a short message that wraps inner.
type wrapper struct{ inner error }

func (wrapper) Error() string { return "w" }

func (w wrapper) Unwrap() error { return w.inner }

// onlyNilChildren is an error whose Unwrap() []error method returns only nil errors.
type onlyNilChildren struct{}

func (onlyNilChildren) Error() string { return "only nil children" }

func (onlyNilChildren) Unwrap() []error { return []error{nil, nil} }

func TestToWafReturnCode(t *testing.T) {
	plain := errors.New("plain")

	deepChain := error(waferrors.ErrInvalidArgument)
	for range 10_000 {
		deepChain = wrapper{deepChain}
	}

	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},

		{"internal", waferrors.ErrInternal, -3},
		{"invalid_object", waferrors.ErrInvalidObject, -2},
		{"invalid_argument", waferrors.ErrInvalidArgument, -1},

		{"timeout", waferrors.ErrTimeout, 0},
		{"wrapped_timeout", fmt.Errorf("encode: %w", waferrors.ErrTimeout), 0},

		{"out_of_memory", waferrors.ErrOutOfMemory, -127},
		{"empty_rule_addresses", waferrors.ErrEmptyRuleAddresses, -127},
		{"unknown_run_error", waferrors.RunError(99), -127},
		{"run_error_zero", waferrors.RunError(0), -127},
		{"run_error_native_value_of_internal", waferrors.RunError(-3), -127},
		{"unknown_return_code", fmt.Errorf("%w: %d", waferrors.ErrUnknownReturnCode, -4), -127},

		{"not_a_run_error", plain, -127},
		{"context_closed", waferrors.ErrContextClosed, -127},
		{"panic_error", &waferrors.PanicError{Err: plain}, -127},

		{"wrapped", fmt.Errorf("during run: %w", waferrors.ErrInvalidObject), -2},
		{"nested_wraps", fmt.Errorf("a: %w", fmt.Errorf("b: %w", fmt.Errorf("c: %w", waferrors.ErrInvalidArgument))), -1},
		{"deep_chain", deepChain, -1},

		{"join_of_codes", errors.Join(waferrors.ErrInternal, waferrors.ErrInvalidArgument, waferrors.ErrInvalidObject), -1},
		{"join_error_and_internal", errors.Join(plain, waferrors.ErrInternal), -3},
		{"join_error_and_out_of_memory", errors.Join(plain, waferrors.ErrOutOfMemory), -127},
		{"join_timeout_and_internal", errors.Join(waferrors.ErrTimeout, waferrors.ErrInternal), -3},
		{"join_timeout_and_invalid_object", errors.Join(waferrors.ErrTimeout, waferrors.ErrInvalidObject), -2},
		{"join_invalid_argument_and_timeout", errors.Join(waferrors.ErrInvalidArgument, waferrors.ErrTimeout), -1},
		{"join_timeout_and_out_of_memory", errors.Join(waferrors.ErrTimeout, waferrors.ErrOutOfMemory), -127},
		{"join_timeout_and_unknown_run_error", errors.Join(waferrors.ErrTimeout, waferrors.RunError(99)), -127},
		{"join_timeout_and_error", errors.Join(waferrors.ErrTimeout, plain), -127},
		{"join_of_timeouts", errors.Join(waferrors.ErrTimeout, fmt.Errorf("x: %w", waferrors.ErrTimeout)), 0},
		{"multiple_wrapped_errors", fmt.Errorf("%w: %w", waferrors.ErrResultInvalidType, waferrors.ErrInvalidObject), -2},
		{"join_in_wrap", fmt.Errorf("run: %w", errors.Join(plain, fmt.Errorf("y: %w", waferrors.ErrInvalidArgument))), -1},

		{"as_internal", adapter{as: waferrors.ErrInternal}, -3},
		{"as_timeout", adapter{as: waferrors.ErrTimeout}, 0},
		// An As match does not stop the search: the wrapped errors count too.
		{"as_internal_wrapping_invalid_argument", adapter{as: waferrors.ErrInternal, inner: waferrors.ErrInvalidArgument}, -1},
		{"as_unknown_run_error_wrapping_internal", adapter{as: waferrors.RunError(99), inner: waferrors.ErrInternal}, -3},
		{"as_timeout_wrapping_error", adapter{as: waferrors.ErrTimeout, inner: plain}, -127},
		{"as_timeout_wrapping_internal", adapter{as: waferrors.ErrTimeout, inner: waferrors.ErrInternal}, -3},
		{"as_without_target", asWithoutTarget{}, -127},
		// The target is reset between nodes: the timeout of the first node is not kept for the second.
		{"timeout_then_as_without_target", errors.Join(waferrors.ErrTimeout, asWithoutTarget{}), -127},
		{"only_nil_children", onlyNilChildren{}, -127},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := waferrors.ToWafReturnCode(tc.err); got != tc.want {
				t.Errorf("ToWafReturnCode() = %d, want %d", got, tc.want)
			}
		})
	}
}

// recorder is an error that writes its name in log when its As method is called.
type recorder struct {
	name     string
	log      *[]string
	children []error
}

func (r recorder) Error() string { return r.name }

func (r recorder) As(any) bool {
	*r.log = append(*r.log, r.name)
	return false
}

func (r recorder) Unwrap() []error { return r.children }

// TestToWafReturnCodeOrder checks that ToWafReturnCode visits the errors in the same
// order as errors.As: an error before the errors that it wraps, and the errors of
// Unwrap() []error from left to right.
func TestToWafReturnCodeOrder(t *testing.T) {
	newTree := func(log *[]string) error {
		leaf := func(name string) error { return recorder{name: name, log: log} }
		return recorder{name: "root", log: log, children: []error{
			leaf("a"),
			recorder{name: "b", log: log, children: []error{leaf("b1"), leaf("b2")}},
			leaf("c"),
		}}
	}

	var asLog []string
	var target waferrors.RunError
	if errors.As(newTree(&asLog), &target) {
		t.Fatalf("errors.As() = true, want false")
	}

	var codeLog []string
	if got := waferrors.ToWafReturnCode(newTree(&codeLog)); got != -127 {
		t.Errorf("ToWafReturnCode() = %d, want -127", got)
	}

	want := []string{"root", "a", "b", "b1", "b2", "c"}
	if !slices.Equal(asLog, want) {
		t.Errorf("errors.As visited %v, want %v", asLog, want)
	}
	if !slices.Equal(codeLog, want) {
		t.Errorf("ToWafReturnCode visited %v, want %v", codeLog, want)
	}
}

func TestSupportErrorStrings(t *testing.T) {
	if got := (waferrors.UnsupportedOSArchError{OS: "plan9", Arch: "sparc"}).Error(); got != "unsupported OS/Arch: plan9/sparc" {
		t.Errorf("UnsupportedOSArchError.Error() = %q", got)
	}
	if got := (waferrors.ManuallyDisabledError{}).Error(); got != "the WAF has been manually disabled using the `datadog.no_waf` go build tag" {
		t.Errorf("ManuallyDisabledError.Error() = %q", got)
	}
	if got := (waferrors.UnsupportedGoVersionError{}).Error(); !strings.HasPrefix(got, "unsupported Go version: ") {
		t.Errorf("UnsupportedGoVersionError.Error() = %q, want prefix %q", got, "unsupported Go version: ")
	}
	if got := (waferrors.CgoDisabledError{}).Error(); !strings.Contains(got, "cgo is disabled") {
		t.Errorf("CgoDisabledError.Error() = %q, want substring %q", got, "cgo is disabled")
	}
}
