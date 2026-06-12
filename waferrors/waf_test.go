package waferrors_test

import (
	"errors"
	"fmt"
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
