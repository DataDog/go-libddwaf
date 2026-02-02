package waferrors_test

import (
	"errors"
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
