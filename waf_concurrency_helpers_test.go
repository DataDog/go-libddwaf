package libddwaf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCaptureWorkerErrorReturnsWorkerError(t *testing.T) {
	want := errors.New("worker failed")

	err := captureWorkerError(func() error {
		return want
	})

	require.ErrorIs(t, err, want)
}

func TestCaptureWorkerErrorConvertsPanicToError(t *testing.T) {
	err := captureWorkerError(func() error {
		panic("boom")
	})

	require.EqualError(t, err, "worker panic: boom")
}

func captureWorkerError(fn func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if recoveredErr, ok := recovered.(error); ok {
				err = fmt.Errorf("worker panic: %w", recoveredErr)
				return
			}
			err = fmt.Errorf("worker panic: %v", recovered)
		}
	}()

	return fn()
}
