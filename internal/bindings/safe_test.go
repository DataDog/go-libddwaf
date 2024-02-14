// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTryCall(t *testing.T) {
	myErr := errors.New("my error")
	myPanicErr := errors.New("my error")

	t.Run("panic", func(t *testing.T) {
		t.Run("error", func(t *testing.T) {
			// panic called with an error
			err := tryCall(func() error {
				panic(myPanicErr)
			})
			require.Error(t, err)
			var panicErr *PanicError
			require.True(t, errors.As(err, &panicErr))
			require.True(t, errors.Is(err, myPanicErr))
		})

		t.Run("string", func(t *testing.T) {
			// panic called with a string
			str := "woops"
			err := tryCall(func() error {
				panic(str)
			})
			require.Error(t, err)
			var panicErr *PanicError
			require.True(t, errors.As(err, &panicErr))
			require.Contains(t, panicErr.Err.Error(), str)
		})

		t.Run("int", func(t *testing.T) {
			// panic called with an int to cover the default fallback in tryCall
			var i int64 = 42
			err := tryCall(func() error {
				panic(i)
			})
			require.Error(t, err)
			var panicErr *PanicError
			require.True(t, errors.As(err, &panicErr))
			require.Contains(t, panicErr.Err.Error(), strconv.FormatInt(i, 10))
		})
	})

	t.Run("error", func(t *testing.T) {
		err := tryCall(func() error {
			return myErr
		})
		require.Equal(t, myErr, err)
	})

	t.Run("no error", func(t *testing.T) {
		err := tryCall(func() error {
			return nil
		})
		require.NoError(t, err)
	})
}
