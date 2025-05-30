// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"fmt"
	"reflect"
	"runtime"

	"github.com/DataDog/go-libddwaf/v4/waferrors"
	"github.com/pkg/errors"
)

func newPanicError(in any, err error) *waferrors.PanicError {
	return &waferrors.PanicError{
		In:  runtime.FuncForPC(reflect.ValueOf(in).Pointer()).Name(),
		Err: err,
	}
}

// tryCall calls function `f` and recovers from any panic occurring while it
// executes, returning it in a `PanicError` object type.
func tryCall[T any](f func() T) (res T, err error) {
	defer func() {
		r := recover()
		if r == nil {
			// Note that panic(nil) matches this case and cannot be really tested for.
			return
		}

		switch actual := r.(type) {
		case error:
			err = errors.WithStack(actual)
		case string:
			err = errors.New(actual)
		default:
			err = fmt.Errorf("%v", r)
		}

		err = newPanicError(f, err)
	}()
	res = f()
	return
}
