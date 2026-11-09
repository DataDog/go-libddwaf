// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"testing"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// TestGoRunErrorReturnCodeRoundTrip checks that waferrors.ToWafReturnCode gives
// back the ddwaf_run return code that goRunError converted to a Go error. The
// bindings constants mirror the libddwaf C API and are the reference: waferrors
// cannot import them (import cycle), so it has its own copy of the values.
func TestGoRunErrorReturnCodeRoundTrip(t *testing.T) {
	for _, rc := range []bindings.WAFReturnCode{
		bindings.WAFErrInternal,
		bindings.WAFErrInvalidObject,
		bindings.WAFErrInvalidArgument,
		bindings.WAFOK,
	} {
		if got := waferrors.ToWafReturnCode(goRunError(rc)); got != int(rc) {
			t.Errorf("ToWafReturnCode(goRunError(%d)) = %d, want %d", int(rc), got, int(rc))
		}
	}

	// A match is not an error.
	if got := waferrors.ToWafReturnCode(goRunError(bindings.WAFMatch)); got != 0 {
		t.Errorf("ToWafReturnCode(goRunError(WAFMatch)) = %d, want 0", got)
	}

	// A code that go-libddwaf does not know is reported as an error from the bindings.
	if rc := bindings.WAFErrInternal - 1; waferrors.ToWafReturnCode(goRunError(rc)) != -127 {
		t.Errorf("ToWafReturnCode(goRunError(%d)) = %d, want -127", int(rc), waferrors.ToWafReturnCode(goRunError(rc)))
	}
}
