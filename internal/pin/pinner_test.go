package pin

import (
	"testing"
	"time"
)

func TestConcurrentPinnerRecoverFromPinPanic(t *testing.T) {
	var p ConcurrentPinner

	x := 42
	p.Pin(&x)

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("Pin on a non-pointer must panic to exercise the regression path")
			}
		}()
		p.Pin(x) // non-pointer panics in runtime.Pinner.Pin
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		y := 99
		p.Pin(&y) // must not deadlock
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Pin deadlocked after a panic in a previous Pin call — mutex was not released")
	}

	p.Unpin()
}
