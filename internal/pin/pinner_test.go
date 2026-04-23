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
				t.Fatal("expected panic")
			}
		}()
		p.Pin(x)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		y := 99
		p.Pin(&y)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Pin deadlocked")
	}

	p.Unpin()
}
