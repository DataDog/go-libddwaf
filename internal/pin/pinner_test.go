package pin

import (
	"runtime"
	"sync"
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

func TestConcurrentPinnerPinAfterClose(t *testing.T) {
	p := &ConcurrentPinner{}

	buf := make([]byte, 32)
	p.Pin(&buf[0])
	p.Close()

	later := make([]byte, 32)
	p.Pin(&later[0])

	p = nil
	runtime.GC()
	runtime.GC()
}

func TestConcurrentPinnerDoubleClose(t *testing.T) {
	p := &ConcurrentPinner{}

	buf := make([]byte, 16)
	p.Pin(&buf[0])

	p.Close()
	p.Close()
}

func TestConcurrentPinnerRace(t *testing.T) {
	const (
		iterations = 500
		workers    = 8
	)

	for range iterations {
		p := &ConcurrentPinner{}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(workers + 1)

		for range workers {
			buf := make([]byte, 32)
			go func(b []byte) {
				defer wg.Done()
				<-start
				p.Pin(&b[0])
			}(buf)
		}

		go func() {
			defer wg.Done()
			<-start
			p.Close()
		}()

		close(start)
		wg.Wait()

		runtime.Gosched()
	}

	runtime.GC()
	runtime.GC()
}
