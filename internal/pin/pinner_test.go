package pin

import (
	"runtime"
	"sync"
	"testing"
	"time"
	_ "unsafe"
)

//go:linkname runtimeCgoCheckPointer runtime.cgoCheckPointer
func runtimeCgoCheckPointer(ptr any, arg any)

func assertCgoCheckPanics(t *testing.T, p any) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("runtime.CgoCheckPointer did not panic")
		}
	}()
	runtimeCgoCheckPointer(p, true)
}

func assertCgoCheckAllows(t *testing.T, p any) {
	t.Helper()
	runtimeCgoCheckPointer(p, true)
}

func TestConcurrentPinnerShardIndexBounds(t *testing.T) {
	if shardCount < 4 || shardCount > 64 {
		t.Fatalf("shardCount=%d, want between 4 and 64", shardCount)
	}
	if shardCount&(shardCount-1) != 0 {
		t.Fatalf("shardCount=%d, want power of 2", shardCount)
	}

	for range 256 {
		idx := cheapShardIndex()
		if idx < 0 || idx >= shardCount {
			t.Fatalf("cheapShardIndex=%d, want [0,%d)", idx, shardCount)
		}
	}
}

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

func TestConcurrentPinnerCrossShardPinLifetime(t *testing.T) {
	workers := shardCount * 2

	type pinnedObj struct {
		value [32]byte
	}

	p := &ConcurrentPinner{}
	objs := make([]*pinnedObj, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		obj := &pinnedObj{}
		objs[i] = obj
		go func(o *pinnedObj) {
			defer wg.Done()
			<-start
			p.Pin(o)
		}(obj)
	}

	close(start)
	wg.Wait()

	runtime.GC()
	runtime.GC()

	for _, obj := range objs {
		ptr := obj
		assertCgoCheckAllows(t, &ptr)
	}

	p.Close()

	for _, obj := range objs {
		ptr := obj
		assertCgoCheckPanics(t, &ptr)
	}
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
