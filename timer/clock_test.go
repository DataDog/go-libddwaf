package timer

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestClockConcurrentNow(t *testing.T) {
	c := &clock{}
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier
			for range 1000 {
				_ = c.now()
			}
		}()
	}
	close(barrier)
	wg.Wait()
}

func TestPoolInvariants_Clock(t *testing.T) {
	resettable := &clock{}
	resettable.mu.Lock()
	resettable.lastRequest = time.Now().Add(48 * time.Hour)
	resettable.reset()
	if resettable.mu != (sync.Mutex{}) {
		t.Fatalf("expected clock.reset to zero mutex")
	}

	cached := newTimeCache()
	for range 8 {
		_ = cached.now()
	}

	stale := time.Now().Add(24 * time.Hour)
	cached.lastRequest = stale
	putTimeCache(cached)
	if !cached.lastRequest.Before(stale) {
		t.Fatalf("expected putTimeCache to reset lastRequest before pooling")
	}

	reused := newTimeCache()
	t.Cleanup(func() {
		putTimeCache(reused)
	})

	if !reused.lastRequest.Before(stale) {
		t.Fatalf("expected pooled clock to reset lastRequest before stale value %v, got %v", stale, reused.lastRequest)
	}
	if reused.mu != (sync.Mutex{}) {
		t.Fatalf("expected pooled clock mutex to be zero-value after reset")
	}

	start := reused.lastRequest
	now := reused.now()
	if now.Before(start) {
		t.Fatalf("expected now() >= lastRequest after reset, start=%v now=%v", start, now)
	}

	next := reused.now()
	if next.Before(now) {
		t.Fatalf("expected monotonic now() across pooled reuse, previous=%v next=%v", now, next)
	}
}

func BenchmarkMostUsedFunctions(b *testing.B) {
	b.Run("timer.Start()", func(b *testing.B) {
		var err error
		timers := make([]Timer, b.N)
		for i := 0; i < b.N; i++ {
			timers[i], err = NewTreeTimer(WithBudget(time.Hour))
			if err != nil {
				b.Fatal(err)
			}
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.KeepAlive(timers[i].Start())
		}
	})

	b.Run("timer.Spent()", func(b *testing.B) {
		timer, err := NewTreeTimer(WithBudget(time.Hour))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.KeepAlive(timer.Spent())
		}
	})

	b.Run("timer.Remaining()", func(b *testing.B) {
		timer, err := NewTreeTimer(WithBudget(time.Hour))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.KeepAlive(timer.Remaining())
		}
	})

	b.Run("timer.Exhausted()", func(b *testing.B) {
		timer, err := NewTreeTimer(WithBudget(time.Hour))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.KeepAlive(timer.Exhausted())
		}
	})
}

// Benchmark time.Now() vs clock.now()
func BenchmarkNow(b *testing.B) {
	b.Run("time.Now()", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			runtime.KeepAlive(time.Now())
		}
	})
	ct := &clock{lastRequest: time.Now()}
	b.Run("clock.now()", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			runtime.KeepAlive(ct.now())
		}
	})
}
