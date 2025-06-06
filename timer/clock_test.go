package timer

import (
	"runtime"
	"testing"
	"time"
)

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
