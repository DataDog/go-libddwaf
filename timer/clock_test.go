package timer

import (
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

func TestChildTimersShareClockPointer(t *testing.T) {
	root, err := NewTreeTimer(WithBudget(1), WithComponents("a"))
	require.NoError(t, err)

	t.Run("leaf", func(t *testing.T) {
		leaf, err := root.NewLeaf("a")
		require.NoError(t, err)

		rootImpl := root.(*nodeTimer)
		leafImpl := leaf.(*baseTimer)

		require.Equal(t, reflect.Pointer, reflect.TypeOf(rootImpl.baseTimer.clock).Kind())
		require.Equal(t, reflect.Pointer, reflect.TypeOf(leafImpl.clock).Kind())
		require.Equal(t, reflect.ValueOf(rootImpl.baseTimer.clock).Pointer(), reflect.ValueOf(leafImpl.clock).Pointer())
	})

	t.Run("node", func(t *testing.T) {
		node, err := root.NewNode("a", WithComponents("b"))
		require.NoError(t, err)

		rootImpl := root.(*nodeTimer)
		nodeImpl := node.(*nodeTimer)

		require.Equal(t, reflect.Pointer, reflect.TypeOf(rootImpl.baseTimer.clock).Kind())
		require.Equal(t, reflect.Pointer, reflect.TypeOf(nodeImpl.baseTimer.clock).Kind())
		require.Equal(t, reflect.ValueOf(rootImpl.baseTimer.clock).Pointer(), reflect.ValueOf(nodeImpl.baseTimer.clock).Pointer())
	})
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
