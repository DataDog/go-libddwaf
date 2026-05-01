package timer

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testNodeTimer struct{}

func (testNodeTimer) Start() time.Time                           { return time.Time{} }
func (testNodeTimer) Stop() time.Duration                        { return 0 }
func (testNodeTimer) Spent() time.Duration                       { return 0 }
func (testNodeTimer) Remaining() time.Duration                   { return 0 }
func (testNodeTimer) Exhausted() bool                            { return false }
func (testNodeTimer) Timed(func(Timer)) time.Duration            { return 0 }
func (testNodeTimer) SumSpent() time.Duration                    { return 0 }
func (testNodeTimer) SumRemaining() time.Duration                { return 0 }
func (testNodeTimer) SumExhausted() bool                         { return false }
func (testNodeTimer) NewNode(Key, ...Option) (NodeTimer, error)  { return nil, nil }
func (testNodeTimer) NewLeaf(Key, ...Option) (Timer, error)      { return nil, nil }
func (testNodeTimer) MustLeaf(Key, ...Option) Timer              { return nil }
func (testNodeTimer) AddTime(Key, time.Duration)                 {}
func (testNodeTimer) Stats() map[Key]time.Duration               { return nil }
func (testNodeTimer) StatsInto(map[Key]time.Duration)            {}
func (testNodeTimer) ComponentKeys() []Key                       { return nil }
func (testNodeTimer) childStarted()                              {}
func (testNodeTimer) childStopped(Key, time.Duration)            {}
func (testNodeTimer) now() time.Time                             { return time.Time{} }

func TestPoolInvariants_BaseTimer(t *testing.T) {
	bt := getBaseTimer()

	parent := testNodeTimer{}
	bt.config = newConfig(WithBudget(2 * time.Second), WithComponents("stale"))
	bt.clock = newTimeCache()
	bt.parent = parent
	bt.componentName = Key("leaf")
	bt.budget.Store(int64(time.Second))
	bt.budgetResolved.Store(true)
	bt.Start()
	bt.Stop()
	bt.spent.Store(int64(123 * time.Millisecond))
	bt.stopped.Store(true)
	bt.startOnce = sync.Once{}
	bt.stopOnce = sync.Once{}
	bt.startValue = time.Now()
	bt.start.Store(&bt.startValue)

	putBaseTimer(bt)

	reused := getBaseTimer()
	require.Equal(t, config{}, reused.config)
	require.Nil(t, reused.clock)
	require.Nil(t, reused.start.Load())
	require.Equal(t, time.Time{}, reused.startValue)
	require.Nil(t, reused.parent)
	require.Equal(t, Key(""), reused.componentName)
	require.Zero(t, reused.budget.Load())
	require.False(t, reused.budgetResolved.Load())
	require.Zero(t, reused.spent.Load())
	require.False(t, reused.stopped.Load())

	require.Nil(t, reused.start.Load())

	putBaseTimer(reused)
}

func TestPoolInvariants_NodeTimer(t *testing.T) {
	pooled := nodeTimerPool.Get().(*nodeTimer)
	pooled.config = newConfig(WithBudget(time.Second), WithComponents("encode", "decode"))
	pooled.parent = testNodeTimer{}
	pooled.componentName = "encode"
	pooled.startValue = time.Now()
	pooled.start.Store(&pooled.startValue)
	pooled.budget.Store(int64(time.Second))
	pooled.budgetResolved.Store(true)
	pooled.spent.Store(int64(time.Millisecond))
	pooled.stopped.Store(true)
	pooled.clock = newTimeCache()
	pooled.components = newComponents([]Key{"encode", "decode"})
	pooled.lookup["encode"].Store(int64(time.Millisecond))
	pooled.lookup["decode"].Store(int64(2 * time.Millisecond))

	PutNodeTimer(pooled)

	reused := nodeTimerPool.Get().(*nodeTimer)
	t.Cleanup(func() { PutNodeTimer(reused) })

	require.Equal(t, config{}, reused.config)
	require.Nil(t, reused.parent)
	require.Equal(t, Key(""), reused.componentName)
	require.Nil(t, reused.start.Load())
	require.Equal(t, time.Time{}, reused.startValue)
	require.Zero(t, reused.budget.Load())
	require.False(t, reused.budgetResolved.Load())
	require.Zero(t, reused.spent.Load())
	require.False(t, reused.stopped.Load())
	require.Nil(t, reused.clock)
	require.Empty(t, reused.storage)
	require.Empty(t, reused.lookup)

	require.Nil(t, reused.start.Load())
}
