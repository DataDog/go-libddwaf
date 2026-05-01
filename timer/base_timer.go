// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// baseTimer is the type used for all the timers that won't have children
// It's implementation is more lightweight than nodeTimer and can be used as a standalone timer using NewTimer
type baseTimer struct {

	// config is the configuration of the timer
	config config

	clock *clock

	// startOnce guards the one-time initialization in Start() so that
	// concurrent callers don't race on startValue or budget resolution.
	startOnce sync.Once
	// start is the time when the timer was started
	start atomic.Pointer[time.Time]
	// startValue stores the start time once it has been published via start.
	startValue time.Time

	// parent is the parent timer. It is used to progate the stop of the timer to the parent timer and get the remaining time in case the budget has to be inherited.
	parent NodeTimer

	// componentName is the name of the component of the timer. It is used to store the time spent in the component and to propagate the stop of the timer to the parent timer.
	componentName Key

	// budget stores the resolved inherited budget once Start() has computed it.
	budget atomic.Int64
	// budgetResolved is true once budget has been resolved from the parent.
	budgetResolved atomic.Bool

	// stopOnce guards the one-time teardown in Stop() so that concurrent
	// callers don't double-count childStopped or race on spent.
	stopOnce sync.Once
	// spent is the time spent on the timer, set after calling stop
	spent atomic.Int64
	// stopped is true if the timer has been stopped
	stopped atomic.Bool
}

var _ Timer = (*baseTimer)(nil)

type baseTimerSyncPool struct {
	pool sync.Pool
}

func (p *baseTimerSyncPool) Get() any {
	return p.pool.Get()
}

func (p *baseTimerSyncPool) Put(x any) {
	timer := x.(*baseTimer)
	timer.reset()
	p.pool.Put(timer)
}

var baseTimerPool = baseTimerSyncPool{
	pool: sync.Pool{
		New: func() any {
			return &baseTimer{}
		},
	},
}

func getBaseTimer() *baseTimer {
	timer := baseTimerPool.Get().(*baseTimer)
	timer.reset()
	return timer
}

func putBaseTimer(timer *baseTimer) {
	baseTimerPool.Put(timer)
}

func (timer *baseTimer) ReleaseToPool() {
	putBaseTimer(timer)
}

func (timer *baseTimer) reset() {
	if timer.parent == nil {
		putTimeCache(timer.clock)
	}
	timer.config = config{}
	timer.clock = nil
	timer.startOnce = sync.Once{}
	timer.start.Store(nil)
	timer.startValue = time.Time{}
	timer.parent = nil
	timer.componentName = ""
	timer.budget.Store(0)
	timer.budgetResolved.Store(false)
	timer.stopOnce = sync.Once{}
	timer.spent.Store(0)
	timer.stopped.Store(false)
}

// NewTimer creates a new Timer with the given options. You have to specify either the option WithBudget or WithUnlimitedBudget.
func NewTimer(options ...Option) (Timer, error) {
	config := newConfig(options...)
	if config.budget == DynamicBudget {
		return nil, errors.New("root timer cannot inherit parent budget, please provide a budget using timer.WithBudget() or timer.WithUnlimitedBudget()")
	}

	if len(config.components) > 0 {
		return nil, errors.New("NewTimer: timer that have components must use NewTreeTimer()")
	}

	timer := getBaseTimer()
	timer.config = config
	timer.clock = newTimeCache()
	return timer, nil
}

func (timer *baseTimer) Start() time.Time {
	timer.startOnce.Do(func() {
		if timer.budgetValue() == DynamicBudget && timer.parent != nil {
			timer.budget.Store(int64(timer.config.dynamicBudget(timer.parent)))
			timer.budgetResolved.Store(true)
		}

		timer.startValue = timer.now()
		timer.start.Store(&timer.startValue)
	})

	return *timer.start.Load()
}

func (timer *baseTimer) now() time.Time {
	return timer.clock.now()
}

func (timer *baseTimer) Spent() time.Duration {
	// timer was already stopped
	if timer.stopped.Load() {
		return time.Duration(timer.spent.Load())
	}

	// timer was never started
	start := timer.start.Load()
	if start == nil {
		return 0
	}

	return time.Since(*start)
}

func (timer *baseTimer) Remaining() time.Duration {
	budget := timer.budgetValue()
	if budget == UnlimitedBudget || budget == DynamicBudget {
		return UnlimitedBudget
	}

	remaining := budget - timer.Spent()
	if remaining < 0 {
		return 0
	}

	return remaining
}

func (timer *baseTimer) Exhausted() bool {
	budget := timer.budgetValue()
	if budget == UnlimitedBudget || budget == DynamicBudget {
		return false
	}

	return timer.Spent() > budget
}

func (timer *baseTimer) budgetValue() time.Duration {
	if timer.config.budget != DynamicBudget {
		return timer.config.budget
	}

	if timer.budgetResolved.Load() {
		return time.Duration(timer.budget.Load())
	}

	return DynamicBudget
}

func (timer *baseTimer) Stop() time.Duration {
	timer.stopOnce.Do(func() {
		spent := timer.Spent()
		timer.spent.Store(int64(spent))
		timer.stopped.Store(true)
		if timer.parent != nil {
			timer.parent.childStopped(timer.componentName, spent)
		}
	})

	return time.Duration(timer.spent.Load())
}

func (timer *baseTimer) Timed(timedFunc func(timer Timer)) (spent time.Duration) {
	timer.Start()
	defer func() {
		spent = timer.Stop()
	}()

	timedFunc(timer)
	return
}
