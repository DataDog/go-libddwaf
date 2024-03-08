// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"errors"
	"time"
)

// baseTimer is the type used for all the timers that won't have children
// It's implementation is more lightweight than nodeTimer and can be used as a standalone timer using NewTimer
type baseTimer struct {
	timeCache

	// start is the time when the timer was started
	start time.Time

	// parent is the parent timer. It is used to progate the stop of the timer to the parent timer and get the remaining time in case the budget has to be inherited.
	parent NodeTimer

	// parentComponent is the component stored in the map of the parent timer. We keep a reference to it to update its spent time
	// once the timer is stopped. It may be nil if the timer is not a child of a tree timer, like when calling NewTimer.
	parentComponent *component

	// config is the configuration of the timer
	config Config

	// spent is the time spent on the timer, set after calling stop
	spent time.Duration
}

var _ Timer = (*baseTimer)(nil)

// NewTimer creates a new Timer with the given options. You have to specify either the option WithBudget or WithUnlimitedBudget.
func NewTimer(options ...Option) (Timer, error) {
	config := newConfig(options...)
	if config.Budget == InheritedBudget {
		return nil, errors.New("root timer cannot inherit parent budget, please provide a budget using timer.WithBudget() or timer.WithUnlimitedBudget()")
	}

	if len(config.Components) > 0 {
		return nil, errors.New("NewTimer: timer that have components must use NewTreeTimer()")
	}

	return &baseTimer{
		config:    config,
		timeCache: newTimeCache(),
	}, nil
}

func (timer *baseTimer) Start() time.Time {
	// already started before
	if timer.start != (time.Time{}) {
		return timer.start
	}

	if timer.config.Budget == InheritedBudget && timer.parent != nil {
		timer.config.Budget = timer.parent.Remaining()
	}

	timer.start = timer.now()
	return timer.start
}

func (timer *baseTimer) Spent() time.Duration {
	// timer was never started
	if timer.start == (time.Time{}) {
		return 0
	}

	// timer was already stopped
	if timer.spent != 0 {
		return timer.spent
	}

	return time.Since(timer.start)
}

func (timer *baseTimer) Remaining() time.Duration {
	if timer.config.Budget == UnlimitedBudget {
		return UnlimitedBudget
	}

	remaining := timer.config.Budget - timer.Spent()
	if remaining < 0 {
		return 0
	}

	return remaining
}

func (timer *baseTimer) Expired() bool {
	if timer.config.Budget == UnlimitedBudget {
		return false
	}

	return timer.Spent() > timer.config.Budget
}

func (timer *baseTimer) Stop() time.Duration {
	// If the current timer has already stopped, return the current spent time
	if timer.spent != 0 {
		return timer.spent
	}

	timer.spent = timer.Spent()
	if timer.parent != nil {
		timer.parentComponent.spent.Add(int64(timer.spent))
		timer.parent.childStopped(timer.spent)
	}

	return timer.spent
}

func (timer *baseTimer) Timed(timedFunc func(timer Timer)) (spent time.Duration) {
	timer.Start()
	defer func() {
		timer.spent = timer.Stop()
		spent = timer.spent
	}()

	timedFunc(timer)
	return
}
