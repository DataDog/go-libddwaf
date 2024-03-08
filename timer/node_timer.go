// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"errors"
	"fmt"
	"time"
)

// nodeTimer is the type used for all the timers that can (and will) have children
type nodeTimer struct {
	baseTimer

	// parent is the parent timer. It is used to propagate the stop of the timer to the parent timer and get the remaining time in case the budget has to be inherited.
	parent NodeTimer

	// parentComponent is the component stored in the map of the parent timer. We keep a reference to it to update its spent time
	// once the timer is stopped. It may be nil if the timer is not a child of a tree timer, like when calling NewTimer.
	parentComponent *component

	components
}

var _ NodeTimer = (*nodeTimer)(nil)

// NewTreeTimer creates a new Timer with the given options. You have to specify either the option WithBudget or WithUnlimitedBudget and at least one component using the WithComponents option.
func NewTreeTimer(options ...Option) (NodeTimer, error) {
	config := newConfig(options...)
	if config.Budget == InheritedBudget {
		return nil, errors.New("root timer cannot inherit parent budget, please provide a budget using timer.WithBudget() or timer.WithUnlimitedBudget()")
	}

	if len(config.Components) == 0 {
		return nil, errors.New("NewTreeTimer: tree timer must have at least one component, otherwise use NewTimer()")
	}

	return &nodeTimer{
		baseTimer: baseTimer{
			config:    config,
			timeCache: newTimeCache(),
		},
		components: newComponents(config.Components),
	}, nil
}

func (timer *nodeTimer) NewNode(name string, options ...Option) (NodeTimer, error) {
	config := newConfig(options...)
	if len(config.Components) == 0 {
		return nil, errors.New("NewNode: node timer must have at least one component, otherwise use NewLeaf()")
	}

	component, ok := timer.components.lookup[name]
	if !ok {
		return nil, fmt.Errorf("NewNode: component %s not found", name)
	}

	return &nodeTimer{
		baseTimer: baseTimer{
			config:    config,
			timeCache: timer.timeCache,
		},
		components:      newComponents(config.Components),
		parentComponent: component,
		parent:          timer,
	}, nil
}

func (timer *nodeTimer) NewLeaf(name string, options ...Option) (Timer, error) {
	config := newConfig(options...)
	if len(config.Components) != 0 {
		return nil, errors.New("NewLeaf: leaf timer cannot have components, otherwise use NewNode()")
	}

	component, ok := timer.components.lookup[name]
	if !ok {
		return nil, fmt.Errorf("NewLeaf: component %s not found", name)
	}

	return &baseTimer{
		timeCache:       timer.timeCache,
		config:          config,
		parentComponent: component,
		parent:          timer,
	}, nil
}

func (timer *nodeTimer) MustLeaf(name string, options ...Option) Timer {
	leaf, err := timer.NewLeaf(name, options...)
	if err != nil {
		panic(err)
	}
	return leaf
}

func (timer *nodeTimer) childStopped(duration time.Duration) {
	if timer.parent == nil {
		return
	}

	timer.parentComponent.spent.Add(int64(duration))
	timer.parent.childStopped(duration)
}

func (timer *nodeTimer) Stats() map[string]time.Duration {
	stats := make(map[string]time.Duration, len(timer.components.lookup))
	for name, component := range timer.components.lookup {
		stats[name] = time.Duration(component.spent.Load())
	}

	return stats
}

func (timer *nodeTimer) SumSpent() time.Duration {
	var sum time.Duration
	for _, component := range timer.components.lookup {
		sum += time.Duration(component.spent.Load())
	}
	return sum
}

func (timer *nodeTimer) SumRemaining() time.Duration {
	if timer.config.Budget == UnlimitedBudget {
		return UnlimitedBudget
	}

	remaining := timer.config.Budget - timer.SumSpent()
	if remaining < 0 {
		return 0
	}

	return remaining
}

func (timer *nodeTimer) SumExpired() bool {
	if timer.config.Budget == UnlimitedBudget {
		return false
	}

	return timer.SumSpent() > timer.config.Budget
}
