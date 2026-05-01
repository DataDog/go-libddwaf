// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// nodeTimer is the type used for all the timers that can (and will) have children
type nodeTimer struct {
	baseTimer
	components
}

var _ NodeTimer = (*nodeTimer)(nil)

type ownedNodeTimer struct {
	state atomic.Pointer[ownedNodeTimerState]
}

type ownedNodeTimerState struct {
	live     *nodeTimer
	snapshot *nodeTimerSnapshot
}

type nodeTimerSnapshot struct {
	start         time.Time
	spent         time.Duration
	remaining     time.Duration
	exhausted     bool
	sumSpent      time.Duration
	sumRemaining  time.Duration
	sumExhausted  bool
	stats         map[Key]time.Duration
	componentKeys []Key
}

var _ NodeTimer = (*ownedNodeTimer)(nil)

var nodeTimerPool = sync.Pool{
	New: func() any {
		return &nodeTimer{}
	},
}

func (timer *nodeTimer) reset() {
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

	lookupSize := len(timer.lookup)
	if timer.lookup != nil {
		clear(timer.lookup)
		if lookupSize > 32 {
			timer.lookup = make(map[Key]*atomic.Int64)
		}
	}
	if cap(timer.storage) > 32 {
		timer.storage = make([]atomic.Int64, 0, 32)
	} else {
		clear(timer.storage)
		timer.storage = timer.storage[:0]
	}
}

// PutNodeTimer returns a pooled node timer to the timer package pool.
func PutNodeTimer(t NodeTimer) {
	if t == nil {
		return
	}

	if owned, ok := t.(*ownedNodeTimer); ok {
		owned.release()
		return
	}

	node, ok := t.(*nodeTimer)
	if !ok {
		return
	}

	node.reset()
	nodeTimerPool.Put(node)
}

// WrapOwnedNodeTimer protects externally reachable node timers so aliases remain
// safe after the underlying pooled timer is returned.
func WrapOwnedNodeTimer(t NodeTimer) NodeTimer {
	if t == nil {
		return nil
	}
	if owned, ok := t.(*ownedNodeTimer); ok {
		return owned
	}
	node, ok := t.(*nodeTimer)
	if !ok {
		return t
	}
	wrapper := &ownedNodeTimer{}
	wrapper.state.Store(&ownedNodeTimerState{live: node})
	return wrapper
}

func (timer *ownedNodeTimer) release() {
	for {
		state := timer.loadState()
		if state == nil || state.live == nil {
			return
		}

		snapshot := snapshotNodeTimer(state.live)
		if timer.state.CompareAndSwap(state, &ownedNodeTimerState{snapshot: snapshot}) {
			PutNodeTimer(state.live)
			return
		}
	}
}

func snapshotNodeTimer(timer *nodeTimer) *nodeTimerSnapshot {
	componentKeys := timer.ComponentKeys()
	stats := make(map[Key]time.Duration, len(componentKeys))
	timer.StatsInto(stats)
	return &nodeTimerSnapshot{
		start:         timer.startValue,
		spent:         timer.Spent(),
		remaining:     timer.Remaining(),
		exhausted:     timer.Exhausted(),
		sumSpent:      timer.SumSpent(),
		sumRemaining:  timer.SumRemaining(),
		sumExhausted:  timer.SumExhausted(),
		stats:         stats,
		componentKeys: componentKeys,
	}
}

func (timer *ownedNodeTimer) loadState() *ownedNodeTimerState {
	return timer.state.Load()
}

func (timer *ownedNodeTimer) liveNode() *nodeTimer {
	state := timer.loadState()
	if state == nil {
		return nil
	}
	return state.live
}

func (timer *ownedNodeTimer) snapshot() *nodeTimerSnapshot {
	state := timer.loadState()
	if state == nil {
		return nil
	}
	return state.snapshot
}

func (timer *ownedNodeTimer) Start() time.Time {
	if live := timer.liveNode(); live != nil {
		return live.Start()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.start
	}
	return time.Time{}
}

func (timer *ownedNodeTimer) Stop() time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.Stop()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.spent
	}
	return 0
}

func (timer *ownedNodeTimer) Spent() time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.Spent()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.spent
	}
	return 0
}

func (timer *ownedNodeTimer) Remaining() time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.Remaining()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.remaining
	}
	return 0
}

func (timer *ownedNodeTimer) Exhausted() bool {
	if live := timer.liveNode(); live != nil {
		return live.Exhausted()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.exhausted
	}
	return false
}

func (timer *ownedNodeTimer) Timed(timedFunc func(timer Timer)) time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.Timed(timedFunc)
	}
	start := timer.Start()
	timedFunc(timer)
	_ = start
	return timer.Stop()
}

func (timer *ownedNodeTimer) NewNode(name Key, options ...Option) (NodeTimer, error) {
	live := timer.liveNode()
	if live == nil {
		return nil, errors.New("NewNode: timer is closed")
	}
	config := newConfig(options...)
	if len(config.components) == 0 {
		return nil, errors.New("NewNode: node timer must have at least one component, otherwise use NewLeaf()")
	}
	if _, ok := live.lookup[name]; !ok {
		return nil, fmt.Errorf("NewNode: component %s not found", name)
	}
	return newPooledNodeTimer(config, live.clock, timer, name), nil
}

func (timer *ownedNodeTimer) NewLeaf(name Key, options ...Option) (Timer, error) {
	live := timer.liveNode()
	if live == nil {
		return nil, errors.New("NewLeaf: timer is closed")
	}
	config := newConfig(options...)
	if len(config.components) != 0 {
		return nil, errors.New("NewLeaf: leaf timer cannot have components, otherwise use NewNode()")
	}
	if _, ok := live.lookup[name]; !ok {
		return nil, fmt.Errorf("NewLeaf: component %s not found", name)
	}
	leaf := getBaseTimer()
	leaf.clock = live.clock
	leaf.config = config
	leaf.componentName = name
	leaf.parent = timer
	return leaf, nil
}

func (timer *ownedNodeTimer) MustLeaf(name Key, options ...Option) Timer {
	if len(options) == 0 {
		live := timer.liveNode()
		if live == nil {
			panic("MustLeaf: timer is closed")
		}
		if _, ok := live.lookup[name]; !ok {
			panic(fmt.Sprintf("MustLeaf: component %s not found", name))
		}
		leaf := getBaseTimer()
		leaf.clock = live.clock
		leaf.config = defaultLeafConfig
		leaf.componentName = name
		leaf.parent = timer
		return leaf
	}
	leaf, err := timer.NewLeaf(name, options...)
	if err != nil {
		panic(err)
	}
	return leaf
}

func (timer *ownedNodeTimer) AddTime(name Key, duration time.Duration) {
	if live := timer.liveNode(); live != nil {
		live.AddTime(name, duration)
	}
}

func (timer *ownedNodeTimer) Stats() map[Key]time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.Stats()
	}
	snapshot := timer.snapshot()
	if snapshot == nil {
		return nil
	}
	stats := make(map[Key]time.Duration, len(snapshot.stats))
	for name, duration := range snapshot.stats {
		stats[name] = duration
	}
	return stats
}

func (timer *ownedNodeTimer) StatsInto(dst map[Key]time.Duration) {
	if live := timer.liveNode(); live != nil {
		live.StatsInto(dst)
		return
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		for name, duration := range snapshot.stats {
			dst[name] = duration
		}
	}
}

func (timer *ownedNodeTimer) ComponentKeys() []Key {
	if live := timer.liveNode(); live != nil {
		return live.ComponentKeys()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return append([]Key(nil), snapshot.componentKeys...)
	}
	return nil
}

func (timer *ownedNodeTimer) SumSpent() time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.SumSpent()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.sumSpent
	}
	return 0
}

func (timer *ownedNodeTimer) SumRemaining() time.Duration {
	if live := timer.liveNode(); live != nil {
		return live.SumRemaining()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.sumRemaining
	}
	return 0
}

func (timer *ownedNodeTimer) SumExhausted() bool {
	if live := timer.liveNode(); live != nil {
		return live.SumExhausted()
	}
	if snapshot := timer.snapshot(); snapshot != nil {
		return snapshot.sumExhausted
	}
	return false
}

func (timer *ownedNodeTimer) childStarted() {}

func (timer *ownedNodeTimer) childStopped(componentName Key, duration time.Duration) {
	if live := timer.liveNode(); live != nil {
		live.childStopped(componentName, duration)
	}
}

func (timer *ownedNodeTimer) now() time.Time {
	if live := timer.liveNode(); live != nil {
		return live.now()
	}
	return time.Time{}
}

func newPooledNodeTimer(config config, clock *clock, parent NodeTimer, componentName Key) *nodeTimer {
	timer := nodeTimerPool.Get().(*nodeTimer)
	timer.config = config
	timer.clock = clock
	timer.parent = parent
	timer.componentName = componentName
	timer.components = newComponents(config.components)
	return timer
}

// NewTreeTimer creates a new Timer with the given options. You have to specify either the option WithBudget or WithUnlimitedBudget and at least one component using the WithComponents option.
func NewTreeTimer(options ...Option) (NodeTimer, error) {
	config := newConfig(options...)
	if config.budget == DynamicBudget {
		return nil, errors.New("root timer cannot inherit parent budget, please provide a budget using timer.WithBudget() or timer.WithUnlimitedBudget()")
	}

	return newPooledNodeTimer(config, newTimeCache(), nil, ""), nil
}

func (timer *nodeTimer) NewNode(name Key, options ...Option) (NodeTimer, error) {
	config := newConfig(options...)
	if len(config.components) == 0 {
		return nil, errors.New("NewNode: node timer must have at least one component, otherwise use NewLeaf()")
	}

	_, ok := timer.lookup[name]
	if !ok {
		return nil, fmt.Errorf("NewNode: component %s not found", name)
	}

	return newPooledNodeTimer(config, timer.clock, timer, name), nil
}

func (timer *nodeTimer) NewLeaf(name Key, options ...Option) (Timer, error) {
	config := newConfig(options...)
	if len(config.components) != 0 {
		return nil, errors.New("NewLeaf: leaf timer cannot have components, otherwise use NewNode()")
	}

	_, ok := timer.lookup[name]
	if !ok {
		return nil, fmt.Errorf("NewLeaf: component %s not found", name)
	}

	leaf := getBaseTimer()
	leaf.clock = timer.clock
	leaf.config = config
	leaf.componentName = name
	leaf.parent = timer
	return leaf, nil
}

var defaultLeafConfig = newConfig()

func (timer *nodeTimer) MustLeaf(name Key, options ...Option) Timer {
	if len(options) == 0 {
		if _, ok := timer.lookup[name]; !ok {
			panic(fmt.Sprintf("MustLeaf: component %s not found", name))
		}
		leaf := getBaseTimer()
		leaf.clock = timer.clock
		leaf.config = defaultLeafConfig
		leaf.componentName = name
		leaf.parent = timer
		return leaf
	}
	leaf, err := timer.NewLeaf(name, options...)
	if err != nil {
		panic(err)
	}
	return leaf
}

func (timer *nodeTimer) childStarted() {}

func (timer *nodeTimer) childStopped(componentName Key, duration time.Duration) {
	timer.components.lookup[componentName].Add(int64(duration))
}

func (timer *nodeTimer) AddTime(name Key, duration time.Duration) {
	value, ok := timer.lookup[name]
	if !ok {
		return
	}

	value.Add(int64(duration))
}

func (timer *nodeTimer) Stats() map[Key]time.Duration {
	stats := make(map[Key]time.Duration, len(timer.lookup))
	timer.StatsInto(stats)
	return stats
}

func (timer *nodeTimer) StatsInto(dst map[Key]time.Duration) {
	for name, component := range timer.lookup {
		dst[name] = time.Duration(component.Load())
	}
}

func (timer *nodeTimer) ComponentKeys() []Key {
	keys := make([]Key, 0, len(timer.lookup))
	for k := range timer.lookup {
		keys = append(keys, k)
	}
	return keys
}

func (timer *nodeTimer) SumSpent() time.Duration {
	var sum time.Duration
	for _, component := range timer.lookup {
		sum += time.Duration(component.Load())
	}
	return sum
}

func (timer *nodeTimer) SumRemaining() time.Duration {
	budget := timer.sumBudget()
	if budget == UnlimitedBudget {
		return UnlimitedBudget
	}

	remaining := budget - timer.SumSpent()
	if remaining < 0 {
		return 0
	}

	return remaining
}

func (timer *nodeTimer) SumExhausted() bool {
	budget := timer.sumBudget()
	if budget == UnlimitedBudget {
		return false
	}

	return timer.SumSpent() > budget
}

// sumBudget returns the budget used by SumRemaining/SumExhausted.
// When Start() has resolved an inherited budget, that resolved value is used.
// Otherwise the budget is computed on the fly from the parent so callers can
// query a dynamically-budgeted node timer before it has been started.
func (timer *nodeTimer) sumBudget() time.Duration {
	budget := timer.budgetValue()
	if budget == DynamicBudget && timer.parent != nil {
		budget = timer.config.dynamicBudget(timer.parent)
	}
	if budget == DynamicBudget {
		return UnlimitedBudget
	}
	return budget
}
