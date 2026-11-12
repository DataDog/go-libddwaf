// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

const (
	// EncodeTimeKey is the key used to track the time spent encoding the address data reported in [Result.TimerStats].
	EncodeTimeKey timer.Key = "encode"
	// DurationTimeKey is the key used to track the time spent in libddwaf ddwaf_run C function reported in [Result.TimerStats].
	DurationTimeKey timer.Key = "duration"
	// DecodeTimeKey is the key used to track the time spent decoding the address data reported in [Result.TimerStats].
	DecodeTimeKey timer.Key = "decode"
)

// subcontextExtraTimerKeys is the number of timer keys ([EncodeTimeKey],
// [DurationTimeKey] and [DecodeTimeKey]) that a subcontext timer may add to the
// timer keys of its parent.
const subcontextExtraTimerKeys = 3

// Context is a WAF execution context. It allows running the WAF incrementally when calling it
// multiple times to run its rules every time new addresses become available. Each request must have
// its own [Context]. New [Context] instances can be created by calling
// [Handle.NewContext].
//
// Subcontexts can be created via [Context.NewSubcontext]. Data passed to a subcontext is stored
// and persists across multiple calls to Run on that subcontext, until the subcontext is closed.
//
// # Concurrency
//
// Context.Run may be called concurrently; same-Context Run calls serialize
// internally via a per-instance mutex. Context.Run may run concurrently with
// Subcontext.Run calls under the same Context.
//
// Context.Close waits for all in-flight Run and NewSubcontext operations to
// complete before destroying the underlying ddwaf_context.
type Context struct {
	// Timer registers the time spent in the WAF and go-libddwaf. It is created alongside the Context using the options
	// passed in to NewContext. Once its time budget is exhausted, each new call to Context.Run will return a timeout error.
	Timer timer.NodeTimer

	handle *Handle // Instance of the WAF

	closedHint    atomic.Bool
	evalsInFlight sync.WaitGroup
	mu            sync.Mutex
	cContext      bindings.WAFContext

	// truncationsMu protects reads and writes to truncations independently of
	// the run mutex, so that Truncations() does not block on long Run() calls.
	truncationsMu sync.RWMutex

	truncations Truncations

	// pinners retains Go data passed to the WAF as part of [RunAddressData.Data].
	// Each Run call gets its own [runtime.Pinner]; all are unpinned on [Context.Close].
	pinners   []*runtime.Pinner
	pinnersMu sync.Mutex
	// pinnersReleased is set by Close, under pinnersMu, once the ddwaf_context
	// has been destroyed and the collected pinners unpinned.
	pinnersReleased bool

	// subcontexts tracks live subcontexts derived from this context. The libddwaf
	// C API does not document ddwaf_context_destroy as cascading to subcontexts
	// created via ddwaf_subcontext_init, so Context.Close destroys each live
	// ddwaf_subcontext itself to avoid leaking them. Guarded by mu.
	subcontexts map[*Subcontext]struct{}
}

// NewSubcontext creates a subcontext derived from this context.
// The provided ctx only scopes the construction call itself and is not retained
// after NewSubcontext returns; per-run deadlines and cancellation must be supplied
// to [Context.Run] via its own ctx argument.
// Data passed to the subcontext's Run() is stored and persists across multiple calls
// to Run on that subcontext, but does not persist in the parent context.
// When the subcontext is closed, its data is released.
//
// A subcontext gets its own timer whose initial budget is snapshotted from the
// caller's remaining budget when the subcontext is created.
//
// Usage:
//
//	subCtx, err := ctx.NewSubcontext(context.Background())
//	if err != nil {
//	    return err
//	}
//	defer subCtx.Close()
//	result, err := subCtx.Run(context.Background(), RunAddressData{Data: data})
func (context *Context) NewSubcontext(ctx context.Context) (*Subcontext, error) {
	if err := validateConstructionContext("Context.NewSubcontext", ctx); err != nil {
		return nil, err
	}

	if !context.handle.retain() {
		if context.closedHint.Load() {
			return nil, waferrors.ErrContextClosed
		}
		return nil, waferrors.ErrHandleReleased
	}
	success := false
	defer func() {
		if !success {
			context.handle.Close()
		}
	}()

	context.mu.Lock()
	defer context.mu.Unlock()

	if context.closedHint.Load() || context.cContext == 0 {
		return nil, waferrors.ErrContextClosed
	}

	cSubcontext, subTimer, err := context.initSubcontextLocked()
	if err != nil {
		return nil, err
	}

	success = true
	return context.addSubcontextLocked(cSubcontext, subTimer), nil
}

// initSubcontextLocked creates the ddwaf_subcontext and the timer of a new
// [Subcontext]. The caller MUST hold context.mu. If it returns an error, no
// ddwaf_subcontext is left alive.
func (context *Context) initSubcontextLocked() (bindings.WAFSubcontext, timer.NodeTimer, error) {
	cSubcontext := bindings.Lib.SubcontextInit(context.cContext)
	if cSubcontext == 0 {
		return 0, nil, errors.New("failed to create subcontext: ddwaf_subcontext_init returned null")
	}

	subTimer, err := context.newSubcontextTimer()
	if err != nil {
		bindings.Lib.SubcontextDestroy(cSubcontext)
		return 0, nil, fmt.Errorf("failed to create subcontext timer: %w", err)
	}
	return cSubcontext, subTimer, nil
}

// newSubcontextTimer creates the timer of a new [Subcontext]. It has the timer
// keys of the Context timer, plus the keys that Run needs, and the remaining
// budget of the Context timer.
func (context *Context) newSubcontextTimer() (timer.NodeTimer, error) {
	parentKeys := context.Timer.ComponentKeys()
	seen := make(map[timer.Key]struct{}, len(parentKeys)+subcontextExtraTimerKeys)
	components := make([]timer.Key, 0, len(parentKeys)+subcontextExtraTimerKeys)
	for _, k := range parentKeys {
		seen[k] = struct{}{}
		components = append(components, k)
	}
	for _, key := range []timer.Key{EncodeTimeKey, DurationTimeKey, DecodeTimeKey} {
		if _, ok := seen[key]; !ok {
			components = append(components, key)
			seen[key] = struct{}{}
		}
	}
	return timer.NewTreeTimer(
		timer.WithComponents(components...),
		timer.WithBudget(context.Timer.SumRemaining()),
	)
}

// addSubcontextLocked creates the [Subcontext] and registers it in
// context.subcontexts. The caller MUST hold context.mu.
func (context *Context) addSubcontextLocked(cSubcontext bindings.WAFSubcontext, subTimer timer.NodeTimer) *Subcontext {
	sub := &Subcontext{
		Timer:  subTimer,
		parent: context,
		cSub:   cSubcontext,
	}
	if context.subcontexts == nil {
		context.subcontexts = make(map[*Subcontext]struct{})
	}
	context.subcontexts[sub] = struct{}{}
	return sub
}

// Run encodes the given [RunAddressData] values and runs them against the WAF rules.
// Callers must check the returned [Result] object even when an error is returned, as the WAF might
// have been able to match some rules and generate events or actions before the error was reached.
//
// Deadline precedence is the minimum of ctx's deadline and the remaining [Context.Timer] budget.
// If ctx fires first, Run returns ctx.Err(). If the timer budget fires first, Run returns
// [waferrors.ErrTimeout].
func (context *Context) Run(ctx context.Context, addressData RunAddressData) (res Result, err error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("Context.Run: %w", waferrors.ErrNilContext)
	}

	if addressData.isEmpty() {
		return Result{}, context.emptyRunError()
	}

	if err := context.checkRunnable(ctx); err != nil {
		return Result{}, err
	}

	runTimer, err := newRunTimer(context.Timer, addressData.TimerKey)
	if err != nil {
		return Result{}, err
	}
	defer func() { res.TimerStats = runTimer.Stats() }()

	runTimer.Start()
	defer runTimer.Stop()

	return context.encodeAndEval(ctx, addressData.Data, runTimer)
}

// emptyRunError returns the error of a Run call without data: [waferrors.ErrContextClosed]
// if the Context is closed, nil otherwise.
func (context *Context) emptyRunError() error {
	if context.closedHint.Load() {
		return waferrors.ErrContextClosed
	}
	return nil
}

// checkRunnable runs the cheap checks that reject a Run call before any work
// is done: the Context is closed, the Context timer is exhausted, or ctx is
// done. The order of the checks is part of the behavior.
func (context *Context) checkRunnable(ctx context.Context) error {
	if context.closedHint.Load() {
		return waferrors.ErrContextClosed
	}

	if context.Timer.SumExhausted() {
		return waferrors.ErrTimeout
	}

	return ctx.Err()
}

// encodeAndEval encodes data, takes the Context lock and evaluates the encoded
// data. It owns the input pinner and the Context lock: both are released by
// the defers below when it returns, in this order: evalsInFlight.Done, mu.Unlock,
// pinner hand-off or unpin.
func (context *Context) encodeAndEval(ctx context.Context, data map[string]any, runTimer timer.NodeTimer) (Result, error) {
	pinner := new(runtime.Pinner)
	// wafOwnsData becomes true once the encoded data is handed to the WAF,
	// which retains references to it until the context is destroyed. Until
	// then (encode error, timeout, closed context) the pinned data was never
	// seen by the WAF and can be released immediately.
	wafOwnsData := false

	// Keep the closure. With "defer context.keepOrUnpin(pinner, wafOwnsData)",
	// wafOwnsData would be read now (false) and the pinner would unpin data
	// that the WAF still reads.
	defer func() { context.keepOrUnpin(pinner, wafOwnsData) }()

	encoded, err := context.encodeRunData(pinner, data, runTimer)
	if err != nil {
		return Result{}, err
	}

	if runTimer.SumExhausted() {
		return Result{}, waferrors.ErrTimeout
	}

	context.mu.Lock()
	defer context.mu.Unlock()

	if err := context.startEvalLocked(ctx); err != nil {
		return Result{}, err
	}
	defer context.evalsInFlight.Done()

	return context.evalLocked(ctx, encoded, runTimer, &wafOwnsData)
}

// encodeRunData encodes data with pinner and merges the truncations of the
// encoding into the Context. It does not need the Context lock.
func (context *Context) encodeRunData(pinner *runtime.Pinner, data map[string]any, runTimer timer.NodeTimer) (*WAFObject, error) {
	wafEncodeTimer := runTimer.MustLeaf(EncodeTimeKey)
	wafEncodeTimer.Start()
	encoded, truncations, err := encodeAddressData(pinner, data, wafEncodeTimer)
	wafEncodeTimer.Stop()
	if err != nil {
		return nil, err
	}

	if !truncations.IsEmpty() {
		context.truncationsMu.Lock()
		context.truncations.Merge(truncations)
		context.truncationsMu.Unlock()
	}
	return encoded, nil
}

// startEvalLocked checks that the evaluation can start and registers it in
// evalsInFlight. The caller MUST hold context.mu, so that [Context.Close] sees
// the evaluation, and MUST call evalsInFlight.Done when the evaluation ends if
// this returns nil.
func (context *Context) startEvalLocked(ctx context.Context) error {
	if context.closedHint.Load() {
		return waferrors.ErrContextClosed
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	context.evalsInFlight.Add(1)
	return nil
}

// evalLocked evaluates the encoded data and decodes the result. The caller MUST
// hold context.mu. The result object is destroyed and unpinned when this
// returns, so before the caller releases context.mu.
func (context *Context) evalLocked(ctx context.Context, data *WAFObject, runTimer timer.NodeTimer, wafOwnsData *bool) (Result, error) {
	var resultPinner runtime.Pinner
	defer resultPinner.Unpin()
	var result WAFObject
	resultPinner.Pin(&result)
	defer bindings.Lib.ObjectDestroy(&result, bindings.Lib.DefaultAllocator())

	cContext := context.cContext
	*wafOwnsData = true
	ret := bindings.Lib.ContextEval(cContext, data, 0, &result, effectiveTimeoutMicros(ctx, runTimer))

	return decodeWafResult(ctx, ret, &result, runTimer)
}

// keepOrUnpin releases the input pinner of a Run call. If the WAF received the
// data (wafOwnsData), the pinner is kept until [Context.Close]. Otherwise the
// data was never seen by the WAF and is unpinned now.
func (context *Context) keepOrUnpin(pinner *runtime.Pinner, wafOwnsData bool) {
	if !wafOwnsData {
		pinner.Unpin()
		return
	}
	context.pinnersMu.Lock()
	defer context.pinnersMu.Unlock()
	// The ddwaf_context keeps reading this data (including from other
	// in-flight evaluations) until it is destroyed, so the pinner must be
	// handed to Close even if Close has already started. It is only safe to
	// release it here once Close has destroyed the context.
	if context.pinnersReleased {
		pinner.Unpin()
		return
	}
	context.pinners = append(context.pinners, pinner)
}

// Close disposes of the context: it destroys the underlying ddwaf_context,
// releases associated data, and decreases the reference count of the [Handle]
// created for this [Context].
//
// Close cascades to subcontexts: any still-open [Subcontext] derived from this
// Context via [Context.NewSubcontext] is fully torn down as part of Close — its
// underlying ddwaf_subcontext is destroyed, its pinned input data released, and
// its per-scope timer durations and truncations folded into this Context.
// (The underlying ddwaf_context_destroy does not itself cascade, so go-libddwaf
// destroys each live subcontext explicitly before destroying the context.)
// Calling [Subcontext.Close] afterwards remains safe and becomes a no-op.
//
// The parent [Context] reflects a subcontext's timer stats and truncations only
// after that subcontext is closed — either explicitly via [Subcontext.Close] or
// implicitly via this cascade. Callers reading the aggregate [Context.Timer] or
// [Context.Truncations] must close their subcontexts first (or read after
// [Context.Close]).
// For this rollup, only subcontext runs that have fully returned before Close
// are guaranteed to be reflected; a subcontext Run executing concurrently with
// Context.Close may be omitted from the aggregate timer durations or
// truncations.
//
// Close blocks until all in-flight Run and NewSubcontext operations complete,
// and is safe to call more than once.
func (context *Context) Close() {
	if !context.closedHint.CompareAndSwap(false, true) {
		return
	}

	context.mu.Lock()
	context.mu.Unlock() //nolint:staticcheck // SA2001: intentional barrier — synchronize with Run/NewSubcontext before waiting for in-flight evals

	context.evalsInFlight.Wait()

	// ddwaf_context_destroy does NOT cascade to derived subcontexts, so destroy
	// each live subcontext's ddwaf_subcontext before the context. Holding mu
	// across both the subcontext loop and ContextDestroy serializes with any
	// concurrent Subcontext.Close (which destroys its own cSub under the same
	// lock and gates on cSub != 0), guaranteeing each subcontext is destroyed
	// exactly once and always before the context.
	context.mu.Lock()
	for sub := range context.subcontexts {
		sub.close(true)
	}

	if context.cContext != 0 {
		bindings.Lib.ContextDestroy(context.cContext)
		context.cContext = 0
	}
	context.mu.Unlock()

	context.pinnersMu.Lock()
	defer context.pinnersMu.Unlock()
	for _, p := range context.pinners {
		p.Unpin()
	}
	context.pinners = nil
	context.pinnersReleased = true

	context.handle.Close()
}

// Supports reports whether the WAF ruleset behind this context monitors addr,
// via the handle's cached known-address set.
func (context *Context) Supports(addr string) bool {
	return context.handle.Supports(addr)
}

// Truncations returns the truncations that occurred while encoding address
// data for WAF execution. The returned value is a snapshot; subsequent Run
// calls may accumulate more truncations.
func (context *Context) Truncations() Truncations {
	context.truncationsMu.RLock()
	defer context.truncationsMu.RUnlock()
	return Truncations{
		StringTooLong:     append([]int(nil), context.truncations.StringTooLong...),
		ContainerTooLarge: append([]int(nil), context.truncations.ContainerTooLarge...),
		ObjectTooDeep:     append([]int(nil), context.truncations.ObjectTooDeep...),
	}
}
