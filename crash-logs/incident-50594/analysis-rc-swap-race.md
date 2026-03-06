# Analysis: Remote Config Handle Swap Race Condition

**Analyst:** analyst-2 (Go concurrency specialist)
**Date:** 2026-03-06
**Scope:** Race between Remote Config handle swap and request-handling goroutines
**Verdict:** CONFIRMED use-after-free race with two distinct root causes

---

## Executive Summary

The production SIGSEGV crashes are caused by a **use-after-free race condition** triggered when
Remote Config updates swap the WAF handle while in-flight HTTP/gRPC request goroutines are still
using it. The race has **two independent manifestation paths**, both rooted in the same architectural
gap: the `Feature.handle` field is a plain (non-atomic) pointer that is read by request goroutines
without synchronization against the RC goroutine that replaces it.

---

## 1. The Swap Sequence (What RC Does)

When a Remote Config update arrives, the call chain is:

```
remoteconfig.Client.applyUpdate
  -> appsec.onRCRulesUpdate          (remoteconfig.go:164)
    -> appsec.SwapRootOperation      (features.go:36)
      -> waf.NewWAFFeature(cfg, newRoot)   // creates NEW Handle + Feature
      -> dyngo.SwapRootOperation(newRoot)  // atomic pointer swap of root op
      -> oldFeature.Stop()                 // calls old Handle.Close -> ddwaf_destroy
```

Key observations about `SwapRootOperation` (features.go:36-85):

1. **Line 41:** `newFeature(a.cfg, newRoot)` creates a new `waf.Feature` with a new `Handle`.
2. **Line 76:** `dyngo.SwapRootOperation(newRoot)` atomically swaps the root operation pointer.
   After this, **new** requests will pick up the new root and the new Feature/Handle.
3. **Line 80-82:** `oldFeature.Stop()` is called, which calls `oldHandle.Close()` (waf.go:170).

The problem: **in-flight requests that started before line 76 still hold references to the old
Feature and its old Handle.**

---

## 2. Race Path A: `Feature.onStart` reads `waf.handle` after `Stop()`

### The vulnerable code (waf.go:93-111)

```go
func (waf *Feature) onStart(op *waf.ContextOperation, _ waf.ContextArgs) {
    // ...
    ctx, err := waf.handle.NewContext(...)   // <-- reads waf.handle (line 98)
    // ...
}
```

### The race

```
Goroutine A (request handler)           Goroutine B (RC update)
─────────────────────────────           ────────────────────────
dyngo.On(rootOp, feature.onStart)
  // feature.onStart is a closure
  // capturing `waf *Feature`
                                        SwapRootOperation():
                                          dyngo.SwapRootOperation(newRoot) // line 76
  feature.onStart is called:
    waf.handle.NewContext(...)
      handle.retain() -> returns true     oldFeature.Stop():
                                            handle.Close():
                                              addRefCounter(-1) -> 0
                                              bindings.Lib.Destroy(handle.cHandle)
      bindings.Lib.ContextInit(handle.cHandle)  // <-- cHandle is FREED!
        -> SIGSEGV
```

**Why `retain()` doesn't save us here:** There's a TOCTOU gap. The `retain()` call in
`NewContext` (handle.go:54) succeeds because it runs *before* `Close()` decrements the counter.
But between `retain()` succeeding and `ContextInit` being called (handle.go:58), the RC goroutine
can call `Close()` which does `addRefCounter(-1)` bringing the counter to 0 (or it might see 2
because of the retain, then later reach 0 when the context closes). **However**, the critical
issue is:

Even when `retain()` is correct, the underlying C library function `ddwaf_destroy` is called on
the `cHandle` value. The `cHandle` field at handle.go:36 is a plain `bindings.WAFHandle`
(which is a `uintptr`). It is **not** protected by atomic operations or a mutex.

Specifically:
- `handle.cHandle` is read at handle.go:58 (`NewContext`)
- `handle.cHandle` is zeroed at handle.go:99 (`Close`) AFTER `Destroy` returns

But `Destroy` is called at handle.go:98, which frees the C memory. The zero-assignment at
line 99 is *after* the free. So another goroutine that already read `cHandle` (a non-zero
stale value) and is about to call `ContextInit` will pass a freed pointer to `ddwaf_context_init`.

### The `cHandle` field is not atomic

```go
type Handle struct {
    refCounter atomic.Int32        // <-- atomic, good
    cHandle    bindings.WAFHandle  // <-- NOT atomic, just uintptr
}
```

The `refCounter` CAS loop provides correct mutual exclusion for the *counter* itself, but it
does **not** provide a happens-before relationship for the `cHandle` read. Go's memory model
requires that if goroutine A writes to a variable and goroutine B reads it, there must be a
synchronization event between them. The `refCounter` atomic ops do not establish this for
`cHandle` because:

1. `retain()` does `refCounter.CompareAndSwap` (atomic, establishes ordering for refCounter)
2. The goroutine then reads `handle.cHandle` (handle.go:58) -- **plain read, no barrier**
3. `Close()` calls `Destroy(handle.cHandle)` then sets `handle.cHandle = 0` -- **plain write**

Under the Go memory model, the plain read at step 2 and the plain write at step 3 are a data
race. The Go race detector would flag this.

---

## 3. Race Path B: `ContextOperation.Run` uses a Context whose Handle is being destroyed

### The vulnerable code (run.go:26-43)

```go
func (op *ContextOperation) Run(eventReceiver dyngo.Operation, addrs libddwaf.RunAddressData) {
    ctx := op.context.Load()        // atomic load, safe
    if ctx == nil { return }
    // ...
    result, err := ctx.Run(addrs)   // uses ctx.handle.cHandle transitively
}
```

The `ContextOperation.context` field is an `atomic.Pointer[libddwaf.Context]`, so the load is
safe. But the loaded `*Context` holds a reference to the old `Handle` (via `context.handle`).

**Scenario:**

```
Goroutine A (request, started pre-swap)     Goroutine B (RC goroutine)
───────────────────────────────────────     ──────────────────────────
ctx := op.context.Load() // non-nil
                                            SwapRootOperation():
                                              dyngo.SwapRootOperation(newRoot)
                                              oldFeature.Stop():
                                                handle.Close():
                                                  addRefCounter(-1)
                                                  // if refCounter reaches 0:
                                                  Destroy(handle.cHandle)
ctx.Run(addrs):
  // ctx.handle is the OLD handle
  // ctx.cContext was created from the OLD handle
  // ddwaf_run uses the OLD handle's internal state
  // which was just freed by ddwaf_destroy
  -> SIGSEGV
```

**Why the refcount may reach 0 prematurely:** The `Handle` starts with refCounter=1.
`NewContext` calls `retain()` (+1 -> 2). `Feature.Stop` calls `Handle.Close` (-1 -> 1).
The context is still alive, so refCounter=1 and `Destroy` is NOT called yet.

**However**, in the `onFinish` callback (waf.go:134-162):

```go
func (waf *Feature) onFinish(op *waf.ContextOperation, _ waf.ContextRes) {
    ctx := op.SwapContext(nil)   // atomically sets context to nil
    if ctx == nil { return }
    ctx.Close()                  // calls context.handle.Close() -> addRefCounter(-1)
```

If the root operation was already swapped, the `onFinish` listener on the OLD root operation
**may or may not fire** depending on whether the operation was already registered before the swap.
Operations that started before the swap have their parent chain pointing to the old root, so
their finish events DO bubble up to the old root's listeners.

The real danger is the **timing**: `Feature.Stop` -> `Handle.Close` happens on the RC goroutine
immediately after `dyngo.SwapRootOperation`. Any in-flight request that hasn't yet called
`Handle.NewContext` (which does `retain()`) will find the Handle already closed.

---

## 4. The `dyngo.SwapRootOperation` Does NOT Wait for In-Flight Operations

```go
func SwapRootOperation(newOp Operation) {
    rootOperation.Swap(&newOp)
    // NOTE: does NOT call Finish on old root
    // does NOT wait for in-flight operations
}
```

This is the architectural gap. The swap is a simple atomic pointer replacement. There is no
mechanism to:
1. Wait for in-flight operations to complete
2. Drain existing contexts
3. Ensure all `onStart` callbacks have completed before `Stop()` is called

The comment in the code even acknowledges this (dyngo operation.go:83-85):
> calling Finish(old, ...) could result into mem leaks because some finish event listeners,
> possibly releasing memory and resources, wouldn't be called anymore

---

## 5. Crash Address Analysis

The crash traces show `addr=0x0` in most cases. This is consistent with:

1. **NULL dereference after `cHandle = 0`:** If the RC goroutine completes `Destroy` and sets
   `cHandle = 0` before the request goroutine reads it, the request goroutine passes 0 (NULL)
   to `ddwaf_context_init` or `ddwaf_run`, causing a NULL pointer dereference in the C library.

2. **Freed memory access:** If the request goroutine reads `cHandle` *before* it's zeroed but
   *after* `ddwaf_destroy` has freed the underlying C memory, the crash address would be
   non-zero but invalid. The traces showing `addr=0x0` likely indicate the former case, while
   crash trace-04 (BatchAddEdges via `ddwaf_run`) hits freed memory that hasn't been reassigned.

The non-zero crash addresses (mentioned in the task description: 0x2a48-0x1fe950) are consistent
with accessing **partially-reused freed C heap memory**. After `ddwaf_destroy` frees the WAF
instance, the C allocator may reassign parts of that memory. A subsequent `ddwaf_run` or
`ddwaf_context_init` call dereferences internal pointers in what it thinks is a valid WAF
handle/context structure, but those memory locations now contain garbage or data from a new
allocation, leading to crashes at various offsets.

---

## 6. Timeline of a Crash

```
T0: Request goroutine starts, picks up old root operation
    -> waf.Feature.onStart is called (old Feature, old Handle)
    -> Handle.NewContext: retain() succeeds (refCounter: 1 -> 2)
    -> ContextInit(cHandle) succeeds, returns cContext
    -> Context is stored in ContextOperation.context

T1: RC goroutine calls SwapRootOperation
    -> New root operation installed (atomic swap)
    -> oldFeature.Stop() called
       -> Handle.Close(): addRefCounter(-1) -> refCounter goes from 2 to 1
       -> refCounter != 0, so Destroy is NOT called (CORRECT)

T2: Request goroutine processes sub-requests (gRPC streaming)
    -> ContextOperation.Run() calls ctx.Run()
    -> ddwaf_run uses cContext (which references old cHandle internally)
    -> This works because the C handle is still alive

T3: Request goroutine finishes
    -> waf.Feature.onFinish on OLD root
    -> ctx.Close() calls Context.Close()
       -> ContextDestroy(cContext) -- this is fine, cContext is valid
       -> handle.Close(): addRefCounter(-1) -> refCounter goes from 1 to 0
       -> Destroy(cHandle) is called -- this is CORRECT cleanup

--- SAFE CASE ABOVE, CRASH CASE BELOW ---

T0: RC goroutine calls SwapRootOperation
    -> new root installed

T1: Concurrently, request goroutine's onStart fires (already bound to old root)
    -> waf.Feature.onStart reads waf.handle (the old one)
    -> calls handle.retain() -- CAS loop, may see refCounter > 0

T2: RC goroutine calls oldFeature.Stop()
    -> handle.Close(): addRefCounter(-1) -> 0
    -> Destroy(cHandle)  <-- FREES C MEMORY
    -> cHandle = 0

T3: Request goroutine calls ContextInit(cHandle)
    -> cHandle was read BEFORE T2's zeroing (stale value)
    -> passes freed pointer to ddwaf_context_init
    -> SIGSEGV
```

**The race window is between T1 (retain succeeds) and T2 (Destroy runs).** If retain() runs
and increments refCounter to 2 before Close() decrements it, we're safe (the T3 safe case).
If Close() runs first and decrements to 0, retain() will return false and NewContext returns
an error. The crash happens when retain() and Close() interleave such that Destroy runs
while a goroutine is between retain() and the actual C call.

---

## 7. Root Cause Summary

| # | Root Cause | Location | Severity |
|---|-----------|----------|----------|
| 1 | `Feature.handle` is a plain pointer read without synchronization by request goroutines while the RC goroutine calls `Stop()` | waf.go:34, waf.go:98 | CRITICAL |
| 2 | `Handle.cHandle` is not atomic; data race between `NewContext` read (handle.go:58) and `Close` write (handle.go:99) | handle.go:36 | CRITICAL |
| 3 | `dyngo.SwapRootOperation` does not wait for in-flight operations to drain | dyngo/operation.go:80-86 | CRITICAL (architectural) |
| 4 | `Feature.Stop()` is called synchronously on the RC goroutine immediately after root swap, with no grace period | features.go:80-82 | HIGH |

---

## 8. Recommendations

### 8.1 Immediate fix: Make `cHandle` access safe within go-libddwaf

The `cHandle` field should be accessed atomically or under a mutex. Specifically:

```go
type Handle struct {
    refCounter atomic.Int32
    cHandle    atomic.Uintptr  // <-- make atomic
}
```

Then `NewContext` reads `atomic.LoadUintptr(&handle.cHandle)` after `retain()`, and `Close` does
`atomic.StoreUintptr(&handle.cHandle, 0)` before (or instead of after) `Destroy`. However, this
alone is insufficient because the C memory is freed by `Destroy` regardless of what other
goroutines have already read.

### 8.2 Structural fix: Hold a lock across retain + C call

```go
func (handle *Handle) NewContext(...) (*Context, error) {
    handle.mu.RLock()
    defer handle.mu.RUnlock()

    if !handle.retain() {
        return nil, fmt.Errorf("handle was released")
    }

    if handle.cHandle == 0 {
        handle.Close()
        return nil, fmt.Errorf("handle was destroyed")
    }

    cContext := bindings.Lib.ContextInit(handle.cHandle)
    // ...
}
```

With `Close` taking `handle.mu.Lock()` before calling `Destroy`. This ensures no goroutine is
between `retain()` and `ContextInit` when `Destroy` runs.

### 8.3 Architectural fix in dd-trace-go: Drain before destroy

`SwapRootOperation` should wait for in-flight operations to finish (or at least for all
`onStart` callbacks to complete) before calling `oldFeature.Stop()`. This could be done with
a `sync.WaitGroup` or by deferring the `Stop()` call to a finalizer/background goroutine that
waits for the refcount to reach zero naturally.

### 8.4 Defense in depth: Check cHandle after retain in NewContext

Even without a mutex, adding a check after `retain()`:

```go
func (handle *Handle) NewContext(...) (*Context, error) {
    if !handle.retain() {
        return nil, ...
    }
    cHandle := handle.cHandle
    if cHandle == 0 {
        handle.Close()
        return nil, fmt.Errorf("handle was destroyed concurrently")
    }
    cContext := bindings.Lib.ContextInit(cHandle)
    // ...
}
```

This narrows the race window but does NOT eliminate it (TOCTOU between the check and the C call).
It would only help if `Close` sets `cHandle = 0` *before* calling `Destroy`, which is the
opposite of the current order.

---

## 9. Evidence from Crash Traces

| Trace | Function | Goroutine | Analysis |
|-------|----------|-----------|----------|
| trace-01 | ddwaf_context_init | 2716 (BatchAddNodes) | Request creating new context from freed handle |
| trace-02 | ddwaf_run | 3224 (BatchAddNodes) | Request running WAF with context from freed handle |
| trace-03 | ddwaf_context_init | (BatchAddNodes) | Same as trace-01, different host |
| trace-04 | ddwaf_run | 2374 (BatchAddEdges) | Different RPC, same race - streaming subrequest |
| trace-05 | ddwaf_context_destroy | (request finish) | Context destroy on freed handle memory |
| trace-06 | ddwaf_context_destroy | (request finish) | Same as trace-05 |
| trace-07 | ddwaf_run | 7530 (arm64 staging) | Same race on ARM64, different code path via grpcsec |
| trace-08 | ddwaf_context_init | 1578 (BatchAddNodes) | Same as trace-01 |
| trace-09 | ddwaf_destroy | 213 (RC goroutine) | **SMOKING GUN**: RC goroutine destroying handle |
| trace-10 | ddwaf_run | 6186 (grpcsec.OnStart) | Different listener path, same underlying race |

**trace-09 is the RC goroutine**, all others are request-handling goroutines. They crash
simultaneously because `ddwaf_destroy` frees the C memory that all the other goroutines are
actively using.

---

## 10. Conclusion

The crash is a **confirmed use-after-free race condition** between the Remote Config update
goroutine and request-handling goroutines. The refcounting mechanism in `Handle` is conceptually
sound but has two implementation gaps:

1. The `cHandle` field lacks memory-model synchronization (no atomic/mutex protection).
2. There is no mechanism to ensure that `Destroy` cannot run while other goroutines are between
   `retain()` and their actual C library calls (`ContextInit`, `Run`, `ContextDestroy`).

The fix requires either (a) a mutex in `Handle` that serializes `Destroy` against C API calls,
or (b) an architectural change in dd-trace-go to defer `Feature.Stop()` until all in-flight
contexts have drained.
