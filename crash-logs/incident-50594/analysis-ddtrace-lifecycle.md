# dd-trace-go Handle Lifecycle Analysis

**Analyst**: analyst-3
**Scope**: How dd-trace-go (v2.5.0) uses go-libddwaf Handle, and whether it violates the lifecycle contract
**Verdict**: The caller code is **largely correct** in its use of the Handle refcount contract, but there is a **critical race window** during `SwapRootOperation` / `stop()` where in-flight requests can use a WAF Context whose Handle is being (or has been) destroyed.

---

## 1. How waf.Feature stores the Handle

**File**: `internal/appsec/listener/waf/waf.go:31-44`

```go
type Feature struct {
    handle *libddwaf.Handle   // Plain pointer, no atomic, no mutex
    ...
}
```

The `handle` field is a **plain pointer** -- not an `atomic.Pointer`, not behind a mutex. It is set once during `NewWAFFeature()` (line 78) and never mutated afterward. This is safe because the Feature itself is never modified after construction; instead, the entire Feature is replaced during `SwapRootOperation`.

**Assessment**: Safe. The Handle pointer is effectively immutable within a Feature's lifetime.

---

## 2. Feature.Stop() and in-flight Context draining

**File**: `internal/appsec/listener/waf/waf.go:168-171`

```go
func (waf *Feature) Stop() {
    waf.limiter.Stop()
    waf.handle.Close()   // Decrements refcount by 1
}
```

`Feature.Stop()` calls `Handle.Close()`, which decrements the refcount. Thanks to the CAS-based refcount in go-libddwaf, the actual C handle destruction is deferred until all Contexts created from this Handle have also been closed. So the refcount mechanism itself is correct.

**However**, the critical question is: **when is Feature.Stop() called relative to in-flight requests?**

---

## 3. SwapRootOperation: The race window

**File**: `internal/appsec/features.go:36-85`

The `SwapRootOperation` sequence is:

```
1. Create new root operation (newRoot)                    [line 37]
2. Create new Features (each with a new Handle)           [lines 40-53]
3. Lock featuresMu                                        [line 63]
4. Replace a.features with newFeatures                    [line 67]
5. dyngo.SwapRootOperation(newRoot)  -- atomic swap        [line 76]
6. Unlock featuresMu                                      [line 64, deferred]
7. Stop old features (calls Handle.Close on old handles)  [lines 80-82]
```

**The atomic root operation swap (step 5)** ensures that *new* requests will use the new root operation and thus the new Handle/Feature. This is correct.

**The old Features are stopped (step 7)** *after* the swap, which means old Handle.Close() is called. The refcount mechanism ensures the C handle isn't freed until all old Contexts are also closed.

**Critical analysis of the race**: There is a window between when `dyngo.SwapRootOperation(newRoot)` is called and when old `Feature.Stop()` is called. During this window:

- Old in-flight requests still hold a `libddwaf.Context` (via `ContextOperation.context` atomic pointer) that references the old Handle.
- These Contexts are still valid because the old Handle's refcount hasn't been decremented yet (Stop hasn't been called).
- When `Stop()` is called, it decrements the Handle refcount by 1 (the Handle's own reference).
- The Handle will only be destroyed when all Contexts from it are also closed.

**This part is safe** -- the refcount mechanism handles it correctly.

---

## 4. The grpcsec path: How Run gets its Context

**File**: `internal/appsec/listener/grpcsec/grpc.go:54`

```go
func (f *Feature) OnStart(op *grpcsec.HandlerOperation, args grpcsec.HandlerOperationArgs) {
    ...
    op.Run(op, addresses.NewAddressesBuilder()...Build())
}
```

The `op.Run()` call here is on a `grpcsec.HandlerOperation`, which emits a `RunEvent` via dyngo. This event propagates to the parent `ContextOperation`, which handles it in `OnEvent`:

**File**: `internal/appsec/emitter/waf/context.go:181-183`
```go
func (op *ContextOperation) OnEvent(event RunEvent) {
    op.Run(event.Operation, event.RunAddressData)
}
```

**File**: `internal/appsec/emitter/waf/run.go:27`
```go
func (op *ContextOperation) Run(eventReceiver dyngo.Operation, addrs libddwaf.RunAddressData) {
    ctx := op.context.Load()   // Atomic load of *libddwaf.Context
    if ctx == nil {
        return
    }
    ...
    result, err := ctx.Run(addrs)
    ...
}
```

The `ContextOperation.Run` method loads the WAF Context via an **atomic pointer** (`op.context.Load()`). This is the same Context that was set during `Feature.onStart`:

**File**: `internal/appsec/listener/waf/waf.go:93-103`
```go
func (waf *Feature) onStart(op *waf.ContextOperation, _ waf.ContextArgs) {
    ctx, err := waf.handle.NewContext(...)   // Increments Handle refcount
    op.SwapContext(ctx)                      // Stores ctx in atomic pointer
    ...
}
```

**Assessment**: The grpcsec path does NOT directly access the Handle. It uses the `ContextOperation`'s atomically-stored WAF Context. The Context holds a reference to the Handle (which was retained during `NewContext`). This is safe because:
1. `NewContext` calls `handle.retain()` (incrementing refcount)
2. `Context.Close` calls `handle.Close()` (decrementing refcount)
3. The Handle is only destroyed when refcount reaches 0

**Could grpcsec use a Context from a stale Handle?** No, not in a dangerous way. A Context created from an "old" Handle is still valid -- the refcount system ensures the Handle stays alive as long as any Context references it. The Context will use the old rules, which is expected behavior during a rules update.

---

## 5. Missing drain: The real vulnerability

**File**: `internal/appsec/appsec.go:193-218`

```go
func (a *appsec) stop() {
    ...
    dyngo.SwapRootOperation(nil)
    a.cfg.WAFManager.Reset()

    // TODO: block until no more requests are using dyngo operations   <-- LINE 211

    for _, feature := range a.features {
        feature.Stop()
    }
    a.features = nil
}
```

**This is the smoking gun.** The `TODO` comment on line 211 explicitly acknowledges that there is no drain mechanism. The sequence is:

1. `SwapRootOperation(nil)` -- new requests won't register with dyngo
2. `WAFManager.Reset()` -- **resets the WAF manager immediately**
3. No wait/drain for in-flight requests
4. `feature.Stop()` -- calls `Handle.Close()` on all Handles

The `WAFManager.Reset()` call is potentially dangerous because it may release WAF Builder/Manager resources that are still referenced. However, the key protection is that each `Context` holds its own reference to the Handle, and Handle destruction is guarded by the refcount.

**The real risk**: The `Feature.Stop()` / `Handle.Close()` path is safe *as long as Context.Close() is eventually called for every Context*. If a Context is leaked (e.g., a request goroutine panics between `onStart` and `onFinish`), the Handle refcount will never reach 0, causing a resource leak rather than a crash.

---

## 6. Race between RC goroutine and request goroutines

The Remote Config callback `onRCRulesUpdate` (remoteconfig.go:29) is called from the RC goroutine. It calls `SwapRootOperation()` (line 164), which:
1. Creates new Features with new Handles
2. Atomically swaps the dyngo root operation
3. Stops old Features (closes old Handles)

Request goroutines interact through:
1. `ContextOperation.onStart` -- called when a request starts, creates a new WAF Context from the Feature's Handle
2. `ContextOperation.Run` -- atomically loads the WAF Context and runs the WAF
3. `ContextOperation.onFinish` -- swaps the Context to nil and closes it

**Race analysis**:

| Time | RC Goroutine | Request Goroutine |
|------|-------------|-------------------|
| T1 | | `onStart`: `handle.NewContext()` (retains handle, refcount=2) |
| T2 | `SwapRootOperation`: creates new features | |
| T3 | `SwapRootOperation`: `dyngo.SwapRootOperation(newRoot)` | |
| T4 | `oldFeature.Stop()`: `handle.Close()` (refcount=1) | |
| T5 | | `Run`: `ctx.Run(addrs)` -- still valid, handle alive |
| T6 | | `onFinish`: `ctx.Close()` (refcount=0, handle destroyed) |

This sequence is **safe** thanks to the refcount mechanism.

**However**, there is a subtle race in `ContextOperation.Run` (run.go:27):

```go
ctx := op.context.Load()    // T1: Load context
if ctx == nil { return }
// ... address filtering ...
result, err := ctx.Run(addrs)  // T2: Use context
```

Between T1 and T2, `onFinish` could be called concurrently (on the same ContextOperation), which does:

```go
ctx := op.SwapContext(nil)  // Atomically sets context to nil
ctx.Close()                 // Destroys the WAF context (and possibly the Handle)
```

If `onFinish` runs between the `Load()` and `ctx.Run()` in `Run()`, then `Run()` would call `ctx.Run()` on a **closed Context**. However, `Context.Run` checks `context.cContext == 0` under a mutex (context.go:142-145), so it would return `ErrContextClosed` rather than crash.

**BUT** -- `Context.Close()` destroys the `cContext` (sets it to 0) and then calls `handle.Close()`. If the Handle refcount reaches 0 during `Context.Close()`, the C handle is destroyed. Then when `Context.Run()` tries to call `ddwaf_run`, it would be using a `cContext` that was created from a destroyed handle. The `cContext == 0` check in `Context.Run` is done under a mutex, but `Context.Close` also uses the same mutex, so these are serialized. The question is whether `ddwaf_run` can still be called safely on a `cContext` whose parent handle has been destroyed.

**Key finding**: The `Context.mutex` serialization between `Run` and `Close` prevents use-after-free of the `cContext` pointer itself. If `Close` runs first, `Run` sees `cContext == 0` and returns an error. If `Run` runs first, it completes before `Close` can destroy the context. This is safe.

---

## 7. Summary of findings

### Safe patterns:
1. **Handle pointer immutability in Feature** -- the Handle is never mutated, only replaced via Feature replacement
2. **Atomic Context pointer** -- `ContextOperation.context` is an `atomic.Pointer`, safe for concurrent load/swap
3. **Refcount-based Handle lifecycle** -- `NewContext` retains, `Context.Close` releases, destruction only at refcount=0
4. **Mutex-protected Context.Run/Close** -- prevents use-after-free on the C context pointer
5. **SwapRootOperation ordering** -- new root is swapped atomically before old features are stopped

### Potential issues:
1. **No drain mechanism** (appsec.go:211 TODO) -- `stop()` does not wait for in-flight requests to complete before closing features. This relies entirely on the refcount mechanism for safety.
2. **WAFManager.Reset() before drain** -- called before features are stopped, potentially releasing shared resources prematurely. Need to verify what `Reset()` actually releases.
3. **Context leak on panic** -- if a request goroutine panics between `onStart` and `onFinish`, the Context is never closed, the Handle refcount never reaches 0, and both the Context and Handle leak permanently.

### Verdict on SIGSEGV root cause:
The dd-trace-go caller code does **not** appear to violate the Handle lifecycle contract in a way that would directly cause a SIGSEGV. The refcount mechanism and mutex serialization provide sufficient protection. The crash is more likely to originate from:
1. A bug in the refcount CAS loop itself (see analyst-1's analysis)
2. A race in the Handle swap at the go-libddwaf level (see analyst-2's analysis)
3. A bug in the C libddwaf library (use-after-free in the C code despite correct Go-level refcounting)
4. A memory corruption from incorrect CGo pointer passing or premature GC of pinned objects
