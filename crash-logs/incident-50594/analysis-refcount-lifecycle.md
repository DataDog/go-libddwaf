# Refcount Lifecycle Analysis — Handle / Context in go-libddwaf

**Analyst:** analyst-1
**Files analyzed:** `handle.go`, `context.go`, `builder.go`
**Focus:** Refcount math correctness, CAS loop safety, race conditions, use-after-free vectors

---

## 1. Refcount Lifecycle Trace

### 1.1 Creation: `wrapHandle` (handle.go:43-47)

```go
func wrapHandle(cHandle bindings.WAFHandle) *Handle {
    handle := &Handle{cHandle: cHandle}
    handle.refCounter.Store(1)
    return handle
}
```

- Called from `builder.go:177`.
- Initial refcount = **1**, representing the caller's (owner's) reference.
- **Correct.** The owner must eventually call `Handle.Close()` to release this reference.

### 1.2 Retain: `NewContext` -> `retain()` (handle.go:52-56, 106-108)

```go
func (handle *Handle) retain() bool {
    return handle.addRefCounter(1) > 0
}
```

- `NewContext` (handle.go:54) calls `retain()` which increments refcount by 1.
- If `retain()` returns false (refcount was already <= 0), `NewContext` returns an error. **Correct.**
- On success, refcount goes from N to N+1. The new `Context` holds an implicit reference.
- If `ContextInit` fails (handle.go:59-61), `handle.Close()` is called to release the just-acquired reference. **Correct.**

### 1.3 Release: `Handle.Close()` (handle.go:91-100)

```go
func (handle *Handle) Close() {
    if handle.addRefCounter(-1) != 0 {
        return
    }
    bindings.Lib.Destroy(handle.cHandle)
    handle.cHandle = 0
}
```

- Decrements refcount by 1.
- `addRefCounter(-1)` returns:
  - **> 0**: Other references exist. Do nothing. **Correct.**
  - **== 0**: This call brought refcount to exactly 0. Caller destroys. **Correct.**
  - **== -1**: Refcount was already 0 (someone else destroyed). Do nothing. **Correct.**

### 1.4 Release: `Context.Close()` (context.go:323-332)

```go
func (context *Context) Close() {
    context.mutex.Lock()
    defer context.mutex.Unlock()
    bindings.Lib.ContextDestroy(context.cContext)
    defer context.handle.Close()
    context.cContext = 0
    context.pinner.Unpin()
}
```

- Destroys the C context under the mutex.
- Calls `handle.Close()` via defer (runs after mutex unlock due to defer ordering).
- **The `handle.Close()` defer executes AFTER the `mutex.Unlock()` defer.** Go defers run LIFO, so:
  1. `context.pinner.Unpin()` runs inline
  2. `defer context.handle.Close()` registered second
  3. `defer context.mutex.Unlock()` registered first

  Execution order on return: `handle.Close()` first, then `mutex.Unlock()`.

  **Wait — correction:** The defers execute in LIFO (last-in, first-out). `mutex.Lock()` + `defer mutex.Unlock()` is registered first. `defer handle.Close()` is registered second. So on exit: `handle.Close()` runs first (last registered), then `mutex.Unlock()` runs second (first registered).

  **This means `handle.Close()` runs WHILE the context mutex is still held.** This is safe: the mutex only protects `cContext`, and by the time `handle.Close()` runs, `cContext` is already zeroed out and destroyed. The handle's refcount operations are lock-free (atomic CAS). No deadlock risk.

### 1.5 Math Summary

| Event | Refcount Delta | Expected Refcount |
|---|---|---|
| `wrapHandle()` | Store(1) | 1 |
| `NewContext()` success | +1 | 2 (1 owner + 1 context) |
| `NewContext()` success (2nd) | +1 | 3 (1 owner + 2 contexts) |
| `Context.Close()` | -1 | 2 |
| `Context.Close()` (2nd) | -1 | 1 |
| `Handle.Close()` (owner) | -1 | 0 -> Destroy |

**The refcount math is correct for the normal lifecycle.**

---

## 2. CAS Loop Analysis: `addRefCounter` (handle.go:116-137)

```go
func (handle *Handle) addRefCounter(x int32) int32 {
    for {
        current := handle.refCounter.Load()    // L119
        if current <= 0 {                       // L120
            return -1                           // L122
        }
        next := current + x                     // L125
        if swapped := handle.refCounter.CompareAndSwap(current, next); swapped { // L126
            if next < 0 {                       // L127
                return 0                        // L132
            }
            return next                         // L134
        }
    }
}
```

### 2.1 BUG: Negative Value Stored on Underflow (handle.go:126-132)

**This is the most critical finding.**

When `next < 0` (line 127), the function returns 0 — but the **CAS has already succeeded** (line 126), meaning the **negative value is now stored** in `refCounter`.

**Scenario triggering this:**
1. Refcount is 1 (only owner reference).
2. Thread A calls `Close()` -> `addRefCounter(-1)`: loads current=1, next=0, CAS succeeds, returns 0. Thread A proceeds to `Destroy()`.
3. Thread B calls `Close()` (double-close bug in caller): loads current=0, hits `current <= 0`, returns -1. **Safe — no underflow here.**

But consider a different scenario with a **race**:
1. Refcount is 1.
2. Thread A calls `addRefCounter(-1)`: loads current=1.
3. Thread B calls `addRefCounter(-1)`: loads current=1.
4. Thread A CAS(1, 0) succeeds. Returns 0. Proceeds to Destroy.
5. Thread B CAS(1, 0) **fails** (current is now 0). Loops back.
6. Thread B loads current=0, hits `current <= 0`, returns -1. **Safe.**

**This particular race is safe** because the CAS prevents the ABA problem. However, the `next < 0` path (line 127-132) represents a **defensive fallback for a scenario that cannot happen in the current CAS loop logic**:

- If `current > 0` (passed the check on L120) and `x == -1` (the only decrement used), then `next = current - 1 >= 0` always, since `current >= 1`.
- The only way `next < 0` could happen is if `x < -current`, meaning someone passes `x = -2` or worse — but this never happens in the codebase (only `+1` and `-1` are used).

**Verdict:** The `next < 0` branch is dead code in practice. If it ever triggered, the stored negative value would cause `current <= 0` to return `-1` for all subsequent callers, effectively preventing double-Destroy. The clamping to return `0` masks the bug but does NOT cause a double-free because only the caller who gets `0` calls Destroy. **However, the negative value remains stored, which would permanently poison the refcounter.**

### 2.2 CAS Loop Correctness for Normal Operations

For `retain()` (x=+1) and `Close()` (x=-1):
- The loop correctly prevents concurrent mutations from corrupting the counter.
- The `current <= 0` early exit correctly prevents incrementing a dead handle.
- The CAS retry loop is standard and correct.

**Verdict: The CAS loop is correct for all operations that actually occur in the codebase (+1/-1).**

---

## 3. Race: `Handle.Close()` vs `NewContext` / `retain()`

**Scenario:** Thread A (appsec) calls `Handle.Close()`. Thread B (request handler) calls `NewContext()`.

### Timeline Analysis:

**Case 1: retain() CAS happens first**
1. Thread B: `retain()` -> loads current=1, CAS(1,2) succeeds, returns 2. Refcount=2.
2. Thread A: `Close()` -> `addRefCounter(-1)`: loads current=2, CAS(2,1) succeeds, returns 1. No Destroy.
3. Thread B: Uses context normally, eventually `Context.Close()` decrements to 0 and Destroys.
- **Safe.**

**Case 2: Close() CAS happens first**
1. Thread A: `Close()` -> `addRefCounter(-1)`: loads current=1, CAS(1,0) succeeds, returns 0. Proceeds to Destroy.
2. Thread B: `retain()` -> loads current=0, hits `current <= 0`, returns -1 (=> false). NewContext returns error.
- **Safe.**

**Case 3: Interleaved loads**
1. Thread A: loads current=1.
2. Thread B: loads current=1.
3. Thread B: CAS(1,2) succeeds. Refcount=2.
4. Thread A: CAS(1,1) **fails** (current is now 2). Retries.
5. Thread A: loads current=2, CAS(2,1) succeeds. Returns 1. No Destroy.
- **Safe.**

**Case 4: Interleaved the other way**
1. Thread B: loads current=1.
2. Thread A: loads current=1.
3. Thread A: CAS(1,0) succeeds. Returns 0. Proceeds to Destroy.
4. Thread B: CAS(1,2) **fails**. Retries.
5. Thread B: loads current=0, hits `current <= 0`, returns -1. NewContext returns error.
- **Safe.**

**Verdict: The CAS ordering between Handle.Close() and retain()/NewContext is safe. All interleavings produce correct behavior.**

**HOWEVER:** There is a critical **TOCTOU window** between `retain()` succeeding and `ContextInit` being called (handle.go:54-58):

```go
if !handle.retain() {           // L54: refcount goes 1->2
    return nil, fmt.Errorf(...)
}
cContext := bindings.Lib.ContextInit(handle.cHandle)  // L58: uses cHandle
```

Between lines 54 and 58, if another thread calls `Handle.Close()` and it happens to be the one that decrements to 0 (e.g., two Close() calls in a buggy caller, or another path), then `Destroy(handle.cHandle)` could execute concurrently with `ContextInit(handle.cHandle)`. **But this cannot happen in correct usage:** after `retain()` succeeds, refcount >= 2, so a single `Handle.Close()` can only bring it to >= 1, never to 0. This is safe as long as `Handle.Close()` is called exactly once by the owner.

---

## 4. `Context.Close()` Double-Close Safety

```go
func (context *Context) Close() {
    context.mutex.Lock()
    defer context.mutex.Unlock()

    bindings.Lib.ContextDestroy(context.cContext)  // L327
    defer context.handle.Close()                    // L328
    context.cContext = 0                             // L329
    context.pinner.Unpin()                           // L331
}
```

**Double-close scenario:**
1. Call 1: acquires mutex, destroys cContext (non-zero), sets cContext=0, schedules handle.Close().
2. Call 2: acquires mutex (after Call 1 releases it), calls `ContextDestroy(0)`.

**Risk:** `ContextDestroy(0)` is called with a NULL pointer. Whether this is safe depends on the C library implementation. If `ddwaf_context_destroy(NULL)` is a no-op (like `free(NULL)`), this is safe. If not, this is a **crash vector**.

**For `handle.Close()`:** Call 1 decrements handle refcount. Call 2 also decrements handle refcount — this is a **double-decrement bug**. The refcount will go one below what it should, potentially causing premature Destroy of the Handle while other contexts still reference it.

**Verdict: `Context.Close()` is NOT double-close safe.** A double-close will:
1. Possibly crash on `ContextDestroy(0)` (depends on C library).
2. Double-decrement the Handle refcount, which can cause **use-after-free of the Handle** by other contexts.

**Note:** The mutex prevents concurrent double-close (serializes the calls), but does not prevent the logical error of the second close performing destructive operations.

---

## 5. `Handle.Addresses()` and `Handle.Actions()` — Unprotected Access (handle.go:79-87)

```go
func (handle *Handle) Addresses() []string {
    return bindings.Lib.KnownAddresses(handle.cHandle)  // L80
}

func (handle *Handle) Actions() []string {
    return bindings.Lib.KnownActions(handle.cHandle)     // L86
}
```

These methods read `handle.cHandle` **without calling `retain()`** and without any synchronization.

**Race scenario:**
1. Thread A calls `handle.Addresses()`, reads `handle.cHandle` (non-zero).
2. Thread B calls `handle.Close()`, decrements to 0, calls `Destroy(handle.cHandle)`, sets `handle.cHandle = 0`.
3. Thread A calls `KnownAddresses()` with a **destroyed cHandle** — **use-after-free**.

Even if the Go read of `handle.cHandle` and the C library call were atomic (they are not), the underlying C object is destroyed, so the pointer is dangling.

**Verdict: `Addresses()` and `Actions()` are unsafe to call concurrently with `Handle.Close()`.** This is a potential SIGSEGV vector. The fix would be to call `retain()` at the start and `Close()` at the end, or document that these must not be called after/concurrently with `Close()`.

---

## 6. Summary of Findings

| # | Finding | Severity | Line(s) | Exploitable? |
|---|---------|----------|---------|-------------|
| 1 | CAS loop stores negative value on underflow before returning 0 | Low (dead code path) | handle.go:126-132 | Only if caller passes x < -1 (never happens) |
| 2 | Handle.Close() vs retain() race | **Safe** | handle.go:54-58, 91-100 | N/A — CAS properly serializes |
| 3 | Context.Close() double-close causes double-decrement of Handle refcount | **High** | context.go:327-328 | Yes — leads to premature Handle destruction, use-after-free |
| 4 | Context.Close() double-close calls ContextDestroy(NULL) | Medium | context.go:327 | Depends on C library NULL handling |
| 5 | Addresses()/Actions() unprotected read of cHandle | **High** | handle.go:79-87 | Yes — use-after-free if called concurrently with Close() |
| 6 | Negative refcount permanently poisons the counter | Low | handle.go:126-132 | Theoretical only — masks bugs but prevents double-Destroy |

### Recommendations

1. **Finding 3 (Critical):** Add a guard in `Context.Close()` to check `cContext != 0` before destroying, and skip `handle.Close()` on the second call:
   ```go
   func (context *Context) Close() {
       context.mutex.Lock()
       defer context.mutex.Unlock()
       if context.cContext == 0 {
           return // Already closed
       }
       bindings.Lib.ContextDestroy(context.cContext)
       defer context.handle.Close()
       context.cContext = 0
       context.pinner.Unpin()
   }
   ```

2. **Finding 5:** Either add retain/release around `Addresses()`/`Actions()`, or clearly document they must not be called after/concurrently with `Close()`.

3. **Finding 1:** Consider clamping the CAS store as well (store 0 instead of negative), or panic to surface the bug immediately rather than silently masking it.
