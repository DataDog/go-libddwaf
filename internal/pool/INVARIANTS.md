# Pool Correctness Invariants

This document establishes the canonical contract for all `sync.Pool` usage in this project. Every pooled type must implement a `Reset()` method that satisfies these invariants to ensure memory safety, prevent leaks, and maintain predictable performance.

## Core Invariants

### 1. Zero scalar fields
All primitive fields (int, bool, float, etc.) must be reset to their zero value. This prevents stale state from leaking between different operations using the same pooled object.

### 2. Nil reference fields
All pointer types (`*T`), slice headers, map references, and interface values must be set to nil or their zero value. This is critical for allowing the Garbage Collector to reclaim downstream allocations that are no longer needed.

### 3. Truncate but retain slice capacity
Slices should be truncated to zero length but retain their underlying capacity if it is less than or equal to 32. If the capacity exceeds 32, the slice must be dropped (set to nil) to bound the resident memory of the pool.

### 4. Clear slice contents before truncation
Before truncating a slice, its contents must be cleared (e.g., using the `clear()` built-in or by zeroing elements). This prevents the pool from retaining live references to objects that should be collected, such as pinned WAFObject children.

### 5. Zero Truncations value type
The `Truncations` struct (or similar value-typed metadata structs) must be zeroed at the start of each operation. Since it is a value type, it should be overwritten with a fresh instance.

### 6. Never retain pinned-pointer-bearing fields
Fields that held pinned pointers must be zeroed before the object is returned to the pool. While the `runtime.Pinner` lifetime ends at `Unpin`, the pooled object must not retain any references to that memory after the `Put` call.

### 7. Idempotent Put
Calling `Put` twice on the same object must not corrupt the pool. If a pool requires single-shot semantics, it should use a pooled `atomic.Bool` flag to track whether the object has already been returned.

### 8. Pool of pools order
When a pooled object contains other pooled objects, the parent must call `Put` on the nested objects before zeroing its own references to them.

### 9. Test fixture requirement
Every pooled type `T` must have a corresponding `TestPoolInvariants_<T>` unit test. This test must assert that a `Get -> Use -> Put -> Get` cycle results in an object that is indistinguishable from a freshly allocated one.

### 10. Zero-value validity
The `pool.New()` function must return a pointer to a type whose `Reset()` method leaves it in the exact same state as a freshly allocated `T{}`.

## Code Examples

### Slice-bearing type Reset()
This example demonstrates clearing slice contents and enforcing the capacity bound.

```go
type Buffer struct {
    data []byte
}

func (b *Buffer) Reset() {
    if cap(b.data) > 32 {
        b.data = nil
    } else {
        clear(b.data)
        b.data = b.data[:0]
    }
}
```

### Reference-bearing type Reset()
This example shows how to handle pointers, maps, and interfaces to prevent memory leaks.

```go
type Context struct {
    User    *User
    Meta    map[string]string
    Handler any
}

func (c *Context) Reset() {
    c.User = nil
    c.Meta = nil
    c.Handler = nil
}
```

### Struct-fields-only type Reset()
This example covers zeroing scalar fields and handling types that are usable in their zero state.

```go
type Metrics struct {
    mu      sync.Mutex
    count   atomic.Int64
    active  bool
    latency float64
}

func (m *Metrics) Reset() {
    // Mutex does not need reset if it's not held
    m.count.Store(0)
    m.active = false
    m.latency = 0
}
```

## Forbidden Patterns

- **Pooling runtime.Pinner**: Reusing `runtime.Pinner` or `pin.ConcurrentPinner` is undocumented and unsafe. Always allocate a fresh pinner for the duration of the pin operation.
- **runtime.SetFinalizer on pooled objects**: Finalizers may run after an object has been returned to the pool and subsequently reused, leading to non-deterministic behavior and pool corruption.
- **Retaining large slice capacity**: Retaining slices with capacity > 32 without explicit, documented justification is forbidden as it leads to excessive resident memory usage.
- **Retaining pinned-pointer-bearing fields**: Storing references to memory that was previously pinned violates the pin lifetime contract and can lead to use-after-free scenarios.

## pool.New() Requirements

The `New` function provided to `sync.Pool` must return a valid, zero-state object. The state of an object returned by `New()` must be identical to the state of an object after a `Reset()` call. This ensures that the application logic can treat objects from the pool and freshly allocated objects interchangeably.
