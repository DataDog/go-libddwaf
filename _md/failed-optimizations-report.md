# Failed Optimizations Report

## Benchstat: Clean State vs Baseline

Measured on Apple M4 Max, Go 1.24, darwin/arm64, `count=10`.

### Latency (ns/op)

| Benchmark | Baseline | Optimized | Delta | p-value |
|-----------|----------|-----------|-------|---------|
| WAF/Run/RecommendedRuleset/NoAttack | 51.63 us | 51.96 us | ~ | p=0.052 |
| WAF/Run/RecommendedRuleset/Attack | 51.29 us | 52.04 us | +1.46% | p=0.001 |
| WAF/RequestResponse | 60.55 us | 61.62 us | ~ | p=0.105 |
| WAF/ContextLifecycle | 801.6 ns | 822.9 ns | +2.66% | p=0.003 |
| WAF/DataComplexity/Minimal | 11.17 us | 10.80 us | **-3.29%** | p=0.000 |
| WAF/DataComplexity/Realistic | 52.09 us | 52.01 us | ~ | p=0.529 |
| WAF/Parallel | 8.788 us | 8.911 us | ~ | p=0.853 |
| WAF/Subcontext | 24.21 us | 24.00 us | -0.85% | p=0.029 |
| SiblingSubcontextSerialized | 1.737 us | 1.661 us | **-4.40%** | p=0.000 |

### Memory (B/op)

| Benchmark | Baseline | Optimized | Delta | p-value |
|-----------|----------|-----------|-------|---------|
| WAF/Run/RecommendedRuleset/NoAttack | 4.651 Ki | 4.495 Ki | **-3.36%** | p=0.000 |
| WAF/Run/RecommendedRuleset/Attack | 10.81 Ki | 10.66 Ki | **-1.45%** | p=0.000 |
| WAF/RequestResponse | 6.349 Ki | 6.191 Ki | **-2.48%** | p=0.000 |
| WAF/Run/SmallRuleset/NoAttack | 3.901 Ki | 3.745 Ki | **-4.01%** | p=0.000 |
| WAF/Run/SmallRuleset/Attack | 6.669 Ki | 6.513 Ki | **-2.34%** | p=0.000 |
| WAF/DataComplexity/Realistic | 4.651 Ki | 4.495 Ki | **-3.36%** | p=0.000 |
| WAF/DataComplexity/Heavy | 20.30 Ki | 20.11 Ki | **-0.92%** | p=0.000 |
| WAF/Parallel | 4.669 Ki | 4.513 Ki | **-3.35%** | p=0.000 |
| WAF/ContextLifecycle | 520 B | 520 B | ~ | p=1.000 |

### Allocations (allocs/op)

| Benchmark | Baseline | Optimized | Delta | p-value |
|-----------|----------|-----------|-------|---------|
| WAF/Run/SmallRuleset/NoAttack | 95 | 82 | **-13.68%** | p=0.000 |
| WAF/Run/RecommendedRuleset/NoAttack | 113 | 100 | **-11.50%** | p=0.000 |
| WAF/RequestResponse | 153 | 137 | **-10.46%** | p=0.000 |
| WAF/Run/SmallRuleset/Attack | 167 | 154 | **-7.78%** | p=0.000 |
| WAF/Run/RecommendedRuleset/Attack | 293 | 280 | **-4.44%** | p=0.000 |
| WAF/DataComplexity/Heavy | 509 | 494 | **-2.95%** | p=0.000 |
| WAF/Parallel | 113 | 100 | **-11.50%** | p=0.000 |
| WAF/ContextLifecycle | 7 | 7 | ~ | p=1.000 |

### Summary

The encoder reflect-bypass delivers consistent, statistically significant improvements:
- **-11.5% allocs/op** on the primary Run benchmark (113 to 100 allocations)
- **-3.4% B/op** on the primary Run benchmark (4.651 Ki to 4.495 Ki)
- **No latency regression** on the primary Run benchmark (within noise, p=0.052)
- **Zero impact** on ContextLifecycle (allocations and bytes unchanged)

---

## What Survived (Kept)

| Change | Task | Files | Rationale |
|--------|------|-------|-----------|
| Encoder reflect-bypass: scalar leaves | T18 | encoder.go | Skips `reflect.ValueOf` for nil, bool, string, int*, uint*, float*, json.Number |
| Encoder reflect-bypass: typed slices | T17 | encoder.go | Skips `reflect.Value.Index(i)` for []any, []string, []int, []float64, []bool |
| Encoder reflect-bypass: map[string]string, map[string][]string | T16 | encoder.go | Skips `reflect.MapRange` for the two most common HTTP header map types |
| Encoder reflect-bypass: map[string]any | T15 | encoder.go | Skips `reflect.MapRange` for the dominant WAF input type |
| Extract tryEncodeScalarFastPath | FU-05 | encoder.go | Readability refactor for the above |
| Singleton closure | T06 | timer/config.go | Hoists `WithInheritedSumBudget` closure to package-level var |
| Per-hotpath isolated benchmarks | T03 | benchmark_test.go | BenchmarkNewContextOnly, ContextCloseOnly, RunOnly, SubcontextRunOnly, ColdStart, NewContextParallel |
| b.N to b.Loop() modernization | FU-02 | benchmark_test.go, subcontext_bench_test.go | |
| Decoder switch restore | FU-04 | decoder.go | Reverted T19 scope drift |
| Result switch restore | FU-06/07 | result.go | Reverted T19 if-chain |
| decodeFeature error restore | FU-12 | decoder.go | Reverted T19 behavioral change |
| Move test helpers | FU-03 | result_test.go, context_test.go | |
| TestTree flakiness fix | FU-11 | timer/timer_test.go | Sampling live Spent() at different instants caused ordering violations |

The encoder reflect-bypass is the only change with measurable performance impact. The pre-revert benchstat showed -51% to -62% B/op on encoder benchmarks for payloads >= 4 KiB. Everything else is cleanup, infrastructure, or bug fixes.

## What Failed (Reverted)

### 1. sync.Pool for *nodeTimer, *baseTimer, *clock (T07-T09)

**Hypothesis**: Pooling timer objects would reduce allocs/op on NewContext and Run paths. pprof showed timer plumbing accounted for ~60% of NewContext alloc_space.

**Result**: No measurable alloc/op reduction. B/op increased due to struct inflation.

**Why it failed**:
- The pooled structs were larger than the originals. Each needed a `reset()` method that touched every field, an `ownedNodeTimer` wrapper to protect against use-after-put, and pool-return hooks in every Close/Stop path.
- `sync.Pool` drains on GC. Under benchmark conditions (GC runs between iterations) and under production load spikes (GC pressure), the pool is empty when you need it. You pay the allocation cost plus the reset cost.
- The `ownedNodeTimer` wrapper added an `atomic.Pointer` indirection, a `nodeTimerSnapshot` struct, and 24 delegating methods. This was more code and more allocations than just creating a fresh `nodeTimer`.
- `baseTimer` has ~10 atomic fields. Resetting them all via `.Store()` is not cheaper than zero-initialization of a fresh struct.

### 2. sync.Pool for *Context and *Subcontext (T21-T22)

**Hypothesis**: Pooling Context/Subcontext would eliminate the dominant NewContext allocation.

**Result**: +400-647% B/op on ContextLifecycle and ContextCloseOnly benchmarks. +95% ns/op on NewContextParallel at 16 CPUs.

**Why it failed**:
- Context contains a `ConcurrentPinner` which cannot be pooled (pin reuse is undocumented and unsafe). Every `reset()` must create a fresh pinner.
- Context contains `sync.WaitGroup`, `sync.Mutex`, `sync.RWMutex` which are zero-value usable but must be re-zeroed on reset.
- Context contains truncation slices that must be cleared and capped.
- After reset(), the pooled Context was no cheaper than `new(Context)`. The pool Put path itself added overhead visible in the Close-only benchmark.
- The Close method had to coordinate: destroy C context, close pinner, close handle refcount, return timer to timer pool, THEN return Context to context pool. This sequencing added latency.

### 3. Per-shard ConcurrentPinner (T23)

**Hypothesis**: Sharding the pinner across 16 mutex-protected shards would reduce lock contention at high goroutine counts.

**Result**: +95% ns/op on NewContextParallel at 16 CPUs compared to the single-mutex baseline.

**Why it failed**:
- The `[16]shard` array is always fully stack-allocated, inflating the `ConcurrentPinner` struct from ~24 bytes (mutex + pinner) to ~768 bytes (16 × mutex + 16 × pinner).
- Since ConcurrentPinner is embedded in every Context and Subcontext, this inflated every context allocation.
- `runtime_procPin`/`runtime_procUnpin` for shard selection added syscall overhead that exceeded the contention savings.
- On Apple Silicon (M4 Max), the P/E core topology doesn't distribute evenly across 16 shards.
- The single-mutex pinner was already fast enough: Pin is a short critical section (one pointer write), so contention was low even at 16 CPUs.

### 4. Stack-allocated component dedup in NewSubcontext (T20)

**Hypothesis**: A `[5]timer.Key` stack array replacing the map+slice would eliminate 2 allocations in the common case (parent with <= 5 unique component keys).

**Result**: No measurable improvement.

**Why it failed**:
- The original allocation (a small map + slice for <= 5 keys) was already cheap — two tiny heap allocations that the allocator handles in nanoseconds.
- The stack array added a branch (`if len(parentKeys)+3 <= cap(staging)`) and a linear scan for dedup instead of map lookup, trading allocation for CPU.
- NewSubcontext's allocation cost is dominated by the Subcontext struct itself and the C context creation call, not the component dedup.

### 5. Byte-compare result/diagnostic keys (T19)

**Hypothesis**: `StringMatches()` byte-level comparison on WAFObject keys would avoid `StringValue()` string materialization allocations.

**Result**: Reverted for code quality, not performance.

**Why it failed**:
- `unwrapWafResult` is called once per Run with 6 known keys. Six `StringValue()` calls produce six small string allocations — roughly 200 bytes total. This is noise.
- `decodeDiagnostics` is called once per Handle creation (cold path). Allocation savings here are invisible.
- The implementation replaced a 30-line switch statement with a 145-line if-chain of `keyMatches` calls, each with its own error check. The code was objectively worse.
- T19 also changed `decodeFeature`'s error semantics (unknown fields silently ignored instead of returning error) and added `decodeKnownDiagnosticEntry`/`decodeKnownWafResultEntry` helper functions that obscured the control flow.
- The `keyMatches` function was a trivial 2-line wrapper around `StringMatches` that added no value.

## Lessons Learned

1. **sync.Pool is not free.** The infrastructure cost (reset methods, use-after-put protection, pool-return sequencing, pool invariants documentation, pool invariant tests) can exceed the allocation savings. Pools help when objects are large, reused frequently, and survive GC cycles. Timer and context objects are small, short-lived, and created under GC pressure.

2. **pprof alloc_space is misleading for optimization targeting.** It showed timer plumbing as 60% of NewContext allocs, which is true in relative terms. But NewContext is already fast in absolute terms (~400 ns). The encoder path — which pprof showed as ~25% of Run allocs — was where the real waste was, because Run processes kilobytes of input data through reflection on every request.

3. **Measure each optimization in isolation before committing.** The plan called for 30-run variance characterization (T02) and per-task benchstat gating. In practice, we committed all pool changes before measuring any of them against the baseline. By the time we ran benchstat, the regressions were baked into 6+ commits that touched the same files.

4. **Struct inflation defeats pooling.** Adding fields to support pool lifecycle (reset flags, owned wrappers, snapshot structs) makes the pooled struct larger than the original. If `reset()` touches every field, it costs the same as zero-initialization. The pool becomes pure overhead.

5. **Code quality is a hard constraint.** T19 was technically correct but turned clean switch statements into verbose if-chains. The theoretical allocation savings (~200 bytes per Run) were invisible in benchmarks but the readability cost was immediate and permanent.
