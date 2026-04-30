# Plumbing allocation reduction — remaining opportunities

Baseline: v5-dev branch, Apple M4 Max, `BenchmarkWAF` suite.
Completed work saved cumulative **-5.4% allocs/op, -5.0% B/op, -1.9% ns/op** (geomean).

This file documents the validated-but-not-yet-implemented optimizations,
ordered by expected payoff based on pprof profiles captured in `.bench/pprof-v5/`.

## 1. Per-run timer node construction

**Status**: partially addressed (batch 2 cached `WithComponents` and fast-pathed `MustLeaf`)
**Remaining cost**: `newRunTimer` still allocates a full `nodeTimer` with `newComponents` (map + atomic slice) on every `Run()`.

**pprof evidence** (`run-recommended-noattack.top.txt`):
- `timer.newComponents`: 11.9 MB (10.8%)
- `timer.(*nodeTimer).NewNode`: 12.3 MB cum
- `timer.(*nodeTimer).NewLeaf`: 8.5 MB cum
- `timer.newConfig`: 5.7 MB

**Opportunity**: the 3-component set `{encode, duration, decode}` is fixed for every run timer. A specialized lightweight run-timer struct with 3 inline `atomic.Int64` fields instead of a `map[Key]*atomic.Int64` would eliminate the map allocation, the `[]atomic.Int64` backing array, and the config construction per run. This is the single largest remaining plumbing allocation.

**Risk**: medium. Requires a new concrete type implementing `NodeTimer` or a subset of it. Must preserve `Stats()`, `AddTime()`, `MustLeaf()`, `SumSpent()`, `SumRemaining()`, and `SumExhausted()` semantics exactly.

**Estimated gain**: ~4-6 allocs/op on every Run-path benchmark.

## 2. Per-run encoder and config construction

**Status**: not addressed.
**Current cost**: every `Run()` call allocates:
- `WithTimer(t)` closure (captures timer pointer)
- `EncoderConfig` struct (may escape to heap via `newEncoder`)
- `*encoder` struct

**pprof evidence** (`run-recommended-noattack.top.txt`):
- `newEncoder`: 1.0 MB
- `newEncoderConfig`: 1.0 MB

**Opportunity**:
- Inline the `encodeAddressData` path to avoid the `WithTimer` closure allocation — pass the timer directly into `EncoderConfig` instead of via an option function.
- If `encoder` doesn't escape (stack-allocatable), restructure so the compiler can prove it stays on the stack. Today the `&encoder{...}` return from `newEncoder` forces a heap escape.

**Risk**: low. The encoder is single-use per run and not retained.

**Estimated gain**: ~2 allocs/op per run.

## 3. WAF object container allocation in `SetMap` / `SetArray`

**Status**: not addressed.
**Current cost**: `SetMap` and `SetArray` in `internal/bindings/ctypes.go` allocate backing arrays for WAF object children.

**pprof evidence** (`run-recommended-noattack.top.txt`):
- `(*WAFObject).SetMap`: 14.5 MB cum (13.2%)
- `(*WAFObject).SetArray`: 6.1 MB cum
- `reflect.unsafe_New`: 16.9 MB (15.3%) — driven by map iteration boxing

**Opportunity**:
- Pre-size WAF object arrays more aggressively using known input sizes.
- Reduce reflection-driven boxing in hot map iteration paths (`reflect.(*MapIter).Key`, `reflect.(*MapIter).Value`, `reflect.copyVal`). These account for ~12.4% cumulative allocation in the run profile.
- Explore whether `(*WAFObject).MapValue` decoding can avoid intermediate allocations when the result is immediately consumed.

**Risk**: medium-high. Changes touch C interop, pinning, and memory layout. Careful lifetime management required.

**Estimated gain**: hard to estimate without prototyping, but `SetMap` + `SetArray` + reflection boxing together are ~30% of the run profile allocation.

## 4. Subcontext timer construction

**Status**: partially addressed (batch 1 replaced `Stats()` with `ComponentKeys()` in `NewSubcontext`)
**Remaining cost**: `NewSubcontext` still builds a full `timer.NewTreeTimer` with `newComponents`, `newConfig`, and `newTimeCache`.

**pprof evidence** (`subcontext.top.txt`):
- `timer.newComponents`: 39.7 MB (21.7%)
- `timer.NewTreeTimer`: 82.8 MB cum (45.2%)
- `timer.newConfig`: 20.4 MB
- `timer.newTimeCache`: 4.5 MB
- `(*Context).NewSubcontext`: 58.2 MB cum (32.5%)

**Opportunity**: same as #1 — a lighter fixed-component timer for the subcontext path would eliminate the map/slice allocation. Additionally, the `seen` map and `components` slice built in `NewSubcontext` to deduplicate parent keys could be eliminated if the parent timer exposes its component set directly.

**Risk**: medium. Same considerations as #1.

**Estimated gain**: ~2-4 allocs/op on the Subcontext benchmark.

## 5. `wrapWAFObjectKVs` allocation

**Status**: not addressed.
**Current cost**: each map encoding allocates a `[]WAFObjectKV` wrapper slice.

**pprof evidence** (`run-recommended-noattack.top.txt`):
- `wrapWAFObjectKVs`: 1.0 MB

**Opportunity**: if `WAFObjectKV` and the internal binding KV type have identical layout, the wrapping could be a cast instead of a copy. Alternatively, pre-allocate the KV slice from a pool or caller-owned buffer.

**Risk**: low-medium. Requires verifying memory layout compatibility.

**Estimated gain**: ~1 alloc/op per map in the input.

## 6. Decode-path container materialization

**Status**: not addressed.
**Current cost**: `decodeWafResult` and `unwrapWafResult` allocate Go maps and slices for every WAF result.

**pprof evidence** (`requestresponse.top.txt`):
- `decodeWafResult`: 22.9 MB cum (20.1%)
- `unwrapWafResult`: 16.3 MB cum
- `(*WAFObject).MapValue`: 13.1 MB cum
- `(*WAFObject).StringValue`: 5.7 MB
- `(*WAFObject).AnyValue`: 3.1 MB

**Opportunity**:
- For no-event runs (the common case), `unwrapWafResult` should short-circuit earlier to avoid materializing empty containers.
- For event runs, the `decodeAttributes` path allocates heavily through `MapValue` — a streaming decode that writes directly into the result struct fields could reduce intermediate containers.
- The `MustLeaf(DecodeTimeKey)` call in `decodeWafResult` was already optimized (batch 2), but the decode itself is still the main cost.

**Risk**: medium. Decoded results are returned to callers who own them. Any reuse scheme must not leak mutable internal state.

**Estimated gain**: primarily visible on attack/event-path benchmarks. The no-event path may already be close to optimal after the timer work.

## 7. `newWAFObject` per-run allocation

**Status**: not addressed.
**Current cost**: each `Run()` allocates a `WAFObject` for the result via `newWAFObject()`, pins it, and destroys it after decoding.

**pprof evidence** (`run-recommended-noattack.top.txt`):
- `newWAFObject`: 0.7 MB

**Opportunity**: small. The result WAF object could be stack-allocated if the compiler can prove it doesn't escape, or reused via a context-owned scratch slot.

**Risk**: low, but pinning semantics must be preserved.

**Estimated gain**: ~1 alloc/op per run.

## Summary table

| Opportunity | Est. allocs saved | Risk | Depends on |
|---|---|---|---|
| Specialized fixed-component run timer | 4-6/op | Medium | Timer refactor |
| Encoder/config construction inline | 2/op | Low | — |
| WAF object container pre-sizing + reflection | Hard to estimate | Medium-High | Bindings knowledge |
| Subcontext timer construction | 2-4/op | Medium | #1 |
| `wrapWAFObjectKVs` cast | 1/op per map | Low-Medium | Layout verification |
| Decode short-circuit + streaming | Event-path only | Medium | — |
| `newWAFObject` stack/reuse | 1/op | Low | Escape analysis |
