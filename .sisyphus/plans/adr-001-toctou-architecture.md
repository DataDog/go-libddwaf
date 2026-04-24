# 1. Use Activity Refcount on contextRoot for TOCTOU Safety (Architecture B)

Date: 2026-04-24

## Status

Accepted

## Context

`review.md:350-374` identifies a TOCTOU race: `context.go:229-267` releases `root.mu` between the first closed-check and encoding, allowing `Close()` on another subcontext to invalidate `root.cContext`. Two architectures were considered:
- A: Hold `root.mu` across the entire encode+run window (serializes all concurrent `Run` calls)
- B: Add `activeRuns atomic.Int64` to `contextRoot`; `Close()` waits for it to reach 0

## Decision

**Architecture B** selected: add `activeRuns atomic.Int64` to `contextRoot`. `Run()` increments before encode, decrements after. `Close()` sets a closed flag then waits for `activeRuns == 0` before calling `bindings.Lib.ContextDestroy`.

## Consequences

- Preserves concurrent `Run` throughput (multiple goroutines can encode/evaluate simultaneously)
- dd-trace-go AppSec per-request hot path is not serialized
- +1 atomic.Int64 per `contextRoot` struct
- `Close()` may block briefly waiting for in-flight evaluations
- Acquire-release semantics required: closed flag set BEFORE reading `activeRuns` in Close(); readers in Run() load closed BEFORE incrementing activeRuns
