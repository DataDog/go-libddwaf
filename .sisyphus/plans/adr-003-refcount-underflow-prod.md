# 3. Refcount Underflow Production Behavior

Date: 2026-04-24

## Status

Accepted

## Context

`review.md:106-137` identifies a silent bug at `handle.go:133-138` where refcount going negative is clamped to 0 with a TODO comment. Three options: (a) always panic, (b) log+clamp, (c) panic in dev/test, clamp in prod.

## Decision

**Hybrid approach**: panic under `test` or `ci` build tags via `internal/invariant.Assert`; silent clamp (return 0) in production. No logging. User explicitly chose "no-op otherwise" for production safety. `internal/invariant` package will provide `Assert(cond bool, format string, args ...any)` — no-op without `ci` tag, panics with it.

## Consequences

- Bugs surface loudly in CI and local test runs
- Production is never crashed by this invariant
- No new log infrastructure needed (no Go-side logger exists)
- The `ci` build tag is set in `.github/workflows/ci.sh:30`
- Downstream consumers MUST NOT set the `ci` build tag (documented via godoc)
