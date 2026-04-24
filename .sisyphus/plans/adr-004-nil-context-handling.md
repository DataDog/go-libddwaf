# 4. Nil context.Context Handling

Date: 2026-04-24

## Status

Accepted

## Context

`review.md:752-767, 1000` identifies that when adding `context.Context` to `Run`, `NewContext`, `SubContext`, callers may pass `nil`. Options: (a) panic (stdlib convention for HTTP), (b) fallback to `context.Background()`, (c) return error.

## Decision

**Return wrapped `waferrors.ErrNilContext` sentinel**: `fmt.Errorf("Context.Run: %w", waferrors.ErrNilContext)`. NO panic (would violate production safety convention). NO silent `context.Background()` fallback (per plan guardrail G15 — hides programming errors).

## Consequences

- Callers learn about nil ctx via error return, not panic
- Consistent with the project's "log+clamp" production safety ethos
- `waferrors.ErrNilContext` sentinel enables `errors.Is` checking by callers
- Every new `ctx`-accepting method must nil-check immediately at entry and return this error
