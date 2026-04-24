# 2. ctx.Deadline vs Timer Budget Precedence

Date: 2026-04-24

## Status

Accepted

## Context

`review.md:780-794` proposes adding `context.Context` to `Run`, `NewContext`, `SubContext`. This creates dual-deadline mechanisms: `ctx.Deadline()` from Go context + the existing Timer budget. The interaction must be defined to avoid confusing callers.

## Decision

**Whichever fires first wins**. The implementation must watch both `ctx.Done()` and the Timer budget concurrently. The returned error matches the fired source: `ctx.Err()` if context fires, `waferrors.ErrTimeout` if Timer fires. Every public method accepting `ctx context.Context` must explicitly document this precedence in its godoc.

## Consequences

- Callers with their own timeout can override the Timer budget
- Callers using `context.Background()` experience unchanged Timer behavior
- No ambiguity about which error is returned
- Slightly more complex implementation (need to watch both channels/timers)
