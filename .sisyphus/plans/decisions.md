## v5 Pre-Release Status
v5 is pre-release; breaking changes allowed as part of v5.0.0 GA.

## TOCTOU Fix Architecture
Architecture B uses activity refcount on `contextRoot` to preserve concurrent Run throughput; Architecture A was rejected because holding `root.mu` across encode+run would serialize execution.

## ctx.Deadline vs Timer Budget
Whichever fires first wins; the returned error matches the source that fired (`ctx.Err()` or `waferrors.ErrTimeout`).

## Refcount Underflow Production Behavior
Hybrid behavior: panic under test/CI build tags via internal invariant checks, silent clamp in production, and no log noise.

## Nil context.Context Handling
Return `fmt.Errorf` wrapping the `waferrors.ErrNilContext` sentinel; do not panic and do not silently fall back to `context.Background()`.
This Nil.ctx handling must stay explicit so callers can detect the failure path.
