# IR-50594: SIGSEGV in unified-graph-platform-intake — ddwaf_run / ddwaf_context_init

## Summary

89 SIGSEGV crashes across multiple hosts in us5, eu1, us3 regions. Services `unified-graph-platform-intake` and `unified-graph-processor` crash-looping on deploy. Rollback stabilized. **This is NOT the same bug as the Feb 26 cloud-streams-processor crash.**

## Affected versions

- Build: `v100696420-a984cbf` (git sha `a984cbf347e8411437624431f218c8c64701c20f`)
- go-libddwaf: v4 (exact version TBD from go.mod at that commit)
- Architecture: linux/amd64 (prod) AND linux/arm64 (staging)

## Impacted libddwaf functions

| C function | Go binding | Location | When |
|---|---|---|---|
| `ddwaf_run` | `WAFLib.Run` | `waf_dl.go:233` | WAF rule evaluation per-request |
| `ddwaf_context_init` | `WAFLib.ContextInit` | `waf_dl.go:210` | WAF context creation per-request |

Both crash during **runtime gRPC request handling** (`BatchAddNodes`), not during startup.

## Crash patterns (89 total)

### Pattern A: addr=0x0, various PCs
- PCs: `0x5a88afa`, `0x5a88ca2`, `0x5542060`, `0x5528320`
- OS threads: m=3,4,5,7,8,9,10,12,14,15,17 (never main thread)
- Full stack traces confirm both `ddwaf_context_init` and `ddwaf_run`
- True NULL dereference inside the native library

### Pattern B: non-zero low addr, consistent PC
- PC: `0x5a2e7c8` (all instances)
- addr range: `0x2a48` – `0x1fe950` (~10KB – ~2MB)
- OS threads: mostly m=0, some m=3,4,7,8
- Suggests dereferencing a pointer computed from a NULL base + offset (corrupted struct or freed memory)

## Staging reproduction

Crash reproduced on **arm64** staging (see `gouroutine.log`):
- Function: `ddwaf_run` via `WAFLib.Run` at `waf_dl.go:233`
- Call path: `grpcsec.Feature.OnStart` → `ContextOperation.Run` → `Context.Run` → `Context.run` → `WAFLib.Run`
- Goroutine 7530, m=15

## Comparison with Feb 26 (cloud-streams-processor)

| | Feb 26 | Mar 5 (this incident) |
|---|---|---|
| Function | `ddwaf_object_from_json` | `ddwaf_run` + `ddwaf_context_init` |
| When | Startup (goroutine 1) | Runtime (request handling) |
| Thread | Always m=0 | Multiple worker threads |
| addr | Always 0x0 | Mixed 0x0 and non-zero |
| Platform | linux/amd64 only | linux/amd64 + arm64 |
| Root cause | Missing NULL check in `emplace()` on malloc failure | **Unknown — under investigation** |

**These are different bugs.** The Feb 26 fix (NULL check in `emplace()`) does not address this incident.

## Hypotheses

1. **Use-after-free**: A WAF handle or context is freed/invalidated while still being used by concurrent requests. The varying non-zero crash addresses are consistent with accessing freed memory that's been partially reused.
2. **Concurrency bug in libddwaf**: `ddwaf_run` or `ddwaf_context_init` are not thread-safe in a way that go-libddwaf assumes they are.
3. **Invalid handle passed to ddwaf_context_init**: The WAF handle could be NULL or corrupted when passed to context init, causing a crash inside the C code.

## Next steps

- [ ] Investigate `ddwaf_context_init` and `ddwaf_run` in libddwaf source for thread safety and NULL handle handling
- [ ] Check if the go-libddwaf `Handle` or `Context` could be used after `Close()`
- [ ] Check what changed in the bad deploy's dependency tree (dd-trace-go version, go-libddwaf version)
- [ ] Get the exact go-libddwaf version from the build at commit `a984cbf`
