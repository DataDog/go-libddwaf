# Consumer Impact Analysis — go-libddwaf v5 Breaking Changes

## dd-trace-go Import Version

**v4** — detected via `gh api repos/DataDog/dd-trace-go/contents/go.mod` on 2026-04-24.  
Pinned to: `github.com/DataDog/go-libddwaf/v4 v4.9.0`

> Note: v5 is not yet indexed by deps.dev (pre-release). Impact scan covers v4→v5 migration surface.

## Scan Metadata

- **Scan date**: 2026-04-24
- **Clone**: `https://github.com/DataDog/dd-trace-go` (shallow, `--depth=1`)
- **Scope**: production `.go` files only (excludes `_test.go`)

## API Change Impact Table

| API Change | Call Sites | Sample Files |
|---|---|---|
| `Build() *Handle` → `Build() (*Handle, error)` | 5 | `internal/appsec/config/wafmanager.go`, `internal/appsec/listener/httpsec/http.go`, `internal/appsec/listener/httpsec/roundtripper.go`, `internal/appsec/listener/usersec/usec.go` |
| `NewContext(timerOpts...)` → `NewContext(ctx, timerOpts...)` | 1 | `internal/appsec/listener/waf/waf.go` |
| `Run(data)` → `Run(ctx, data)` | 2 | `internal/appsec/emitter/waf/run.go`, `internal/appsec/emitter/waf/context.go` |
| `SubContext()` → `SubContext(ctx)` | 0 | _(not used in dd-trace-go)_ |
| `WAFObject` type alias → domain wrapper | 21 | `internal/appsec/body/json/jsoniter.go`, `internal/appsec/body/json/simdjson.go` |
| `WAFObjectKV` type alias → domain wrapper | 0 | _(not used in dd-trace-go)_ |
| `Encodable` interface narrowing | 15 | `internal/appsec/body/body.go`, `internal/appsec/body/json/jsoniter.go`, `internal/appsec/body/json/simdjson.go`, `instrumentation/appsec/emitter/httpsec/http.go`, `instrumentation/appsec/emitter/httpsec/roundtripper.go` |

## Summary

**Total affected call sites: 44** across **7 unique production files**.

Migration complexity is **moderate**:

- `Build()` (5 sites): Requires adding error handling at each call site — callers already use `err` returns at surrounding scope, so this is mechanical.
- `NewContext()` (1 site): Single call site in `waf.go`; straightforward `ctx` parameter addition.
- `Run()` (2 sites): Direct WAF context invocations in emitter layer; adding `ctx` is mechanical.
- `SubContext()` / `WAFObjectKV` (0 sites): No migration needed — these APIs are unused in dd-trace-go.
- `WAFObject` (21 sites): Concentrated in 2 files implementing the `Encodable` interface. If the type remains structurally compatible (same fields), this may be zero-change; if the wrapper adds indirection, both files need updates.
- `Encodable` (15 sites): Interface narrowing is the highest-risk change. dd-trace-go has 5 production files implementing `libddwaf.Encodable` directly. Any signature change to the interface's `Encode()` method will require coordinated updates across `body/body.go` and both JSON encoder implementations.

**Primary risk**: `Encodable` interface narrowing cascades across `body` package and both JSON codec implementations simultaneously. The `smoke-tests` CI job provides the authoritative compatibility gate.
