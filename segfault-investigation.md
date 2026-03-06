# SIGSEGV Investigation: `cloud-streams-processor-oci-metrics`

## Crash Timeline

- **Start**: Feb 26, 2026 at 14:00:56 UTC (15:00 CET)
- **End**: Feb 26, 2026 at ~14:36 UTC (15:36 CET)
- **Duration**: ~35 minutes
- **Total crash events**: 45 unique SIGSEGV emergency events, 150 total SIGSEGV-related log lines
- **Hosts affected**: 10 EC2 instances (crash-looping simultaneously)
- **Recurrence**: None — no SIGSEGV crashes observed after Feb 26

## Affected Hosts

| Host | Crash Count |
|------|-------------|
| i-070bfa03cee9505e8 | 18 |
| i-02979f833d7f6015e | 17 |
| i-0fe47e4545f4c4f72 | 17 |
| i-09300e8ea9c8def93 | 17 |
| i-03f182b0cf07732a5 | 16 |
| i-0603704b9ae27a54a | 15 |
| i-0186efa6ff6e13a95 | 14 |
| i-0a158ab3be86ac797 | 14 |
| i-0ffbedc4637467277 | 13 |
| i-0253482325ba93e39 | 9 |

## Kubernetes Context

- **Deployment**: `cloud-streams-processor-oci-metrics-customer-64-127`
- **Namespace**: `oci-integrations`
- **Cluster**: `whiscash`
- **Pod status**: CrashLoopBackOff ("BackOff: Back-off restarting failed container cloud-streams-processor")

## Root Cause: Crash in native libddwaf during startup

The SIGSEGV occurs at application bootstrap, before the service ever starts processing. The crash is a null pointer dereference (`addr=0x0`) inside the native libddwaf C library when parsing the embedded default ruleset JSON.

### Stack Trace

```
main.main()                                          main.go:89
  → ddapp.Bootstrap()                                bootstrap.go:462
    → tracer.Start()                                 tracer.go:276
      → appsec.Start()                               appsec.go:84
        → NewWAFManagerWithStaticRules()              wafmanager.go:51
          → RestoreDefaultConfig()                    wafmanager.go:154
            → AddDefaultRecommendedRuleset()          builder.go:68
              → DefaultRuleset()                      ruleset.go:44
                → Lib.ObjectFromJSON(decompressed)    waf_dl.go:250  ← CRASH
                  → purego.SyscallN()                 syscall.go:55
                    → SIGSEGV addr=0x0
```

### What happens step by step

1. At startup, the tracer initializes AppSec with the WAF (Web Application Firewall).
2. The WAF manager loads the embedded default ruleset (`recommended.json.gz`).
3. The gzipped ruleset is decompressed successfully.
4. The decompressed JSON (193,082 bytes) is passed to the native libddwaf C library via `ddwaf_object_from_json`.
5. The native C library segfaults with a null pointer dereference (`addr=0x0`) while parsing this JSON.

### Relevant source code

`internal/ruleset/ruleset.go:44`:
```go
parsedRuleset, ok := bindings.Lib.ObjectFromJSON(decompressedRuleset)
```

`internal/bindings/waf_dl.go:250`:
```go
success := waf.syscall(waf.objectFromJSON, unsafe.PtrToUintptr(&obj), unsafe.SliceToUintptr(json), uintptr(len(json))) != 0
```

## Library Versions

- **go-libddwaf**: `v4@v4.8.0` (includes libddwaf v1.30.0)
- **dd-trace-go**: `v2@v2.6.0`
- **purego**: `v0.9.1`

## Assessment

The crash pattern (all 10 hosts starting to crash simultaneously at 14:00 UTC, then stopping at ~14:36) strongly indicates a deployment/rollout triggered this. The CrashLoopBackOff confirms the pods kept restarting and crashing on every start. The resolution at ~14:36 suggests either a rollback or a fix was deployed.

The bug is in the native libddwaf v1.30.0 C library — it fails to handle some edge case in the embedded ruleset JSON parsing, causing a null pointer dereference. The Go side (`ruleset.go:44`, `waf_dl.go:250`) is just passing the decompressed JSON through; the crash happens inside the C code called via purego/CGO.
