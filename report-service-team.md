# Incident Report: cloud-streams-processor-oci-metrics SIGSEGV (Feb 26, 2026)

## Summary

45 SIGSEGV crashes across 10 EC2 instances over 35 minutes (14:00–14:35 UTC). Pods in CrashLoopBackOff during startup. No recurrence since.

## Timeline

- **14:00 UTC**: First SIGSEGV. Kernel logs show 2 hosts freshly booted (node replacement during rollout).
- **14:00–14:35 UTC**: 150 total SIGSEGV log lines across 10 hosts, 45 unique emergency events. Pods crash-loop.
- **~14:35 UTC**: Crashes stop. Cause of resolution unconfirmed (possible rollback or deployment fix).

## Crash Location

```
main.main() → ddapp.Bootstrap() → tracer.Start() → appsec.Start()
  → NewWAFManagerWithStaticRules() → RestoreDefaultConfig()
    → AddDefaultRecommendedRuleset() → DefaultRuleset()
      → Lib.ObjectFromJSON(decompressedRuleset)   ← SIGSEGV addr=0x0
```

The crash occurs in the native libddwaf C library when parsing the 193KB embedded WAF ruleset at startup. The `emplace()` function in `json_utils.cpp` dereferences a NULL pointer. This is an upstream library bug, not a service code issue.

## Affected Versions

- go-libddwaf: v4.8.0 (libddwaf v1.30.0)
- dd-trace-go: v2.6.0
- purego: v0.9.1

## Kubernetes Context

- **Deployment**: `cloud-streams-processor-oci-metrics-customer-64-127`
- **Namespace**: `oci-integrations`
- **Cluster**: `whiscash`

## Environment at Crash Time (from Datadog)

- **Node memory**: 70–97% available on all 10 hosts — no memory pressure
- **Pod memory**: ~110 MB
- **Kernel events**: Zero OOM kills, zero MemoryPressure events, zero cgroup OOM for this service
- **Goroutines at crash**: 103

The exact trigger for the NULL pointer inside the C library remains unconfirmed. The code is vulnerable to malloc failure (verified in source), but production telemetry shows no evidence of memory exhaustion.

## Upstream Fix

The bug is in libddwaf's `emplace()` function which lacks a NULL check. A one-line fix has been identified. The fix is already present on libddwaf master (v2.0.0-alpha0) — verified: 0 SIGSEGV vs 27 on v1.30.0 with the same failmalloc sweep. A backport to v1.x requires a single NULL check. See `report-libddwaf.md`.
