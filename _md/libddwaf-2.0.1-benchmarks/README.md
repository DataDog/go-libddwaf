# libddwaf v2.0.0 → v2.0.1 upgrade — benchmark impact

Performance comparison of the embedded libddwaf native library before and after
running `./_tools/libddwaf-updater/update.sh` (v2.0.0 → v2.0.1). Only the native
library changed between the two runs; the Go code (including the benchmark
harness) is identical on both sides.

## TL;DR

libddwaf **2.0.1 is faster than 2.0.0** on every path that moved, with **no change
in allocations**:

- **geomean: −5.78%** wall time (`sec/op`)
- Hottest wins: `RunOnly` −16.6%, `WAF/Parallel` −16.6%, `WAF/DataComplexity/Realistic` −14.1%, `SubcontextRunOnly` −13.2%, `WAF/Run/RecommendedRuleset/Attack` −12.1%
- `B/op` geomean −0.03% and `allocs/op` geomean +0.00% → **memory profile unchanged** (the speedup is inside the native library, as expected for a patch bump)
- No benchmark regressed; small micro-benchmarks that didn't move report `~` (no statistically significant change)

## Environment

| | |
| --- | --- |
| Machine | Apple M4 Max |
| GOOS/GOARCH | darwin/arm64 |
| GOMAXPROCS | 16 (the `-16` suffix on each benchmark) |
| Go | go1.26.4 |
| libddwaf (before) | 2.0.0 |
| libddwaf (after) | 2.0.1 |

> Numbers are from a developer laptop, so absolute values carry the usual
> laptop-benchmark caveats (thermal/scheduler noise between the two process
> runs). The `-count=10` samples + benchstat p-values are what make the deltas
> trustworthy; treat single-digit-percent moves marked `~` as noise.

## Methodology

Both runs used the identical command, differing only in the embedded library version:

```bash
go test -run='^$' \
  -bench='^(BenchmarkWAF|BenchmarkNewContextClose|BenchmarkRunOnly|BenchmarkSubcontextRunOnly|BenchmarkColdStart|BenchmarkNewContextParallel|BenchmarkSiblingSubcontextParallelism|BenchmarkSiblingSubcontextSerialized|BenchmarkContextRun|BenchmarkSubcontextRun)$' \
  -benchmem -benchtime=1s -count=10 -timeout=20m .
```

- **Scope: only benchmarks that exercise the native libddwaf library.** `BenchmarkEncoder`
  is excluded because it measures the pure-Go WAF-object encoder (no native call), and
  the `timer/` sub-package benchmarks are excluded for the same reason.
- **`-count=10`** so that [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat)
  can compute per-benchmark deltas with p-values.
- Comparison generated with `benchstat old=libddwaf-2.0.0.txt new=libddwaf-2.0.1.txt`.

### Benchmark harness change

`BenchmarkNewContextOnly` and `BenchmarkContextCloseOnly` were fused into a single
`BenchmarkNewContextClose`. The two originals isolated each half of the context
lifecycle with per-iteration `b.StopTimer()`/`b.StartTimer()`; those timer toggles
issue syscalls whose wall-clock cost dwarfed the ~1.5 µs being measured (~34× the
measured time), which made a `-count=10` run at the default 1 s benchtime take
minutes per benchmark and effectively never converge. Measuring the fused
`NewContext`+`Close` lifecycle with `b.Loop()` removes the timer toggling and runs
in ~1 s per sample, so the whole libddwaf benchmark set now completes in ~4.5 min.

## Results

`sec/op` (lower is better):

```
                                       │     old      │                 new                 │
                                       │    sec/op    │   sec/op     vs base                │
WAF/RequestResponse-16                    65.06µ ± 1%   59.92µ ± 1%   -7.91% (p=0.000 n=10)
WAF/Run/SmallRuleset/NoAttack-16          5.548µ ± 1%   5.605µ ± 2%        ~ (p=0.123 n=10)
WAF/Run/SmallRuleset/Attack-16            8.208µ ± 1%   8.098µ ± 1%   -1.34% (p=0.001 n=10)
WAF/Run/RecommendedRuleset/NoAttack-16    55.48µ ± 1%   49.41µ ± 2%  -10.93% (p=0.000 n=10)
WAF/Run/RecommendedRuleset/Attack-16      56.50µ ± 1%   49.67µ ± 1%  -12.09% (p=0.000 n=10)
WAF/ContextLifecycle-16                   847.4n ± 1%   849.6n ± 1%        ~ (p=0.280 n=10)
WAF/DataComplexity/Minimal-16             11.72µ ± 1%   11.47µ ± 0%   -2.14% (p=0.000 n=10)
WAF/DataComplexity/Realistic-16           55.73µ ± 1%   47.85µ ± 0%  -14.14% (p=0.000 n=10)
WAF/DataComplexity/Heavy-16               903.9µ ± 0%   877.1µ ± 1%   -2.97% (p=0.000 n=10)
WAF/Parallel-16                          10.446µ ± 6%   8.716µ ± 8%  -16.55% (p=0.000 n=10)
WAF/Subcontext-16                         24.77µ ± 1%   22.79µ ± 3%   -8.01% (p=0.000 n=10)
NewContextClose-16                        863.9n ± 2%   854.6n ± 3%        ~ (p=0.085 n=10)
RunOnly-16                                49.22µ ± 1%   41.06µ ± 3%  -16.57% (p=0.000 n=10)
SubcontextRunOnly-16                      19.95µ ± 5%   17.32µ ± 2%  -13.17% (p=0.000 n=10)
ColdStart-16                              212.9µ ± 2%   202.9µ ± 3%   -4.68% (p=0.000 n=10)
NewContextParallel-16                     414.4n ± 4%   401.9n ± 5%        ~ (p=0.105 n=10)
SiblingSubcontextParallelism-16           2.503µ ± 1%   2.478µ ± 0%   -1.02% (p=0.000 n=10)
SiblingSubcontextSerialized-16            2.449µ ± 3%   2.458µ ± 2%        ~ (p=0.812 n=10)
ContextRun-16                             2.369µ ± 3%   2.392µ ± 2%        ~ (p=0.210 n=10)
SubcontextRun-16                          2.389µ ± 3%   2.423µ ± 3%        ~ (p=0.063 n=10)
geomean                                   11.88µ        11.19µ        -5.78%
```

`B/op` and `allocs/op` are unchanged (geomean −0.03% and +0.00% respectively; every
benchmark reports `~`). See [`benchstat.txt`](./benchstat.txt) for the full three-metric
comparison.

## Files

| File | Contents |
| --- | --- |
| [`libddwaf-2.0.0.txt`](./libddwaf-2.0.0.txt) | Raw `go test -bench` output, libddwaf 2.0.0 (10 samples/benchmark) |
| [`libddwaf-2.0.1.txt`](./libddwaf-2.0.1.txt) | Raw `go test -bench` output, libddwaf 2.0.1 (10 samples/benchmark) |
| [`benchstat.txt`](./benchstat.txt) | `benchstat` comparison (sec/op, B/op, allocs/op) |

Reproduce the comparison:

```bash
benchstat old=libddwaf-2.0.0.txt new=libddwaf-2.0.1.txt
```
