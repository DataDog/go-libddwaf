# Variance Report (30-run characterization)

| Benchmark | Runs | Mean (ns/op) | Std Dev | CV (σ%) | Threshold (max(2%, 3σ%)) |
|---|---|---|---|---|---|
| BenchmarkColdStart | 11 | 169263.1 | 6161.4 | 3.64% | 10.92% |
| BenchmarkContext | 13 | 6008.9 | 349.1 | 5.81% | 17.43% |
| BenchmarkContextCloseOnly | 11 | 1026.3 | 109.9 | 10.71% | 32.13% |
| BenchmarkContextRun | 13 | 1834.9 | 127.0 | 6.92% | 20.77% |
| BenchmarkEncoder/1024 | 13 | 7486.9 | 521.8 | 6.97% | 20.91% |
| BenchmarkEncoder/16384 | 13 | 7645.1 | 1563.5 | 20.45% | 61.35% |
| BenchmarkEncoder/4096 | 13 | 7947.5 | 603.6 | 7.59% | 22.78% |
| BenchmarkEncoder/8192 | 13 | 6992.0 | 829.0 | 11.86% | 35.57% |
| BenchmarkMostUsedFunctions/timer.Exhausted() | 13 | 2.2 | 0.1 | 6.57% | 19.72% |
| BenchmarkMostUsedFunctions/timer.Remaining() | 13 | 2.3 | 0.2 | 7.07% | 21.22% |
| BenchmarkMostUsedFunctions/timer.Spent() | 13 | 1.3 | 0.1 | 6.94% | 20.82% |
| BenchmarkMostUsedFunctions/timer.Start() | 13 | 48.5 | 4.7 | 9.63% | 28.89% |
| BenchmarkNewContextOnly | 11 | 1728.5 | 135.5 | 7.84% | 23.53% |
| BenchmarkNewContextParallel | 11 | 411.6 | 20.7 | 5.03% | 15.08% |
| BenchmarkNow/clock.now() | 13 | 39.1 | 2.5 | 6.28% | 18.84% |
| BenchmarkNow/time.Now() | 13 | 29.9 | 2.2 | 7.45% | 22.34% |
| BenchmarkRun | 13 | 1399.5 | 140.1 | 10.01% | 30.04% |
| BenchmarkSiblingSubcontextParallelism | 13 | 2216.8 | 34.9 | 1.57% | 4.72% |
| BenchmarkSiblingSubcontextSerialized | 13 | 1875.9 | 127.6 | 6.80% | 20.40% |
| BenchmarkSubcontextRun | 13 | 1854.7 | 128.2 | 6.91% | 20.73% |
| BenchmarkSubcontextRunOnly | 11 | 19782.7 | 1273.6 | 6.44% | 19.31% |
| BenchmarkWAF/ContextLifecycle | 13 | 895.4 | 69.6 | 7.78% | 23.33% |
| BenchmarkWAF/DataComplexity/Heavy | 13 | 942943.2 | 93987.5 | 9.97% | 29.90% |
| BenchmarkWAF/DataComplexity/Minimal | 13 | 12159.9 | 1413.4 | 11.62% | 34.87% |
| BenchmarkWAF/DataComplexity/Realistic | 13 | 56528.8 | 4581.8 | 8.11% | 24.32% |
| BenchmarkWAF/Parallel | 13 | 9501.5 | 2302.3 | 24.23% | 72.69% |
| BenchmarkWAF/RequestResponse | 13 | 67498.0 | 5468.3 | 8.10% | 24.30% |
| BenchmarkWAF/Run/RecommendedRuleset/Attack | 13 | 57051.4 | 4770.6 | 8.36% | 25.09% |
| BenchmarkWAF/Run/RecommendedRuleset/NoAttack | 13 | 57504.5 | 4955.4 | 8.62% | 25.85% |
| BenchmarkWAF/Run/SmallRuleset/Attack | 13 | 8655.9 | 1132.9 | 13.09% | 39.27% |
| BenchmarkWAF/Run/SmallRuleset/NoAttack | 13 | 6095.2 | 431.0 | 7.07% | 21.21% |
| BenchmarkWAF/Subcontext | 13 | 25849.1 | 1902.5 | 7.36% | 22.08% |

## Chosen Regression Gate

threshold = max(2%, 3σ) across all benchmarks
Primary benchmark (BenchmarkWAF/Run/RecommendedRuleset/NoAttack) threshold recorded above.
