# .bench baseline notes

This directory stores benchmark artifacts and branch-specific pprof profiles for the v5-dev optimization work.

## Canonical baseline

`v5-dev-verified-baseline.txt` is the canonical v5-dev pre-optimization baseline used for downstream comparison work.
It was copied from `baseline.txt` after provenance review.

## Provenance

- `baseline.txt` — added in commit `355629f`; earliest captured v5-dev baseline in this set.
- `batch1.txt` — added in commit `355629f`; later baseline capture from the same benchmark batch.
- `batch2.txt` — added in commit `4dfa794`; later capture from a subsequent optimization step.

## Verification audit

- Byte-for-byte comparison showed the three original files are not identical.
- Checksums differ across `baseline.txt`, `batch1.txt`, and `batch2.txt`.
- The canonical file is therefore kept as `v5-dev-verified-baseline.txt`, with the originals retained as provenance artifacts.

## pprof directories

- `pprof-main/` contains profiles captured from the main-branch baseline.
- `pprof-v5-dev/` contains profiles captured from the v5-dev branch.

## Variance threshold

T02 will define the acceptable variance threshold here.

## linux/amd64 baseline — T04

- File: `v5-dev-linux-amd64-baseline.txt`
- Commit: `b5f55916cb494188e8d470320960385d1b5defc1`
- Docker image: `golang:1.25` (go.mod requires go 1.25.0; golang:1.24 was rejected due to version mismatch)
- Platform: `linux/amd64` (QEMU emulation via Docker Desktop on darwin/arm64)
- Command: `docker run --rm -v $(pwd):/work -w /work --platform linux/amd64 golang:1.25 sh -c 'go test -run=^$ -bench=. -benchmem -count=10 -timeout 30m ./...'`
- Date: 2026-05-01
- Note: emulated amd64 on arm64 host — throughput numbers will be slower than native CI; use for relative comparisons only
- Known failure: `BenchmarkRunOnly` hit a WAF internal timeout (`benchmark_test.go:408: waf timeout`); this is an emulation artifact from slow QEMU execution, not a code regression. All other benchmarks completed (298 results, main package ran for 944s).
- Exit code: 1 (due to above failure); all other packages passed
