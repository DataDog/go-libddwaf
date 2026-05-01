# Baseline resolution

The original `.bench` baseline files are not byte-identical.

## Canonical file

`v5-dev-verified-baseline.txt` is the canonical v5-dev pre-optimization baseline.
It was copied from `baseline.txt` after auditing provenance and comparison results.

## Original files

- `baseline.txt` — earliest captured v5-dev baseline in this set.
- `batch1.txt` — later capture from the same benchmark batch.
- `batch2.txt` — later capture from a subsequent benchmark run.

## Audit result

- `diff baseline.txt batch1.txt` returned differences.
- `diff baseline.txt batch2.txt` returned differences.
- Checksums differed for all three originals.
