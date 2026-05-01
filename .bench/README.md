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
