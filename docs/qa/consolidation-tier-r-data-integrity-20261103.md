# Bounded Tier R data-integrity consolidation — 2026-11-03 UTC

## Exact scope and provenance

Base: local published-candidate representation
`2b6a4965cc4e0e1f3822109d8a13ebf236ff9bb0` at
`/tmp/patchtrace-publish-20261102`; published PR #163
`6e82fd70f315b99c6798a42c9061a1424a02933e`, tree
`2e7cd8e258821f50d776ca3b3a4caef594e2a417`.

Implementation was isolated in a local shared clone at
`/tmp/patchtrace-data-integrity-20261103`. The frozen candidate and isolated
dependency/source archive were not edited. Existing orchestration, extraction
isolation, forced-identical native controls and redaction code were outside the
changed paths.

The three shared source fixes and original focused regressions were recovered
read-only from preserved PR #128 at
`04bd023df566f43939296f7df1766e46186e7fff` using exact-commit GitHub file reads.
The local old tree existed but its source/test blob bodies were missing.
The complete earlier read-only disposition is
`docs/qa/consolidation-receipts-lane-20261102.md` in the evidence checkout;
that document remains the broader #128 → #145 → #150 lineage disposition.

- `build.py`: retain each newly observed complete receipt at its exact-byte hash
  under `images/<debug-sha>/builds/`, check existing content, publish exclusively
  from a private staging directory, then update the compatibility `build.json`.
- `factory.py`: bind cached `SideData` to build specification, debug hash,
  recipe digest, source digest and resolved source root.
- `labeler.py`: ambiguous evidence for a declared unchanged control remains
  unchecked; decisive unchanged/cosmetic/change behavior is preserved.
- SPEC-32 has one appended bounded amendment, written before production changes.
  Public schema/wire contracts are unchanged; no schema generation is needed.

## Dependency decision

`persist_build_record` is self-contained in `build.py`, so this bounded fix does
not depend on #150's absent `receipts.py` or either research CLI. It retains
the reviewed local-store guarantee: complete staged bytes and atomic exclusive
hard-link publication. Unsupported or denied hard links fail before advancing
the compatibility view. It does not claim retained-directory anchoring,
hostile same-user path-race protection, power-loss durability, or native Windows
acceptance. A compatibility-view write failure can occur after the complete
immutable receipt has been retained; the operation still raises a failure.

The research CLI publisher, completed matrix/pilot receipt recovery, historical
research archive and their acceptance obligations remain separate. This slice
does not justify closing any of #128, #145 or #150.

## Focused verification

Python: `/tmp/patchtrace-isolated-imports-venv-20261102/bin/python`.
Every command explicitly selected this checkout with:

```sh
PYTHONPATH=/tmp/patchtrace-data-integrity-20261103/src:/tmp/patchtrace-data-integrity-20261103
```

Import verification printed this checkout's exact `build.py`, `factory.py` and
`labeler.py` paths; it did not import those files from the dependency archive.

Original three regression files against the unchanged candidate:
**13 failed, 4 passed**, exit 1. Failures directly reproduced the missing
receipt function, provenance cache conflation, and ambiguous controls incorrectly
marked `ok`.

After porting the three original fixes: **17 passed**, exit 0. Four added
boundary checks exercise debug-hash invalidation, unknown source spans, complete
staged bytes plus a late destination collision, and retained immutable receipts
when compatibility-view publication fails. Final command:

```sh
PYTHONPATH=/tmp/patchtrace-data-integrity-20261103/src:/tmp/patchtrace-data-integrity-20261103 /tmp/patchtrace-isolated-imports-venv-20261102/bin/python -m pytest -q -p no:cacheprovider tests/test_tier_r_build_receipts_r1.py tests/test_tier_r_session_provenance_r1.py tests/test_tier_r_label_promotion_r1.py
```

Result: **21 passed in 0.73s**, exit 0. These use synthetic evidence records
and local temporary files; the analysis seam is constructed in cache tests.
They are not compiler, native comparator, corpus or evaluation acceptance.

Ruff on exactly the three source files and three focused test files:
**All checks passed**, exit 0. `git diff --check`: exit 0.

Source recovery used the exact-commit GitHub reads described above. No broad
suite, compiler, compared target, native engine, corpus acquisition,
real/locked corpus, calibration approval or evaluation run was performed.
Root integration and independent review remain required; full CI and native
Windows filesystem acceptance are not recertified by these Linux checks.
