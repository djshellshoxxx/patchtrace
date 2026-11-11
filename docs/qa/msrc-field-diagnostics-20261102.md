# Native remediation field diagnostics — 2026-11-02

Source commit: `89110d12018c0373e371704934d4ebaf69c9998e`, tree
`1d5a450ab92332c8fdd66212f34275553a74d8bb`. Base: `443fc8e9410ca9eb8f50acf8ce730c6beac5b3eb`;
the parent identity repair is a separate slice. Author: `/root/msrc_recover`.

The exact [CodeRabbit comment 4440384161](https://github.com/djshellshoxxx/patchtrace/pull/153#discussion_r4440384161)
was inspected and freshly reproduced on published `9ae5731`: malformed `ProductID`, invalid present
`Description.Value`, and omitted wrapped `Value` all produced the generic remediation-parent diagnostic
`Description.Value or ProductID has the wrong type`. The existing specification requires a resolvable field
locator or nearest existing parent for missing fields.

The correction diagnoses each present invalid field independently. Product membership errors point to
`/ProductID`; present invalid wrapped values point to `/Description/Value`; missing wrapped values point to
the existing `/Description` with detail `missing Description.Value`. Non-object descriptions point to
`/Description`. If both present fields are invalid, both diagnostics survive. Row rejection, native acceptance,
status/revision rules, Type-2-only missing-description handling and nonfix optional descriptions are unchanged.

Fresh verification in the isolated worktree using the existing shared venv and `PYTHONPATH=.:src:tests`:

- Before source repair, the dedicated 12 cases plus existing review-finding tests: **16 failed, 12 passed in
  1.43 s**. Failures were the intended field-pointer/detail assertions.
- After repair, field diagnostics, native review findings, original provenance, native CVRF and synthetic CVRF
  suites: **228 passed in 5.04 s**.
- Changed source/test Ruff and `git diff --check`: passed.
- Controls resolve every imported edge/status/problem pointer, preserve unrelated valid rows and retain both
  diagnostics through real WorkspaceStore reload with identical raw JSON and SHA-256. No target is executed.

One initial focused command named a nonexistent test file and collected no tests; the corrected command is:

```sh
PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q tests/test_kbc_msrc_field_diagnostics.py tests/test_kbc_msrc_review_findings.py tests/test_kbc_msrc_provenance.py tests/test_kbc_msrc_cvrf.py tests/test_kbc_cvrf.py
```

This is a fresh offline diagnostic repair, not live-vendor, full-suite, performance or native desktop acceptance.
Independent review and integrated CI remain separate. No remote writes, source-authenticity upgrade, schema
change, consent change or release-gate change was made.

Independent source review of89110d1 found no blockers:228focusedchecks and a200-case acceptance/field-preservation differential passed; every emitted ROW_SHAPE pointer resolved. Material identity76ca406 also independently passed87checks and actual raw-source/scope controls. Both review receipts are retained. New exact-head hosted acceptance remains required.
