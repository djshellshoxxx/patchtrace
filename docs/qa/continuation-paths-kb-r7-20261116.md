# Path handling, KB CLI parity and R7 recovery — 2026-11-16

Starting integration: `8f95709540783ceaa8f75579840f7dee608eb651`, PR #297.

## Exact-head hosted evidence inspected

Workflow 43849427684: Ubuntu QA and all five Qt repeat legs succeeded. Windows
QA failed with **2 failed, 21,916 passed, 112 skipped, 5 xfailed**. The failures
were the directory-input and file-as-project-ancestor cases in `test_project_cli.py`.
Windows packaging and dependent release jobs did not run. Six other workflow
families (live unified, Tier R, native Windows Ghidriff, BinDiff, rz-diff and
optional wheels) succeeded on the starting head. Those are historical results
for the starting head, not acceptance of this continuation.

## Repairs and completion

- Reject nonregular input before the Windows fingerprint routine attempts an
  open. Retain the fingerprint checks for admitted regular files.
- For an absent project destination, check its nearest existing ancestor.
  Windows can report ENOENT below a regular file where POSIX reports ENOTDIR.
  Refuse without modifying the blocking file or starting project creation.
- Route `kb index sync --help` and `-h` to the actual online parser without
  building service ports. Advertise the route in offline index help without
  importing online transports into the offline module.
- Add `kb products --all [--query TEXT]` over the existing read-only active
  product catalogue. Preserve `kb products INV`; refuse ambiguous combinations
  before service initialization. Retain source verification, truncation and
  provenance; do not create an investigation or infer binary applicability.

Both new path regressions failed on the starting code, then passed after repair.
The two help variants and the catalogue journey also failed before their repair.
Existing cross-platform CLI assertions were retained.

## Historical reconciliation

An ancestry inventory covers all **300** fetched remote branch refs; **123** are
ancestors of the starting integration. See `branch-ancestry-continuation-20261116.json`.
Ancestry and old patch classifications are not a semantic completeness proof.

Reviewed the rules/callgraph changes on `claude/bugfix-rules-cg-20261029` against
current implementations: path visit limits, truncated exports, bounded suffixes,
rule hashing/input limits, reordered matrix cache cells, decision ordering,
sidecar refusal and diff budgets are already present or further hardened.
The accepted-function-name research scoring change on
`fix/remediation-a58defa8-139db0` is also present with stricter validation.
The MSRC mixed-revision branch was inspected against the current release-based
conflict grouping; no wholesale replacement of the current index was made.

Recovered the unique, isolated R7 research slice from PR #282
(`consolidate/research-r7-20261104`), commits `1f4a0784` and `abadcb36`, originally
PR #134. It contains a bounded synthetic dependency slicer, conservative
guard-delta motif, tests, benchmark and provenance/acceptance documents.
No production matching, ranking, extraction, schema or packaging integration
is implied. The recovered documents and their old benchmark remain historical
records. All source branches and PRs remain intact while integration is gated.

## Local verification

Combined affected run: **724 passed in 13.35 seconds**:

```
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q \
  tests/test_r7_patterns.py tests/test_r7_slicing.py \
  tests/test_kbc_cli.py tests/test_kbc_cvrf_fetch.py tests/test_kbc_index.py \
  tests/test_kbc_service.py tests/test_kb_product_start_20261106.py \
  tests/test_kbc_contracts.py tests/test_help_docs.py tests/test_project_cli.py \
  tests/test_ingestion_core10.py tests/test_gui_creation_retry.py \
  tests/test_verified_backup_byte_integrity.py
```

Whole-tree Ruff, dependency consistency and diff whitespace checks passed.
The R7 synthetic benchmark ran for 128, 1,024 and 4,096 operations; this is
feasibility evidence only, not native accuracy.

The required single-process full-suite command was attempted and killed with
exit **137**, before a summary. No full-suite pass is claimed. A supplementary
batched run was started to reduce per-process resource pressure; its results
must be reported separately from a single complete-suite acceptance run.
The affected run uses synthetic fixtures, offline services and offscreen Qt;
it does not qualify native Windows behavior or a downloadable package.

## Remaining gates

Current-head hosted full Linux/Windows QA, Qt repeats, packaging, smoke and
release gates must pass before merging. Original Windows timeout-pair diagnosis,
native accuracy qualification, clean-machine and assistive-technology acceptance
remain open. Other non-ancestor historical branches still need case-by-case
review. This continuation does not establish that all project features are done.
