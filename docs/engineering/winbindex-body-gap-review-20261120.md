# Generation 19 — offline Winbindex gap-accounting adversarial review

Source under review: generation-18 PR329 head `e4b7c74ca4846c222a95dff6dad270a3d440a898` (tree `84b3a9f61ebe29cc833e866434e7955fac54e855`). The generation-19 candidate is the separate branch `codex/patchtrace-winbindex-body-gap-20261120-g19`.

## Original behavioral defect

The parser returns `RowsResult(rows, skipped, skipped_bodies, warnings)`. `skipped` counts malformed top-level SHA entries. `skipped_bodies` separately counts unreadable Windows-version objects and KB bodies. Original `wiring.WorkspaceFileIndex.rows_for` set `_skipped[file_name] = parsed.skipped`; `rows()` then returned that number plus only `lineage.index_rows` rejections. Invalid body objects are never emitted as mappings, so conversion cannot count them retroactively. Thus a usable index record containing a valid build and unreadable KB body was presented as having zero lost source units. The existing `exampledrv.sys` synthetic fixture has two malformed top-level entries and one unusable version/KB body, but its assertions claimed only two gaps.

An isolated standard-library algorithm-mirror regression intentionally failed (expected gap 1, actual 0); the corrected mirror produced the expected 1 with one selected pytest pass and one deselection. This is **not actual repository execution**, and no empirical binary-matching accuracy gain is claimed.

## Narrow repair

SPEC-31-D was updated before code. The index adapter now retains `parsed.skipped + parsed.skipped_bodies` for the current read; `rows()` still adds `lineage.index_rows` rejection count separately. Missing-source reset from generation16 remains unchanged. Import receipt retains `skipped` meaning and adds distinct `skipped_bodies`; plain import output appends a conditional unreadable-body disclosure. Tests cover one invalid KB body, combined top-level/version/body losses, raw receipt identity, missing-file counter reset, and plain output. Two existing golden assertions on the original fixture changed **from 2 to 3**, without relaxing a threshold.

## Source equivalence / independent attack surface

GitHub REST compare from PR329 source to candidate implementation `e59de066dc06fad378017344207ab9d8c3bdb865` reports **six commits ahead, zero behind** and five changed files: one spec, the wiring adapter, import CLI, one new test file and the two golden assertions. Direct current-main and earlier PR325 wiring inspections still use only `parsed.skipped`; a default-branch search for `skipped_bodies` shows parser/refresh usage but no workspace gap forwarding. This is a **bounded sampled donor comparison**, not semantic reconciliation of all retained branches.

Coordinator adversarial inspection asked whether the extra counter double-counts downstream conversion errors (no: rejected parser bodies produced no mappings), whether stale counts leak into a deleted record (the preexisting reset runs before lookup), whether a normal index with zero body losses changes plain output (no), and whether receipt status conflates top-level and nested errors (no; separate fields). It did not execute the actual repository test suite. No independent external worker signoff was available; do **not** label this as independently accepted.

An unrelated but material inherited failure appeared during this cycle in PR328's **Windows QA** job `136058869951`: its actual offscreen pytest step passed `23,636 passed, 162 skipped, five xfailed`, but subsequent Ruff failed `I001` on an extra blank line at `tests/test_kbc_winbindex_held_admission_20261120.py:2`. The generation-19 branch removes precisely one blank line in the test module (commit `e2e32e0d8006d430950a00b7c12bfad408114c34`), without altering its assertions. PR328's **native (patchtrace-seeded-store-no-adjacent-pdb)** job `136058869772` failed while downloading the Ghidra 12.0.4 archive: PowerShell reported its HTTPS connection was forcibly closed by the remote host; subsequent native steps did not run. This is an observed network acquisition failure, not proof of target code incompatibility or a successful native gate. No failed CI job was rerun or suppressed.

## Boundaries and next reviewer tasks

The four new actual-repository tests were committed but not run locally: no full checkout, complete declared dependencies, Ruff or supported native tooling exists in this execution environment. The source-specific hosted CI triggered by a new draft PR and a truly independent review must execute them. The strict ASM timing test and release gates were not modified. The fix does **not** store raw entry bytes/index population, capture resolver membership, close regular-file/ancestor substitution, resolve the separate Linux forced-export race, prove Microsoft authenticity, settle Qt advisories, qualify Windows trust/manual, or produce verified L1/L2/L3 accuracy labels.

If source-pinned CI finds failures, retain the exact job log/JUnit and repair only after new contract/test assessment. No merge, release, deployment, force push or predecessor ref update is justified.
