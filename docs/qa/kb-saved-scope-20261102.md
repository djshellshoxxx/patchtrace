# Saved KB/CVE investigation scope — fresh verification, 2026-11-02

Base: `039c696c93a443d152d4ddc1383179408ff86b75`. Branch: `codex/kb-saved-scope-20261102`.
This is a newly reproduced and implemented repair for the finite-search-scope finding associated
with #118. No unavailable local audit, unpublished commit or historical test result is claimed as
evidence. Verification uses synthetic advisory and PE fixtures, the actual offline service, SQLite
workspace, production local-project port, context attachment and export. The PE inputs are never run.

## Fresh reproduction and repaired contract

On the unchanged base, `KbService.search(KB5099001, months='2099-Jan')` returned only
`CVE-2099-20001` and stored January-only `Coverage`. After both January and February documents were
loaded, `components` also offered `february.sys`; real `import_pair`/attachment and `explain` returned
both `CVE-2099-20001` and `CVE-2099-20002`, while the attached coverage still named only January.

The repaired service resolves and validates the referenced saved coverage before downstream
mutations, preserving that exact object. KB/CVE investigations require one readable, consistent
saved scope; missing/invalid/contradictory coverage, unavailable selected sources or changed
inspected-label availability returns `PT-KBC-SCOPE` and requires an explicit repeat search. Pair-only
local investigations may have no advisory coverage and still create their ordinary local project.

`ReverseIndex.within_scope` bounds the document set before active-revision selection. Explicit
months/files/mixed scopes retain their selectors; cached-corpus scopes retain their recorded
document IDs, including an empty set. An unselected newer revision cannot suppress a selected older
snapshot. Initial explicit searches and downstream product, component, CVE/card, KB/fixed-build,
pair, context/source and edge-digest selection use the bounded view. Direct context construction
also enforces saved scope. Repair prepares its contexts before the existing recovery routine can
record interruption attempts. No model/schema, card-provenance, workflow, UI, network, acquisition
consent, raw-object store or shared status-ledger changes are included.

## Fresh checks

All checks used `/workspace/scratch/142cb233d750/venv/bin/python`, `PYTHONPATH=.:src:tests`,
and `QT_QPA_PLATFORM=offscreen` for pytest, from the intended worktree.

| Check | Actual result |
|---|---|
| Final `tests/test_kbc_saved_scope.py` copied into a clean detached base worktree; original adapter/service/context/index source retained | **43 failed, 1 passed in 2.25s** |
| Same final regression file on repaired source | **44 passed in 1.63s** |
| All `tests/test_kbc_*.py` plus investigation and frozen-journey GUI tests | **1039 passed in 28.68s** |
| `python -m ruff check src tests tools` | **All checks passed** |
| `git diff --check` | **Passed** |

The final regression cases cover finite months/files/mixed/cached scopes, real attached source
snapshots and export, CVE and KB leads, fixed-build pair resolution, later cached imports, unselected
same-month revisions before and after search, empty cached scope, explicit repeat search, direct
context construction, missing/invalid/contradictory coverage and selected source bytes, and repair
preflight. Failure cases compare complete SQLite dumps and require no destination project; the
repair case also compares the existing project database bytes before and after rejection.

Broad focused command:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q tests/test_kbc_*.py tests/test_ui_kb_investigation.py tests/test_ui_kb_frozen_journey.py
```

The integration owner runs the serial full suite and owns publication/CI. This author receipt does
not claim independent review, full-repository testing, native Windows/frozen packaging, live vendor
compatibility, broader GT06 completion, or a per-card provenance redesign. No remote writes occurred.

## Verified content

| File | SHA-256 |
|---|---|
| `src/patchtrace/kbcorrelation/service.py` | `9ee27c2e6777c31122e71891114ad3ff0ab973c131753d362f9601825b1a7fc7` |
| `src/patchtrace/kbcorrelation/context.py` | `a63d4856a64725066526820ca1c9197c23a8bb399a0b0a75a017d08108ce6785` |
| `src/patchtrace/kbcorrelation/index.py` | `b98000755a5fa74579f3b7238bed57f485ba2d6873cef73dc3b7533ca3ac4715` |
| `tests/test_kbc_saved_scope.py` | `baa5b56e0c238f74b91c71706abb9a7161cd616f51f1a53a8a1b6ed13a97f0a9` |
| `docs/specs/kb-cve/31-E-evidence-intent.md` | `f82ebd660eb56c3bded842d6f08c8a705bef6819fa4eeddf1862fe627668894c` |
| `docs/specs/kb-cve/31-F-workflow-ui-persistence.md` | `1fa8c950304a7070a51c6c636e1d9e91ba06a24982061fafff04d3cb240cb4e5` |
