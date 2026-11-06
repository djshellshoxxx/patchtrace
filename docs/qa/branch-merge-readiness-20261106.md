# Branch consolidation qualification receipt — 2026-11-06 UTC

User-facing date: November 5, 2026 (America/Los_Angeles). See the [execution plan](../plans/branch-merge-plan-20261106.md) and [frozen inventory](../plans/consolidation-20261106/branch-inventory.json).

## Source and preservation

Base #235: `ccfe175d44a70947203c75bbd033a9a9e2633f0f`.

Source #242: `b8bda98452b2f742ad55064aa2e1452700658a33`.

Source #243: `c9cea0671442a6051b068acfb69d17aabcf674ae`.

Local history-preserving staging commits: `9ce7d86a60e1a2d1041399806bab48d95b4045f1`, then `eede24d7e1a7ea4a7c37b7e1dfd9790ca00b7f14`. The reviewed combined source tree is `ea48a7e087590fccffadb54e4414bd000f16838b`. GitHub Git-data publication preserved the exact reviewed trees and source parents as `2974a4db29b6baf6150c9c03cdd7e6c59e140722`, then `ff87aee6d995c22ddc7b038633af21d77c6f4aad`. The latter has exactly the reviewed source tree. Planning/evidence-only additions follow this source commit.

Independent review verified that all four #242 blobs and all five #243 blobs match their leaf owners exactly. No other #235 file changed in the combined source tree. In particular, the latest handoff, module index, QA, task register, and `sonar235-package-path-20261105.md` remained intact. Subsequent QA/todo changes from this task only append the consolidation receipt.

The two #243 merge bases are preserved. Git 2.52 ort constructs a virtual base and resolves the true five-file change cleanly; a one-base triple-dot diff can substantially overstate it. No whole-file replacement from a stale branch was used.

## Executed checks

Environment: isolated Python 3.12 environment installed from the repository's declared `.[dev]` requirements. Worktree `PYTHONPATH=src` was set for every test so the editable checkout could not silently supply the wrong source. `QT_QPA_PLATFORM=offscreen` was used.

Root affected integration selection:

```text
test_kb_acquire_lifecycle_20261105.py
test_kbc_acquire_cli.py
test_kbc_service.py
test_kbc_recovery.py
test_kb_desktop_index_refresh_20261105.py
test_kb_winbindex_refresh_20261105.py
test_kb_candidate_journey_20261105.py
test_kb_online_investigation_20261105.py
test_kb_accessibility_20261105.py
test_ui_kb_investigation.py
test_kb_investigation_service.py
test_kb_binary_only_start.py
test_kb_current_project.py
test_kbc_contracts.py
```

**424 passed in 27.17 seconds, no skips or xfails.** Raw task log: `merge-readiness-focused.log` in the task workspace. The tests use authored fixtures and denied socket/DNS operations; no real metadata fetch, downloaded target, or target execution was performed.

Independent review selected the two new regression files and confirmed the intended source import path: **42 passed in 2.73 seconds**. The review found no blocking standards or specification issue. This overlaps the 424 tests and is not additive unique coverage.

`python -m ruff check src tests tools`: passed. `git diff --check`: passed. `PYTHONPATH=src python tools/generate_kbc_schemas.py`: passed with no tracked schema changes.

#204 was independently checked in a separate worktree: main baseline **3 failed / 48 passed / 3 xfailed**; unchanged #204 head **49 passed / 3 xfailed**. Whole-tree Ruff passed. Original workflow fragment bytes are unchanged by the move. The PR was marked ready without a new source commit.

## Remaining gates

This is an integration candidate, not mainline or release qualification. No new complete 20,000-test suite is claimed from this task; existing hosted results and their current head identities are recorded in the plan. Current-head hosted Linux/Windows/Qt/package evidence, scanner disposition, and applicable normal review requirements remain gates before promotion.

#205 has real Linux/Windows failures. #218 Linux has a successful complete run, while its Windows result was still in progress. #235 has queued work and an open scanner finding. Neither skipped nor queued work is treated as successful.

The source/revision guard is an admission check within an open workspace connection, not a write lock or atomic transaction spanning acquisition. Existing native ownership, quarantine, and evidence are unchanged. No paid API workflow is enabled.
