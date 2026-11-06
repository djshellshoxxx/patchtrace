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

## Remaining gates at initial staging

This is an integration candidate, not mainline or release qualification. No new complete 20,000-test suite is claimed from this task; existing hosted results and their current head identities are recorded in the plan. Current-head hosted Linux/Windows/Qt/package evidence, scanner disposition, and applicable normal review requirements remain gates before promotion.

#205 has real Linux/Windows failures. #218 Linux has a successful complete run, while its Windows result was still in progress. #235 has queued work and an open scanner finding. Neither skipped nor queued work is treated as successful.

The source/revision guard is an admission check within an open workspace connection, not a write lock or atomic transaction spanning acquisition. Existing native ownership, quarantine, and evidence are unchanged. No paid API workflow is enabled.

## Reviewed continuation — 2026-11-06 UTC

The useful workspace proposal from #183 was added with six documentation-only file changes. Seven original Git blobs/SHA-256 receipts and six reference-only wiki dispositions are preserved in the [workspace reconciliation](../research/workspace-docs-reconciliation-20261106.md). Independent review passed, and the combined candidate's documentation selection passed 294 tests in 2.24 s before later source repairs.

The narrow frozen-#205 prerequisite is published as [#245](https://github.com/djshellshoxxx/patchtrace/pull/245), head `4465a0492367d08f324e80b290a594791921691c`, tree `6db3490e96da2a8f0a200d834f8816bc41421f57`. It corrects the cross-API Windows recovery timestamp comparison and the stale crash-test double. The combined affected selection passed 54 tests. This branch was merged once into the isolated #244 candidate. The production/specification/test blobs match #245 exactly; the crash double was already identical in the descendant. Both append-only ledgers retained their complete destination bytes plus each incoming receipt once. The resulting tree `9bebb7cc0fed5d8326f9c9d25781d3576298133f` matches the independent propagation simulation.

The [Qodo source-provenance finding](https://github.com/djshellshoxxx/patchtrace/pull/244#discussion_r4489325824) was reproduced and repaired; the earlier admission disclaimer was not treated as a disposition. [The detailed repair receipt](kb-source-admission-20261106.md) records two real-store tests failing before the correction, two passing afterward and 75 affected checks passing. Independent review of local commit `c93bbe1d85e9069b7443a594a298bcf70dba7da6` found no blocking or nonblocking findings and independently passed both new controls in 1.28 s. The coordinator reviewed the code and preserved the exact five non-ledger blobs during integration; only append-only ledger concatenation was needed.

Combined local source commit `5c46e85c89af60c598dc01bc221892b08375bc82` has tree `3e5276d6643d784e459264d6cb213082b812c8d4`. Git-data publication preserves this exact tree as `a502c9c241d855dba530160e19215d802ebaf90f`, following recovery merge `376d726d3c771d33491f878f001ab6529c58a878`. The coordinator reran the original 14-file selection plus N-way recovery-copy, series-tolerance, series, subprocess crash recovery, spec registry and help-doc tests: **774 passed in 37.31 s, no skips or expected failures**. Whole-tree Ruff and diff hygiene passed; schema generation again produced no drift. Counts overlap all earlier focused runs.

The combined tests used the separately provisioned copied-executable environment with the same pinned dependency files, `PYTHONPATH=src`, `QT_QPA_PLATFORM=offscreen` and `PYTHONDONTWRITEBYTECODE=1`. Ruff used the original provisioned environment, which contains its console binary. The exact source remained clean throughout verification. Documentation/evidence-only updates follow this tested source commit.

The separate complete Linux run is on #245's exact head, not this combined source. Preserve its actual non-green result and source-pinned environment diagnoses: resolved virtual-environment launchers can escape to a base interpreter lacking protobuf/YARA-X, and this runner denies local AF_UNIX socket construction. The corresponding tests also fail on frozen #205. Copied-interpreter controls preserve the original assertions; they do not relabel the original full run as passing.

The frozen application/native owner refs remain unchanged. Current-head hosted checks, Windows qualification, parent scanner dispositions and normal review requirements remain gates for the application candidates. CodeRabbit reports review disabled for the integration base branches; its skipped checks are not successful reviews. The confirmed provenance repair is documented separately from the unresolved/updated review-thread state on GitHub.

## First main promotion completed

At **2026-11-06 06:27:13 UTC**, #204 was merged through GitHub with expected head `1229ca3bba6bc099d040c279ed9ebc8b91ae913e`. Both previously queued Ubuntu smoke jobs succeeded. The original QA run, both OS QA legs, all five Qt gates, Linux packaging, CodeRabbit, SonarCloud and Snyk were successful; release-only jobs were inapplicable/skipped and no unresolved review threads were present. The merge commit is `d02b94bcedb29dae201941f01f2c94d42ebbb297`, with parents `5d504ff5c046bfb758623182b472976003632bba` and `1229ca3bba6bc099d040c279ed9ebc8b91ae913e`. Main and the retained source branch were independently reread through GitHub. This completes the plan's first main step; #205/#218/#235 still require their separate qualification.
