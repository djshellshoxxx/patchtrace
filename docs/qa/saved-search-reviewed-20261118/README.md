# Saved-search independent review and integration — 2026-11-18

The focused candidate starts from published PR #307 `58fc130631f602b6e907bb054d30c21d810551d4`. Its tested source/QA tip is `f021f2d0770be8b5ffca9b56ac290e2ff677ce98`, tree `7570cde1243d3ef464a671949b9a08cb2306e409`. This later append changes evidence/documentation only. Each REST-published commit must have the identical reviewed local tree; source and cherry-pick provenance are retained.

## Scope reviewed

Root reviewed the saved event model, effective query parsing and mode/filter replay, owner-thread storage actions, bounded per-user recent settings, Qt controller lifecycle, actual controls/tooltips, and CLI open/close and storage-only branches. Project-owned saved queries retain the unchanged persisted event contract; recent text is explicitly per-user, limited to twenty sanitized queries and 8 KiB of encoded settings. Listing, saving and deleting do not build or execute an index. Saved runs reparse current stored text and validated matching mode; a missing/deleted row cannot be executed from stale UI data. Project/owner/revision changes invalidate dialog and action snapshots. Actual offscreen controls/results image was inspected.

## Independent finding and repair

The original candidate `e705974b` allowed an older asynchronous index build to auto-submit the newly recalled recent text before Enter. Root's actual TaskRunner/Qt reproducer failed once in 0.92 s; the original test/log/JUnit are retained verbatim in the archive. This violated the specified recent-recall execution boundary.

Author repair `c30c7911` captures the query generation at Build. Completion still clears progress and probes index coverage, but auto-submit requires that same generation. The added event-controlled regression includes ordinary Build auto-submit and explicit Enter after recall as positive controls. Root inspected the fix and reran the unchanged independent reproducer: **1 passed in 0.92 s**. No blocking finding remains in this inspected scope.

## Actual combined checks

With the interpreter/environment in the manifest, root executed the final source on the published #307 base:

```sh
python -m pytest -q tests/test_search_saved_workflow.py tests/test_ui_search_saved.py \
  tests/test_search_saved.py tests/test_search_cli.py tests/test_ui_search_panel.py \
  tests/test_tooltips.py tests/test_gui_host_seam.py tests/test_search_query.py \
  tests/test_search_pilot_buildenv_bugfixes_20261111.py \
  --tb=short --junitxml=affected.xml
python -m ruff check src tests tools
git diff --check
```

**376 passed in 19.18 s**; required Ruff and whitespace checks passed. The suite includes real saved stores, source-pinned CLI subprocesses and reopen journeys with the existing project owner. These are authored/offscreen controls, not native manual, accessibility or whole-project qualification. Overlapping author and reviewer results are not additive.

[Manifest](manifest.json) binds source hashes, verified author archives and all independent/combined [raw receipts](evidence.zip). The original [feature receipt](../saved-search-workflow-20261118.md) and [race repair receipt](../saved-search-build-race-20261118.md) remain unchanged, including failures and original review-pending statements; this checkpoint supersedes only that review status.

## Remaining acceptance

Publish as a focused PR stacked on #307. Complete exact-head full Linux/Windows QA, repeated Qt, applicable native/platform/manual, packaging and security gates before promotion. Main remains subject to the #304 → #307 qualification order. No release, tag, deployment, remote history rewrite, branch deletion or accuracy promotion follows from this checkpoint.
