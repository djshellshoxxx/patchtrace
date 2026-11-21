# Generation 36 — CSV source-column review and regression extension

## Source and ownership
- Parent isolated candidate: `codex/patchtrace-csv-fixture-escape-20261120-g35` at `09af21b0419fe06cce6fdd031355e274e6deb5d0`, preserving g34's CSV runtime and g35's corrected 13 fixture cases.
- Parent draft PR #342 remained `5f34fb57267637b986814ddc81dba11550992fff`. It is not modified.
- New isolated candidate: `codex/patchtrace-csv-crosscolumn-review-20261120-g36`. Initial contract commit `8493be958898d591d9ce57a56d700bc0878086d7`; regression-only code commit `c3a60593d3f6d005ce056ce242765a664202a601`.
- Relevant production blob: `src/patchtrace/strings/export.py` at `3b53c8a42460f55ab1c3d9bf77e966946d168527`, unchanged from g34. Previous g35 test blob: `a4d3956400740e0486612fbb67b35675ce406198`. Exact newest blob/tree must be refreshed after evidence commits.

## Review and unique coverage
A follow-up source-level review of the g35 production and regression files confirmed that all eleven CSV row values pass through the same `_cell` guard. The corrected g35 13-case regression verifies only the `display` value (column 4), leaving the separate source-derived `cues`, `functions`, `lineage_groups` and `reasons` serialization routes uncovered by that test. Git comparison and direct source inspection establish this as **new test coverage**, not a second implementation of the existing production fix; no claim of a new production failure is made.

WB3-S6 was updated before tests to require checking the source-derived free-text columns and an unchanged JSON control. The new parametrized repository test runs `document(delta)` -> `render(doc, 'csv')` -> stdlib `csv.reader`; exercises formula-looking values with leading space/tab, LF, BOM and vertical-tab in those four different columns; and asserts ordinary prose, BOM-prefixed prose, literal slash-n and normal lineage remain unchanged. It separately verifies `render(doc, 'json')` retains exactly the original source-derived values. The test does not execute a target or alter analysis.

## Bounded local verification and limitations
- Python 3.13.5 standalone control `/tmp/patchtrace_csv_g36_control.py`, SHA-256 `e9a97885355297f8024109f7bb45d6a26dbd04567a4a6da3c20ce8f1fc69d17c`, replayed the production-equivalent `_cell`/`_csv_row` helpers and both CSV/JSON control cases; **2 of 2 passed**. It is not repository-source pytest, not Microsoft Excel compatibility, and not an independent externally executed review.
- This container still cannot resolve `github.com` for a checkout and has no `ruff` module. Exact new-head `python -m pytest -q tests/test_strings_export.py`, `python -m ruff check src tests tools`, and full offscreen pytest are **not run**. No CI workflow was dispatched to avoid duplicating PR342's active jobs.
- Source-level inspection is independent of the preceding g35 implementation cycle, but an **external/independent post-change reviewer signoff** is not available and remains a gate. Do not treat this note as such a signoff.
- Parent PR342 source-specific hosted native Windows run `44781837860` has five successful scenarios, including raw-cache-hit job `136446262580` reporting `Raw cache hit verified`; live intel run `44781837959` succeeded. Full Linux QA job `136446430886` succeeded with `23900 passed, 52 skipped, 6 xfailed` and Ruff passed on **PR342**, not g35/g36. Windows QA and several Qt jobs remained in progress at inspection. None of these predecessor receipts qualifies g36. The original 5cc raw-cache `java=unverified` failure remains an unresolved distinct event, not erased by subsequent success.

## No-release boundaries and successor
No main merge, source-branch overwrite/rebase, target binary execution, release, deployment, force-push, branch deletion or message was performed. Full raw Winbindex index retention/exact resolver membership, Linux forced-export final-name race, native Qt, Windows trust/catalog/clean machine/manual accessibility, historical semantic review and distinct L1/L2/L3 are outstanding. Original SIGKILL without final result and strict ASM timing failure are retained with no cause inferred.

Next worker:
1. Refresh ref, exact tree and active CI. On supported checkout execute the new `test_csv_formula_guard_covers_aggregated_source_columns` plus `tests/test_strings_export.py`, whole-tree Ruff, then required full offscreen pytest and relevant native/Qt/package checks; retain first failure and source SHA.
2. Obtain truly separate reviewer acceptance of test schema/CSV round-trip, g35 fixture corrections and invariants for benign source-derived text. Check unusual Python source escapes separately from resulting code points.
3. Decide on a narrowly stacked draft only when upstream CI and ownership are terminal. No merge while blockers persist. Resume source evidence and export race work in separate owned tracks.
