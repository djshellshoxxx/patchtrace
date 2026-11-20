# Saved-search workflow recovery — 2026-11-19

## Disposition and source

**Unique missing workflow recovered locally; independent review and aggregate
qualification remain required. No release or remote mutation was performed.**

The inspected base was `c9fd07798fa1cead691776512eb619eb464b768d`, on top of the
draft #322 engineering baseline. That base already had the project-owned,
append-only saved-query store, but did not expose Save/List/Run/Delete through
the CLI or Search panel. It also lost non-default matching modes on the read
DTO and rejected valid saves in five matching modes.

The recovered slice comes from [PR #310](https://github.com/djshellshoxxx/patchtrace/pull/310),
head `26558cd0723aa5fa6d883f2935ad3c43cef94a86`. The six search source files, two
new regression files, and WB1 specification are byte-identical in the compared
[PR #319](https://github.com/djshellshoxxx/patchtrace/pull/319) head,
`8d130aefe1be6e737cff1d90d2a5b1658d60a3a6`. Attribution within that history:

- `20a61fc747a452fb8a21ab34d1a146daa620e9a0`: saved/recent workflow specification.
- `1de7d8df40661eaf61197310d5d123c3b4159edf`: owner-bound GUI/CLI workflow.
- `90d032041de2cee5046cb1ea5f0ad458bcb5e9b2`: in-flight build generation guard.

Only this search slice was applied. No broader PR, Profiles UI, generic settings,
WinPairs, PE/cache, strings-export, or remote-provider implementation was copied.
The WB1 amendment was applied and the modules index updated before source edits.

## Delivered behavior and boundaries

The Search panel now offers project-owned Save, selection, Run saved, and Delete
saved. Saving captures the validated matching mode and effective filters, using
the existing project service and enrichment store. Listing and selection do not
execute queries. Saved actions recheck current project, revision, service, and
epoch ownership; a stale name dialog cannot write to another project, and a
deleted selection cannot run. Delete appends the existing tombstone.

The CLI exposes the same operations:

```text
patchtrace search PROJECT --saved-list --json
patchtrace search PROJECT --save NAME --query TEXT --mode exact --side older --json
patchtrace search PROJECT --saved-run ID --json
patchtrace search PROJECT --saved-delete ID --json
```

List/save/delete use one open/close path and do not instantiate a search service
or build an index. Saved run returns the existing search result envelope and
uses normal result/index options. Invalid combinations are rejected before a
project is opened; saved-run filters cannot silently override stored intent.

`search/saved_actions.py` contains shared, headless query preparation and store
access. `search/qt_saved.py` contains desktop controls and a settings adapter.
Backend persistence stays outside Qt. Canonical query text is reparsed with its
validated mode; persisted clauses and terms never become executable plans.
`SavedQuery` adds a read-only DTO mode, defaulting to `auto`. The already-stored
`QueryPlan.mode` and `search-saved/1` schema are unchanged, so no persisted
contract or generated schema is changed.

Recent history is separately labelled per-user query text. It stores at most
20 entries, each within the existing 256-character query limit, and at most
8,192 UTF-8 bytes of serialized recent JSON. Whole oldest entries are removed
to meet the byte bound. Recall fills controls in automatic mode without
executing; Enter is explicit. A previously started index build cannot submit a
recalled query from a different generation. Settings failure does not prevent
search, and a failed clear does not claim history was deleted. Actual controls,
including the name dialog, have registered tooltips and accessible names.

## Reproduction and qualification

Tests were installed on the unchanged base before implementation. The red run
contains **20 failures and 8 passes** across the two new files. These are not
20 independent product defects: five parameter cases show existing save-mode
validation failing, CLI and actual Qt-controller cases expose unavailable
workflows, and helper/DTO failures document the missing API surface. The source
and test hashes in the evidence manifest pin the verified working tree.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Unchanged base plus the two regression files | 20 failed, 8 passed; exit 1; 5.75 s | `baseline.log`, `baseline.xml` |
| First affected-suite command | Exit 4: nonexistent `tests/test_ui_search.py`; no tests ran | `recovered.log`, `recovered.xml` |
| Corrected affected suite | 961 passed; exit 0; 47.08 s | `affected.log`, `affected.xml` |
| `python -m ruff check src tests tools` | All checks passed; exit 0 | `ruff.log` |
| `git diff --check` | No whitespace errors; exit 0 | `diff-check.log` |

The incorrect test-selection attempt is retained as an execution error, not
counted as product qualification. The corrected selection was:

```sh
QT_QPA_PLATFORM=offscreen /workspace/scratch/4c8dc848d760/venv/bin/python -m pytest -q \
  tests/test_search_*.py tests/test_ui_search_panel.py tests/test_ui_search_saved.py \
  tests/test_gui_settings.py tests/test_tooltips.py tests/test_strings_search_rows.py
```

These checks cover six matching-mode round trips, canonical filter behavior,
legacy/corrupt rows, reparsing tampered stored terms, real project persistence,
single-owner/no-index storage actions, stale dialog/selection refusal, bounded
settings and settings-error controls, and a delayed-build recall race with a
normal Build positive control. The headless subprocess uses current source and
real search results and verifies no Qt imports. The default MainWindow journey
uses a real sample project and normal search backend, saves without an extra
project open or index writes, explicitly builds and runs, and reopens the saved
record. Smaller GUI race tests inject query/build functions to control ordering;
they are not evidence of an external backend or native Windows integration.

Raw logs, JUnit XML, exact commands, source/test hashes, and outcomes are retained
in [the evidence archive](evidence/saved-search-recovery-20261119.zip). The
[manifest](evidence/saved-search-recovery-20261119-manifest.json) records archive
and member SHA-256 values. Original red evidence was not overwritten.

This worker did not run the repository-wide pytest gate, native Windows/manual
accessibility acceptance, packaging, or release gates. Those remain separate
from the affected Linux/offscreen suite and require qualification on the final
combined commit. No target binaries were executed and no network operation was
added or exercised by this slice.
