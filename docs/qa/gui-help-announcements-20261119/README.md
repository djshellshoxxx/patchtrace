# Selective workspace GUI recovery, 2026-11-19

Source under review: `dc841095307c486ad8397e6e44ccea2c98b4e7d1`, tree
`9793bfb0e7db1a9bf804d00d4724cdd6ebc5e923`, on core candidate
`ac3a98150bd17bbbd973c7e7dcadb7edcf551934`. Root separately verified that core
candidate's tree equals published PR #319 `f6c4b084`; this receipt uses the local
full source pin. Specification and control commit: `48630704`.

## Recovered behavior

| Historical source | Recovered portion | Review boundary |
|---|---|---|
| `4a9e32bb490e4b3c000808554988103b4e50aa61` | Optional `ColumnSpec.tip_id`; registered escaped header tooltip with title/unit fallback | `ColumnSpec`, `headerData`, and `_header_tip` ASTs match the original. Accessible header text and cell tooltip behavior stay intact. |
| `647502ceff0602d2b03f1864136da431a1436511` | Evidence controller supplies its shell announcer through the panel to the matches StateView | Existing StateView handles duplicate suppression and assertive errors. Standalone panel construction still accepts no announcer. |

The source change is three runtime files, 19 inserted and four deleted lines.
No new backend, persistence, schema, provider, or task-lifecycle behavior is
introduced. This receipt records author verification; independent review remains
required before integration.

## Intentionally retained outside this recovery

The same historical header commit also proposed Alt+Up/Down/Backspace table
sorting and a 400-entry empty-query command palette. Alt+Up/Down are reserved
for Previous/Next difference in `gui/shortcuts.py` and the main-window actions;
GUI integration plan 8.3 requires that ownership. Its section 6 specifies a
50-result palette bound, and the historical commit contains no contract change
or performance qualification for 400. These slices remain unintegrated, with
their original source retained in the archive and branch history.

`ui.py`, `gui/shortcuts.py`, `gui/registry.py`, and `gui/qt/palette.py` are
byte-identical to the core candidate. No global key or palette limit changed.

## Observed checks

Shared Python environment: `/workspace/scratch/80dddc5347b2/patchtrace-venv/bin/python`.
Each pytest invocation used `PYTHONPATH=src QT_QPA_PLATFORM=offscreen`.

| Check | Observed result |
|---|---|
| New header-help and actual evidence shell-call controls before runtime changes | **2 failed in 3.55 s**: missing `tip_id` constructor field, and no announcement delivered |
| `tests/test_gui_table.py tests/test_evidence_host.py tests/test_evidence_ui.py tests/test_gui_state_view.py` after runtime changes | **189 passed in 42.36 s**, no skips |
| Ruff over the three changed runtime files and two changed test files | Passed |
| `git diff --check` | Passed |

The evidence control exercises panel failure and no-project state transitions
through the real host shell adapter, observing one assertive error, no repeated
announcement for identical state, and one polite no-project update. It does not
claim that a screen reader spoke them. The header control checks a registered id,
unknown id, empty id, units, and unchanged accessible text.

An initial combined validation command named the nonexistent
`test_gui_state_widgets.py`; it collected no tests and exited 4. Its raw output
is retained, and it is not counted as verification. The corrected four-module
command above ran once. No full suite, live engine, Windows packaging, or native
assistive-technology qualification was performed here.

## Evidence

`evidence.zip` contains original-source patches, the three baseline source files,
the selective source diff, and raw red/green/collection-error pytest logs and
JUnit XML. `manifest.json` pins each member's SHA-256 and size, the archive hash,
and the reviewed runtime file hashes. The archive's historical patches preserve
the excluded keyboard/palette portions without claiming their integration.
