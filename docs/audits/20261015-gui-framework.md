# GUI framework audit, 2026-10-15

Status: read-only audit (no edits to `src/` or `tests/`). Audited commit: `21a005e` (origin/main, fast-forwarded at the start). Method: `docs/plans/e4-audit-and-qa-plan.md` sections 3 and 4, product invariants from `docs/plans/worker-brief.md` section 2, contracts from `docs/specs/program-e/GUI-integration-plan.md`.

Area: `src/patchtrace/gui/**` (including `gui/qt/**`), the panel seam in `ui.py`, `ui_evidence.py`, `ui_series.py`, `ui_inspection.py`, `secondary/evidence_panel.py`, `tooltips.py` (apply and template helpers only).

Counts: High 0, Medium 8, Low 8.

Evidence labels: "repro" means a scratch script run offscreen with PySide6 6.12.0 (scripts kept outside the repository). "static" means read from source with the cited lines.

## Findings

| id | severity | location | finding | evidence |
|---|---|---|---|---|
| GUI-1 | Medium | `gui/qt/commands.py:40,42` | Palette silently drops actions inside submenus (dedupe keyed on `id()` of a short-lived Python wrapper) | repro: id-keyed walk misses submenu actions in 100/100 trials; object-keyed walk misses 0/100 |
| GUI-2 | Medium | `gui/qt/palette.py:87,160-169`; `ui.py:1551` | With the results list focused, Escape fires the window "Cancel job" action and the palette stays open | repro: list focused, Escape -> cancel fired, palette still visible |
| GUI-3 | Medium | `gui/qt/tasks.py:36,457-463`; `ui.py:964,1086`; `ui_bundle_setup.py:19,82` | Legacy QThread registries outside `LEGACY_MODULES` are not joined at shutdown | static; `legacy_threads()` reads only `_LIVE_THREADS` of four modules |
| GUI-4 | Medium | `tooltips.py:1075`; 65 call sites | Legacy `apply_tooltip` defaults to `accessible='full'`, so every legacy widget speaks the whole tip on focus | repro: Files table description starts "What: Recorded file fields ..."; no call site passes `accessible='what'` |
| GUI-5 | Medium | `ui_inspection.py:165-176,189-190` | Files dock tables have no accessible name | repro: `accessibleName()` is '' for `overview.table` and `overview.pe_table` |
| GUI-6 | Medium | `gui/qt/table.py:236-252`; `gui/table_spec.py:39,50`; `gui/qt/codediff.py:137-141`; `gui/qt/canvas.py:66-67` | Interactive widgets without tooltips; declared `tip_id` and `tip_prefix` are never read | static: grep finds no reader of either field; Copy buttons, table and graph carry names only |
| GUI-7 | Medium | `ui_evidence.py:874,965-966,1077-1090`; `secondary/rzdiff.py:48-53` | Engine probe runs `rz-diff -v` (PATH lookup) automatically on every project change | static; contradicts the GUI plan rule "a probe that executes a program is an explicit action, never automatic" |
| GUI-8 | Medium | `ui.py:2411-2412` | `show_external_pair` truncates to 200,000 characters with no notice and shows raw text without sanitizing | static; the main path (`ui.py:2114`) does add a notice |
| GUI-9 | Low | `gui/qt/codediff.py:190-194`; `ui_series.py:404-407` | Two direct clipboard writes bypass the 16 KiB clipboard cap | static; `MainWindowPort.copy_text` (`host.py:185-189`) enforces it |
| GUI-10 | Low | `gui/qt/tasks.py:38`; `gui/qt/announce.py:18` | Two sanitizer copies omit U+061C, U+200E, U+200F, which `gui/text.py:20` strips | static |
| GUI-11 | Low | `gui/anchors.py` | Spec-required `AnchorRef.from_fabric` is absent | static; `GUI-integration-plan.md` lines 104 and 431 |
| GUI-12 | Low | `gui/qt/host.py:195`; `gui/ports.py:78`; `gui/table_spec.py:39,50`; `tests/test_gui_host_seam.py:52-54` | Dead or stale code: `spotlight` has no caller; `tip_id`/`tip_prefix` unread; baseline comment names a `ui_inspection.py` call that no longer exists | static grep |
| GUI-13 | Low | `gui/qt/tasks.py:195-196,199-203,215,243` | A worker raising `BaseException` leaves its channel busy forever and delivers nothing | repro: results `[]`, `busy('demo')` True after the worker ended |
| GUI-14 | Low | `ui_inspection.py:61-63` | Legacy worker sends the exception message, not only the class, across the thread | static; GUI plan 8.5 rule 3 |
| GUI-15 | Low | `gui/qt/host.py:400-411,419-422,429-437` | A panel whose factory raised is rebuilt on every activation instead of waiting for Retry | static |
| GUI-16 | Low | `gui/qt/state_view.py:90-96` | `set_content` leaves a replaced widget visible (latent: the host calls it once per panel) | static |

## Finding details

### GUI-1 (Medium): palette drops submenu actions

- Location: `src/patchtrace/gui/qt/commands.py:38-48`. `seen` stores `id(action)` (lines 40 and 42). PySide6 returns new Python wrappers from each `menu.actions()` call. A submenu's wrapper is released after `_walk` recurses, CPython reuses its address, and a later distinct action is skipped as already seen.
- Evidence (repro): six menus, each with four actions and a submenu of three actions, built 100 times. The id-keyed walk missed submenu actions in 100 of 100 trials. The same walk keyed on the `QAction` objects missed none in 100 of 100.
- Impact: the real "Project > Recent projects" submenu (`ui.py:1576`) is affected, so its commands are unreachable from the palette. This breaks "every function reachable without a mouse" (GUI plan 8.3). No test calls `action_entries` directly.
- Test sketch: `tests/test_gui_host_palette.py`: build a `QMainWindow` with menu, submenu and three actions, repeat 50 times, assert every `objectName()` appears in `action_entries(win)`.
- Fix: `seen: set[QAction]` holding the objects (QObjects hash by identity), not `id()`.

### GUI-2 (Medium): Escape in the palette list cancels the job

- Location: `palette.py:87` installs the event filter on `self.search` only; the Escape handling at `palette.py:160-169` never sees the list. `ui.py:1551` binds Escape to "Cancel job", enabled while a job runs (`ui.py:2959`).
- Evidence (repro): with `results` focused, `QTest.keyClick(Escape)` fired the window action and the palette stayed visible. With `search` focused the palette closed and nothing fired. Tab from the search box reaches the list.
- Impact: an accidental Escape cancels a running comparison. GUI plan section 6 requires "Escape reserved; the palette owns its own Escape".
- Test sketch: extend the Escape test near `test_gui_host_palette.py:121` to focus `host.palette.results` before the key, and assert the palette is hidden and cancel is not called.
- Fix: install the same filter on `self.results`, or handle `ShortcutOverride` for Escape on every child of the palette.

### GUI-3 (Medium): legacy thread registries are not joined

- Location: `tasks.py:36` lists `ui_engine_setup`, `ui_series`, `ui_bundle_setup`, `ui_inspection`. `legacy_threads()` (`tasks.py:457-463`) reads only `_LIVE_THREADS`. `patchtrace.ui` is not listed and holds `_DISCOVERY_THREADS` (`ui.py:964`), filled with a running `Worker` QThread at `ui.py:1086`. `ui_bundle_setup.py:19,82` holds `_THREADS`, not `_LIVE_THREADS`.
- Evidence: static. `shutdown_live_runners()` cannot see these threads, so the app can exit while they run. The GUI plan (F15) says destroying a running QThread aborts the process.
- Test sketch: add a `ui.Worker` whose task blocks on an `Event` to `ui._DISCOVERY_THREADS`, call `shutdown_live_runners(0.1)`, and assert the thread is reported as stuck.
- Fix: expose `_LIVE_THREADS` in `ui.py` and `ui_bundle_setup.py` (or extend `legacy_threads`) and add `'ui'` to the list.

### GUI-4 (Medium): accessible descriptions are the whole tooltip

- Location: `tooltips.py:1075` defaults `accessible='full'`. The new helper (`gui/tips.py:149-173`) defaults to `'what'`. No legacy call site passes `accessible=` (grep: 0 of 66).
- Evidence (repro): `rows_view` (`ui_inspection.py:175`) gives the Files table the accessible description "What: Recorded file fields for the older and newer artifacts", which is the flattened tip with its prefix. GUI plan F9 measured a median of 234 characters; section 8.2 and 8.7 specify `accessible='what'` (<= 160).
- Test sketch: `tests/test_tooltips.py`: `audit()` (lines 105-118) asserts only that a description exists. Add `assert len(widget.accessibleDescription()) <= 160` and no "What:" prefix there.
- Fix: change the default to `'what'` in `tooltips.py` (frozen shared file: an owner ask), then fix the tests that expect the full text.

### GUI-5 (Medium): Files dock tables are unnamed and unaudited

- Location: `ui_inspection.py:165-176` (`rows_view`), used at `189-190` for `overview.table` and `overview.pe_table`.
- Evidence (repro): `accessibleName()` is '' for both tables; `objectName()` and description are set. `test_files_panel` (`tests/test_tooltips.py:333-336`) does run `audit()`, but `audit()` never asserts an accessible name, so the gap passes.
- Fix: `view.setAccessibleName('Recorded artifact fields')` and `'PE comparison fields'`; add `assert widget.accessibleName()` to `audit()` (E4 checklist item 6).

### GUI-6 (Medium): tooltips missing and declared fields unused

- Location: `gui/qt/table.py:236-252` (`VirtualTable` applies no tip to the table or its headers). `gui/table_spec.py:39` (`ColumnSpec.tip_id`) and `:50` (`TableSpec.tip_prefix`) have no reader. `gui/qt/codediff.py:137-141` (Copy buttons, panes and splitter: names only). `gui/qt/canvas.py:66-67` (`GraphCanvas`: name only).
- Evidence: static. GUI plan 8.4 declares both fields; the E4 gate requires a tooltip on every interactive widget.
- Fix: `apply_tip` in `VirtualTable.__init__` using `tip_prefix`; apply column `tip_id` to header sections; `apply_tip` on the Copy buttons and the canvas; a parametrized test over every framework widget.

### GUI-7 (Medium): engine probe runs automatically on project open

- Location: `ui_evidence.py:874` (`auto_probe=True` by default), `:965-966` (`project_changed` starts the probe), `:1077-1090` (`start_probe`), `secondary/evidence_panel_service.py:199-212`, `secondary/rzdiff.py:48-53` (`runner([path, '-v'], ...)`), `secondary/registry.py:67-70` (PATH lookup through `shutil.which`).
- Evidence: static. The evidence dock is `eager=True`, so `project_changed` reaches it on every project change, and `rz-diff -v` runs without user action. The rule is stated at `GUI-integration-plan.md` section 7 (`requires` row), again in the docstring at `gui/qt/host.py:199-201`, and the tip text says the probe "runs nothing on the binaries".
- Scope note: the probed program is the engine tool, not the target, so this is not the target-execution invariant. Owner decision needed: rate High if PATH execution without consent counts as that invariant.
- Fix: default `auto_probe` to False, or run the probe only from the "Probe engines" action; correct the tip text if probing stays automatic.

### GUI-8 (Medium): external pairs are truncated silently and not sanitized

- Location: `ui.py:2411-2412` (`text[:MAX_VIEW_CHARS]`, then `setPlainText` with no sanitize). The main path at `ui.py:2114` appends "[View truncated at 200,000 characters ...]".
- Evidence: static. A side of 250,000 characters shows 200,000 with no sign of the cut. Code text can carry bidi overrides, which the GUI rule (advisory and code text are untrusted, bound and escaped) covers.
- Test sketch: `show_external_pair('a' * 250_000, 'b', 'x')`; assert the older view ends with a truncation notice and contains no U+202A-U+202E.
- Fix: route through `sanitize_text(text, MAX_VIEW_CHARS, multiline=True)` and append the same notice used at `ui.py:2114`.

### GUI-9 (Low): clipboard cap bypassed

- Location: `codediff.py:190-194` (`copy_side`; its docstring says "capped", but the cap is the 200,000-character pane limit, not 16 KiB). `ui_series.py:404-407` (`copy_selected_chain`, no cap).
- Fix: one shared copy helper that enforces `CLIPBOARD_BYTES`, used by `host.py:185-189`, `codediff` and `ui_series`.

### GUI-10 (Low): sanitizer drift

- Location: `tasks.py:38` and `announce.py:18` each define `_UNSAFE`, which omits U+061C, U+200E and U+200F. `gui/text.py:20` strips all three.
- Effect: a status line or announcement can carry left-to-right and right-to-left marks that the label path removes.
- Fix: use `text.sanitize_text` (or one shared constant) in both places.

### GUI-11 (Low): `AnchorRef.from_fabric` missing

- Location: `gui/anchors.py`. Neither `src/` nor `tests/` defines it. `GUI-integration-plan.md` lines 104 and 431 (FAB-0 amendment) name it as the adapter for the fabric's anchors.
- Fix: add the pure classmethod, or record in the plan where the fabric adapts instead.

### GUI-12 (Low): dead and stale code

- `gui/qt/host.py:195-196` and `gui/ports.py:78`: `spotlight` has no caller ("Reserved for the guide (E-5)"). Delete it or document the reservation.
- `gui/table_spec.py:39,50`: `tip_id` and `tip_prefix` are never read (see GUI-6).
- `tests/test_gui_host_seam.py:52-54`: the baseline comment mentions a `ui_inspection.py` resize call. The only remaining call is `ui.py:569`, which matches the baseline value 1.

### GUI-13 (Low): a `BaseException` in a worker wedges its channel

- Location: `tasks.py:195-196` catches `Exception` only. `_work` (`tasks.py:199-203`) posts nothing when the thread ends, and the task stays in `_running` (`tasks.py:215`), so `busy()` (`tasks.py:243`) stays True.
- Evidence (repro): `fn` raising `SystemExit(3)`: no result or error delivered, `busy('demo')` True after the worker ended.
- Fix: catch `BaseException` in `_execute` and post an error event with `TaskFailure(type(exc).__name__)`. Test with `raise SystemExit`.

### GUI-14 (Low): exception text crosses the thread

- Location: `ui_inspection.py:61-63` emits `f'{type(exc).__name__}: {exc}'`. GUI plan 8.5 rule 3 says only the class crosses.
- Fix: emit the class name, and log the detail.

### GUI-15 (Low): failed factories are rebuilt on every show

- Location: `host.py:400-411` leaves `controller` None on failure. `_activate` (`419-422`) and `_reconcile` (`429-437`, on every visibility change) call `_construct` again, so Retry is not the only path to a rebuild.
- Fix: skip `_construct` while `panel.failure` is set; `_retry` already clears it.

### GUI-16 (Low): replaced content stays visible

- Location: `state_view.py:90-96`. `set_content` calls `removeWidget` without hiding or detaching the old widget.
- Fix: hide the old widget and `setParent(None)` it, with a test that a second `set_content` leaves one visible child.

## What I reviewed

- `gui/qt/host.py` (all): lifecycle and shutdown idempotence, `MainWindowPort` adapters, anchor routing, focus cycle, reset layout, failure states.
- `gui/qt/tasks.py` (all): mailbox, generations, shutdown and join, lanes, legacy registry join, unsafe-character set.
- `gui/qt/announce.py`, `gui/qt/state_view.py`, `gui/qt/labels.py`, `gui/text.py` (all).
- `gui/qt/layout.py`, `gui/qt/docks.py`, `gui/qt/settings.py`, `gui/qt/commands.py`, `gui/qt/palette.py`, `gui/tips.py` (all).
- `gui/anchors.py` (all). `gui/registry.py`: `load_manifest`, `_is_not_built`, limits (lint not read in depth).
- `gui/qt/table.py`: model filter, sort, rebuild, selection restore, copy (`VirtualTable` header setup). `gui/table_spec.py`: fields only.
- `gui/qt/canvas.py`: constructor, `set_graph`, label and elide path. `gui/qt/codediff.py`: pane class, constructor, `copy_side`.
- `ui.py`: seam calls (lines 1524, 2005, 2068, 2770, 2942, 3059, 3071), actions (1551, 1576, 1579), `Worker` and discovery (201-205, 964-1090), `show_external_pair` (2403-2412), truncation (2105-2115), `closeEvent` (3050-3070), inspection shutdown (2750-2760).
- `ui_inspection.py` (all). `ui_series.py`: thread class (60-100), teardown and copy (395-410). `ui_evidence.py`: `shutdown` (1005-1013), `project_changed` (945-970), load and probe submits (1040-1100).
- `secondary/evidence_panel.py` (all). `tooltips.py`: `apply_tooltip` (1075-1090) and the tooltip and template helpers (1036-1072).
- Tests: `tests/test_gui_host_seam.py` (forbidden-API grep and legacy baseline), `tests/test_tooltips.py` (sweep scope), `tests/test_gui_host_palette.py` (Escape test), `tests/test_gui_codediff.py` (clipboard test).
- Greps over the area: forbidden APIs listed in GUI plan 8.9 (only `ui.py:569` `resizeColumnsToContents`, the counted baseline, and `announce.py` `updateAccessibility`, its allowed owner, appear); `apply_tip` and `setAccessibleName` coverage; `fabric`/`from_fabric`; `auto_probe` and `start_probe` call sites.
- Tests run (offscreen, scratch venv with PySide6 6.12.0): `tests/test_gui_*.py`, `tests/test_ui_m3_docks.py`, `tests/test_ui_m4_selections.py`, `tests/test_tooltips.py` gave 524 passed and 2 failed. The two failures, `test_ui_m3_docks.py::test_panel_specs_import_no_qt[series|files]`, come from the scratch environment: the package was not installed and `python -I` ignores `PYTHONPATH`. They are not product defects.

## Not reviewed

- `ui.py` outside the seam (about 2,800 lines): job flow, profile and export dialogs, overview, ranking, inspection rendering. Suspicion only, not a finding: `QMessageBox` texts built from user strings (`ui.py:399`, `853`, `944`, `1206`, `1878`, `2246`) use the default AutoText format, which the GUI plan (8.11) flags as rich-text risk.
- `ui_evidence.py` beyond the lifecycle: run path, engine rows, BinDiff setup, its tables (1100-1328 and most of 880-1040).
- `ui_series.py` beyond the thread and teardown (window layout, tables). `ui_leads.py:765` uses `assertive=True`, outside the area; not checked against the "blocking errors only" rule.
- `tooltips.py` beyond the helpers (the other ~1,000 lines: wording, claims, completeness).
- `gui/qt/theme.py` (only lines 170-176, 250, 283-297), `theme_stylesheet.py`, high-contrast branch, `chips.py`, `shortcuts.py`, `graph_view.py`, `pair_text.py`, `gui/projection.py`, `gui/state.py`, `gui/capabilities.py`, `gui/ports.py`, `gui/cli.py`, `gui/qt/runtime.py`, `gui/qt/metrics.py`, `gui/qt/canvas.py` keyboard and paint code, `gui/qt/codediff.py` alignment and `set_pair`, `gui/qt/table.py` paint and header code.
- Not measured: the 100,000-row performance budgets, the Linux and Windows CI gates, the 20x repeat gate, DPI and high-contrast behaviour, and any screen-reader run (NVDA, Narrator). None of these were run or observed.
