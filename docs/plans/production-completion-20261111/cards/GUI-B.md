# Slice card GUI-B - GUI framework fixes: palette, table headers, task lanes, panel host (E-D04, E-D05, E-D08, E-D11, E-D12, E-D13, WP-08)

Evidence and designs: `jq '.actionable_now[] | select(.id=="E-T04" or .id=="E-T05" or .id=="E-T06" or .id=="E-T08" or .id=="E-T10" or .id=="E-T11" or .id=="E-T12")' docs/status/inventory/E.json`,
the matching defects in the same file, and `jq '.actionable_now[] | select(.id=="I1-T09")' docs/status/inventory/I1.json`.
The analyst's porting notes (binding): branch origin/claude/ws-p-20261104 (PR #176, 397 commits behind main) must NOT be
merged; cherry-pick by hunk instead. Commit 4a9e32bb "gui: header tooltips from ColumnSpec.tip_id, keyboard header sort,
full empty-query palette list" applies cleanly to main: port its palette hunks and tip_id hunks as they are
(`git -C <worktree> show 4a9e32bb -- <path>`; keep attribution in the commit body: "ported from 4a9e32bb (PR #176)"),
but its keyboard-sort chord (Alt+Up / Alt+Down) is taken by MainWindow window actions (ui.py about lines 1720-1721,
reserved in gui/shortcuts.py:24) and never reaches the table - its own test passes only because it uses a bare table.
Specs: docs/specs/gui-framework.md, docs/specs/program-e/GUI-integration-plan.md (section 6: the key table).

Items, one commit each, red test first, in this order:

1. E-T04 - the command palette shows only 50 of 106 commands for the empty query. Port the palette hunks of 4a9e32bb
   (src/patchtrace/gui/registry.py, gui/qt/palette.py): the empty query lists every command up to a larger bound; typed
   queries still return at most 50. Test tests/test_gui_host_palette.py (from 4a9e32bb).
2. E-T06 - registered column tips cannot be shown on headers: serve them through ColumnSpec.tip_id in
   VirtualTableModel.headerData (gui/table_spec.py, gui/qt/table.py) and attach the registered strings.col.* tips to the
   Strings panel columns (src/patchtrace/strings/table.py or strings/qt_panel.py - only the column declarations). Port
   the tip_id hunks of 4a9e32bb. Tests tests/test_gui_table.py and tests/test_ui_strings_panel.py.
3. E-T05 - sorting is mouse-only on 18 tables. Spec first: add the chord to the key table in
   docs/specs/program-e/GUI-integration-plan.md section 6 and register it in gui/shortcuts.py. Suggested
   Alt+Shift+Down (ascending), Alt+Shift+Up (descending), Alt+Shift+Backspace (default order) - verify they are in neither
   RESERVED nor FRAMEWORK and that no existing QAction in ui.py or any panel uses them
   (`grep -rn "Alt+Shift" src/patchtrace | head`); add a palette command per action (gui/qt/commands.py). Acceptance:
   inside a REAL MainWindow (not a bare table) with a panel table focused, the chord sorts the focused VirtualTable
   ascending, descending and back to the default order, the sort is announced to assistive technology the way the
   framework announces other state changes, and the window's next/previous-difference actions (Alt+Down / Alt+Up) still
   work. Tests tests/test_gui_table.py plus a MainWindow-level test.
4. E-T08 (Lane part) + I1-T09 (WP-08 residual) - src/patchtrace/gui/qt/tasks.py: (a) `_lane_loop` catches Exception only,
   so a lane init raising SystemExit leaves the lane dead and busy; report it as TaskFailure('SystemExit') and leave
   busy() False; (b) `TaskRunner._start` (about lines 320-327) registers the task and then calls thread.start()
   unguarded: a RuntimeError ("can't start new thread") leaves busy(channel) True for ever - on a failed start the
   channel must return to idle and the failure must be reported through the normal error path. Keep the change inside
   those two functions: Qt teardown in this module is delicate (tracker item T15) - do not restructure ownership.
   Tests tests/test_gui_tasks.py; then run `cd <worktree> && QT_QPA_PLATFORM=offscreen PYTHONPATH=<worktree>/src python tools/qt_gate.py --help`
   and, if it can target one file, `--repeat 10` on tests/test_gui_tasks.py; otherwise loop the file 10 times.
5. E-T11 (audit GUI-15) - src/patchtrace/gui/qt/host.py `_construct` / `_retry`: a panel whose factory raised is rebuilt
   on every activation and visibility change. Do not rebuild a failed panel until the user presses Retry; self_check and
   build_all_for_test call _construct directly and must keep reporting the failure. Test: show, hide and show a dock
   whose factory raises - the factory ran once; Retry runs it a second time.
6. E-T10 (host part only) - MainWindowPort.copy_text returns False silently for text over 16 KiB and five callers ignore
   it. A refused copy produces exactly one status message naming the 16 KiB limit and one announcement; callers that
   already report the result (src/patchtrace/rules/qt_panel.py:351, ui_unified.py:1080 - read-only for you) must not
   produce a second message: design the host change so they do not. The "cut the Calls detail on a byte boundary" half
   lives in src/patchtrace/callgraph/panel_qt.py, which another session is editing: list it under "Integrator asks".
7. E-T12 - tests/test_gui_host_seam.py lines about 116-117 hard-code 13 built panel ids, so every new panel edits a
   shared test. Derive the built set from the manifest (importlib.util.find_spec over MANIFEST modules) and keep one
   explicit assertion that 'guide' is the only not-built slot, so a silently missing module still fails. The test must
   still fail when a built panel's module is removed (prove it with a temporary monkeypatch of find_spec in a second
   test).

## Owned files
src/patchtrace/gui/registry.py, gui/table_spec.py, gui/shortcuts.py, gui/qt/palette.py, gui/qt/table.py,
gui/qt/commands.py, gui/qt/tasks.py, gui/qt/host.py, src/patchtrace/strings/table.py or strings/qt_panel.py (column
declarations only), docs/specs/program-e/GUI-integration-plan.md (key table rows), docs/specs/gui-framework.md is NOT
yours (another session edits it: put status-line text under "Integrator asks"), tests/test_gui_host_palette.py,
tests/test_gui_table.py, tests/test_ui_strings_panel.py, tests/test_gui_tasks.py, tests/test_gui_host.py,
tests/test_gui_host_seam.py (item 7 only; do not touch the seam budget constants).
NOT yours: src/patchtrace/ui.py and tooltips.py (slice GUI-A), ui_evidence.py and search/qt_panel.py (slice GUI-C),
callgraph/**, rules/**, ui_unified.py, panel_manifest.py.
If a registered tooltip id is missing for a strings column, do not edit tooltips.py: list the id and text under
"Integrator asks".
