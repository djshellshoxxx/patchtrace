# Slice card GUI-A - main-window fixes inside the ui.py seam budget (E-D01 high, E-D02, E-D03, E-D09, E-D07)

Evidence and designs: `jq '.actionable_now[] | select(.id=="E-T01" or .id=="E-T02" or .id=="E-T09" or .id=="E-T08" or .id=="E-T07")' docs/status/inventory/E.json`
and the matching defects `jq '.features[].defects[]? | select(.id|test("E-D0[12379]"))' docs/status/inventory/E.json`. Specs: docs/specs/ui.md,
docs/specs/gui-framework.md, docs/specs/accessibility-baseline.md (SPEC-45; rules R-N3 names are user-visible text, R-N4
status labels keep an empty name).

## The hard constraint
src/patchtrace/ui.py is a frozen shared file with a line budget: 3065 lines today, ceiling 3077
(tests/test_gui_host_seam.py::test_ui_seam_budget). You are granted ui.py for this slice, and the FIVE items together may
add at most 12 lines net. Put logic in helper modules (src/patchtrace/gui/text.py or hostile_text.py for text, a new
src/patchtrace/ui_names.py for names, gui/qt helpers for timers) and keep ui.py changes to call sites. Run the seam budget
test after every item. Never raise the ceiling.

Items, one commit each, red test first, in this order:

1. E-T01 (E-D01, high) - the legacy code panes always tint changed rows with the DARK theme tokens (ui.py about lines
   2131 and 2634: DARK.hunk_replace / DARK.hunk_other) and never re-highlight on a theme change, so in the System theme on
   a light palette - and in a light OS high-contrast theme, which is applied automatically - changed lines render
   dark-on-dark (measured contrast 1.77:1). Use the ACTIVE theme tokens (host.tokens.hunk_*) and re-apply the highlight
   when ThemeController.theme_changed fires. Acceptance: with variant 'system' on a light palette every 'diff' extra
   selection uses the active tokens and contrast_ratio(text, background) >= 4.5; dark stays exactly #263a43 / #33392b;
   test tests/test_ui_m4_selections.py::test_changed_rows_follow_the_active_theme_tokens. Net ui.py growth <= +4.
2. E-T02 (E-D02) - untrusted function names and code reach the navigator and the legacy code panes with U+202E, U+2066
   and control characters intact (imported JSON or symbol names). Sanitise AT DISPLAY with the shared rule
   (hostile_text.is_hostile): replace per character, never add or remove line breaks, so row alignment, hunk indexes and
   jump_evidence line numbers do not move; the stored text and "copy provenance" keep the original bytes.
   Test tests/test_ui_untrusted_text.py (new).
3. E-T09 (E-D03) - the navigator search rebuilds the whole list on every key press (0.23-0.30 s per keystroke at 30,000
   synthetic matches, on the GUI thread). Debounce with a single-shot timer so a burst rebuilds once; the final list must
   equal the undebounced result. Existing tests that set the search text and read the list synchronously must keep
   passing: find them (`grep -rn "search.setText\|search_box\|\.search\." tests/test_ui*.py | head -30`) and decide between
   a flush hook used by tests and waiting in the tests - prefer a deterministic flush method over sleeps; do not weaken
   assertions. Test tests/test_ui_responsiveness.py::test_typing_rebuilds_the_navigator_once (five key presses within
   100 ms -> one filter_matches call).
4. E-T08, ui.Worker part (E-D09) - a task raising SystemExit (a non-Exception BaseException) inside the worker QThread
   leaves the job running for ever. Report it as a failure (worker thread only; never swallow KeyboardInterrupt on the
   GUI thread). Test: start_job with a task raising SystemExit -> window.worker becomes None and show_error is called
   once (the test must fail on the base by timeout: use a short qtbot timeout so the red run is quick). The Lane part
   of E-T08 (gui/qt/tasks.py) belongs to slice GUI-B - do not edit tasks.py.
5. E-T07 (E-D07) - 44 interactive controls have neither an accessible name nor a label buddy. Add one names table in a
   new module src/patchtrace/ui_names.py (id -> name) applied by tooltips.apply_tooltip when a control has no name (you
   are granted tooltips.py and tests/test_tooltips.py for exactly this); ui.py may change by at most 2 lines (the two
   unnamed QToolButtons). Leave export.* and Files-dock controls alone (another session's lane: ui_export_v2.py,
   ui_inspection.py). Status labels keep an empty name (R-N4). Acceptance: the introspection audit in
   tests/test_tooltips.py requires accessibleName() or button text for every interactive control in MainWindow,
   NewProjectDialog, AcquisitionDialog, SetupDialog, ContextDialog and CorrectMatchDialog, and the count of controls with
   neither name nor buddy is 0 outside the excluded lane widgets (headers excluded). Names are user-visible text: short,
   specific, no "button" suffix, consistent with the visible labels and the tooltip registry; the banned-word sweep in
   the tooltip tests must stay clean.

## Verification for a Qt slice
Run each new test 10 times in a row and the touched existing files once:
tests/test_ui_m4_selections.py tests/test_ui_audit_p2.py tests/test_tooltips.py tests/test_gui_host_seam.py and the
tests/test_ui*.py files that exercise the navigator. Use `-n 2` at most (Qt tests are timing sensitive and the machine
is shared). If a pre-existing test is flaky on the untouched base as well, prove it on the base and report it; do not
"fix" it by weakening.

## Owned files
src/patchtrace/ui.py (within the 12-line budget), src/patchtrace/tooltips.py and tests/test_tooltips.py (item 5 only),
src/patchtrace/ui_names.py (new), a helper under src/patchtrace/gui/ if needed (new file only),
src/patchtrace/hostile_text.py (add-only helper; another slice is also adding a helper there - keep yours separate and
small), tests/test_ui_m4_selections.py, tests/test_ui_untrusted_text.py (new), tests/test_ui_responsiveness.py (new),
tests/test_ui_backend_progress.py, docs/specs/accessibility-baseline.md is NOT yours (another session edits it): put the
one-line status amendments for SPEC-45 under "Integrator asks".
NOT yours: src/patchtrace/gui/qt/** existing files (slice GUI-B), ui_export_v2.py, ui_inspection.py, ui_evidence.py
(slice GUI-C), ui_unified.py, panel_manifest.py, tests/test_gui_host_seam.py (read-only: the budget test).
