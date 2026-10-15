# GUI and OPS fixes, 2026-10-15

Status: fixes for `20261015-gui-framework.md` and OPS-1/OPS-2 of `20261015-tools-workflows.md`. Base `64bebe5`. Verification: ruff clean on `src tests tools`; GUI, UI and evidence test files 1,481 passed; `tools/qt_gate.py --repeat 5` over the 15 touched Qt test files 2,105 passed, no abort. Not run: Windows, the 20x Linux gate, the new CI jobs themselves.

| id | commit | test | status |
|---|---|---|---|
| GUI-1 | 2cb6ac1 | `test_gui_host_palette.py::test_submenu_actions_all_reach_the_palette` | fixed |
| GUI-2 | 7f2bb67 | `test_gui_host_palette.py::test_escape_in_the_result_list_closes_the_palette_without_cancelling_the_job` | fixed |
| GUI-3 | bf62543 | `test_gui_tasks.py::test_unlisted_legacy_registries_are_joined_at_shutdown` (`LEGACY_REGISTRIES` replaces `LEGACY_MODULES`; `tests/qt_support.py` joins them too) | fixed |
| GUI-4 | 5ee58fc | `test_tooltips.py::audit` (description <= 160, no "What:" prefix), `test_gui_tips.py` | fixed (`apply_tooltip` default is now `'what'`) |
| GUI-5 | efa96dc | `test_tooltips.py::test_files_panel` | fixed; other unnamed views (`findings.list`, `acquire.table`, `correct.older_list`) remain, see Deferred |
| GUI-6 | c885cdc | `test_gui_framework_tips.py` | fixed with new tips `gui.table`, `gui.code_copy`, `gui.code_pane`, `gui.graph`; column headers already had tooltips |
| GUI-7 | 54931cc | `test_evidence_host.py::test_a_project_change_does_not_probe_engines_until_asked` | fixed (`auto_probe` defaults to False; the Probe button is the action) |
| GUI-8 | 4346bc1 | `test_gui_host_seam.py::test_show_external_pair_sanitises_and_announces_truncation` | fixed (`codediff.view_text`) |
| GUI-10 | c07c2bf | `test_gui_tasks.py`, `test_gui_announce.py` bidi parametrized tests | fixed |
| GUI-12 | c885cdc | existing table tests | partly: unread `tip_id`/`tip_prefix` removed, spec table row updated; stale comment was already accurate |
| GUI-13 | 29c8a46 | `test_gui_tasks.py::test_a_worker_raising_a_base_exception_...` | fixed (`TaskRunner` worker path; the lane init path still catches `Exception`) |
| GUI-14 | 1f160d7 | `test_gui_host_seam.py::test_the_inspection_worker_sends_only_the_exception_class` | fixed; detail goes to the log |
| GUI-16 | 5794f94 | `test_gui_state_view.py::test_replacing_the_content_removes_the_old_one_from_the_layout` | fixed |
| OPS-1 | e0cbb77 | `test_workflows.py::test_qa_workflow_runs_the_qt_gate_at_20x_on_linux_and_5x_on_windows` | wired as job `qt-gate` (ubuntu 20x, windows 5x); not added to `needs` of `release`, so it reports but does not block a release |
| OPS-2 | e0cbb77 | `test_workflows.py::test_qa_workflow_reports_each_matrix_leg_to_the_release_notes` | fixed: each leg uploads `qa-leg-result.txt` (`job.status`); the release step reads it, falling back to the aggregate |

Note on OPS-2: `release` still has no `always()`, so it only runs when both legs passed; the per-leg values matter once OPS-6 is fixed.

## Deferred

- GUI-9 (clipboard cap): enforcing 16 KiB on `copy_side` would refuse most real code panes (up to 200,000 characters), a behavior decision.
- GUI-11 (`AnchorRef.from_fabric`): new API outside this slice.
- GUI-12 remainder: `spotlight` is reserved for E-5; kept.
- GUI-15 (rebuild of a failed panel on every activation): needs a Retry-gated host state machine, a behavior change.
- Other unnamed views in the legacy dialogs (see GUI-5); the audit helper does not yet require names for all views.
- OPS-3 to OPS-20: not in this slice.
