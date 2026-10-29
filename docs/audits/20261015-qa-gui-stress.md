# QA stress audit: GUI framework (2026-10-15)

Scope: `gui/qt` (panel host, docks, `VirtualTable`, `GraphCanvas`, `CodeDiffView`, `StateView` and `NoticeStrip`,
`TaskRunner`, theme) and the shipped `MainWindow`. Tests live in `tests/stress/test_gui_stress_*.py`.

## Environment and results

- Tree: `origin/main` at `21a005e` (fast-forwarded, no local changes outside `tests/stress/` and this file).
- PySide6 6.12.0, pytest 9.1.1, pytest-qt 4.5.0, ruff from the project venv; `QT_QPA_PLATFORM=offscreen`.
- Run niced: `nice -n 10 python -m pytest tests/stress -q -p no:cacheprovider`.
- Result: **45 passed, 1 xfailed** (`QA-GUI-1`, strict). Three consecutive runs gave the same result.
- Wall time: 22 to 29 s for the whole directory; the slowest file is `test_gui_stress_theme.py` at about 6 s. Each file is
  well under the 30 s limit.
- `ruff check tests/stress`: clean. (`ruff format` is not clean on existing GUI tests either, so it is not gated.)
- No fixed sleeps. Waits are `qtbot.waitUntil` on a condition, gates and events, or `CancelToken.wait`. The only pacing
  is the runner's own `checkpoint()`, which is production code.
- The autouse `join_gui_threads` fixture fails any test that leaves a worker thread alive.

## What each test does

### `test_gui_stress_tasks.py` (TaskRunner, 5 tests)

| Test | What it does | Result |
|---|---|---|
| `test_a_hundred_tasks_cancelled_mid_flight_deliver_nothing` | 100 channels block on a gate, each ignores its token and returns a value. All are cancelled while running, then released. | pass: no result or error delivered |
| `test_cancelling_half_of_a_hundred_keeps_the_other_half_exact` | 100 workers; the even ones are cancelled mid-flight. | pass: exactly the odd results arrive |
| `test_resubmitting_a_channel_a_hundred_times_delivers_only_the_last_result` | 99 superseded submits on one channel, then one live submit. | pass: only the last result |
| `test_a_progress_flood_is_throttled_and_its_final_value_arrives_before_the_result` | 100,000 `report()` calls in a tight loop. | pass: final `done` is 99,999, progress is monotone, at most 200 deliveries |
| `test_cancelling_during_a_flood_delivers_no_progress_and_no_result` | Cancel at report 1,000 of a flood. | pass: no progress or result after cancel |

### `test_gui_stress_docks.py` (dock lifecycle, 3 tests)

| Test | What it does | Result |
|---|---|---|
| `test_every_dock_is_shown_hidden_floated_moved_and_reset_in_a_seeded_order` | Real `MainWindow`, seed 20261015, 3 cycles of show, hide, toggle, float, move (all four areas) and focus on every dock. Also a layout reset and a `saveState`/`restoreState` round trip. | pass: after every step the host's active state, the toggle action and Qt's visibility agree; no controller is built twice; no second top-level `QMainWindow` appears |
| `test_twelve_docks_across_all_areas_and_tab_groups_stay_consistent` | Same exercise on 12 fake docks, all four areas, three tab groups. | pass |
| `test_a_floated_dock_that_is_hidden_and_shown_keeps_one_controller` | 25 rounds of float, re-dock, hide and show on one dock. | pass: one controller identity throughout |

Coverage note: the shipped manifest has 14 entries, but only 5 panels are built in this tree (`evidence`, `files`,
`leads`, `series`, `unified`). The other 9 (`search`, `graph`, `strings`, `capabilities`, `build_env`, `rules`, `kb`,
`kev`, `guide`) are `not_built` because their modules are absent. Panel-specific behaviour for those is not covered
here, and the 12-dock fake host stands in for them.

### `test_gui_stress_project.py` (project switch, 3 tests)

| Test | What it does | Result |
|---|---|---|
| `test_thirty_rapid_switches_end_on_the_last_project_with_docks_open_and_hidden` | 30 `set_service` calls alternating between two sample projects, with docks shown, then hidden. | pass: root and key match the last project; docks agree with Qt |
| `test_switching_to_the_same_service_again_closes_nothing` | Ten `set_service` calls with the same object, then a save. | pass: the service stays open |
| `test_a_switch_between_two_projects_replaces_the_service_and_its_root` | Switch from project A to B. | pass |

### `test_gui_stress_table.py` (VirtualTable at 100,000 rows, 7 tests)

| Test | What it does | Result |
|---|---|---|
| `test_a_hundred_thousand_rows_sort_and_filter_with_exact_counts` | Header sort both ways; filters with a case-insensitive term and a multi-term substring match. Counts and order are computed from the rows. | pass |
| `test_sorting_a_filtered_hundred_thousand_rows_keeps_the_filter` | Sort a filtered view. | pass |
| `test_one_row_past_the_maximum_shows_the_too_large_state_and_no_rows` | 100,000 rows are shown; 100,001 switch to the too-large state (0 rows, counts `(0, 100001)`, copy copies nothing). | pass: the limit is exact |
| `test_copy_of_a_select_all_is_bounded_by_the_clipboard_limit` | Select all, then Ctrl+C-equivalent copy. | pass: at most 16 KiB, truncation notice last |
| `test_copy_with_no_selection_takes_the_current_row` | Copy with nothing selected. | pass |
| `test_sorting_filtering_and_resizing_in_turns_never_loses_the_selection_or_the_current_row` | 12 rounds of resize, sort and filter, then restore the filter. | pass: the selection and current row come back |
| `test_resizing_a_hundred_thousand_row_table_costs_the_same_as_a_thousand_rows` | Same resize sequence at 1k and 100k rows. | pass: `data()` call counts are equal within 10% |

### `test_gui_stress_graph.py` (GraphCanvas at 2,000 nodes and 8,000 edges, 7 tests)

| Test | What it does | Result |
|---|---|---|
| `test_the_maximum_graph_loads_with_every_node_and_edge` | Load the ceiling. | pass |
| `test_swapping_between_maximum_and_small_graphs_ten_times_leaks_no_scene` | Ten swaps between max and 500 nodes. | pass: exactly one `QGraphicsScene` child after deferred deletes |
| `test_a_focus_and_selection_survive_a_swap_while_their_nodes_do` | Focus and selection through swaps. | pass |
| `test_an_oversized_graph_is_refused_and_the_current_one_stays_on_screen` | 2,001 nodes is refused; the old graph stays. | pass |
| `test_an_edge_past_the_ceiling_is_refused_before_anything_is_built` | 8,001 edges is refused. | pass: nothing is built |
| `test_arrow_keys_walk_the_maximum_graph_and_always_land_on_a_real_node` | 100 arrow-key presses on the max graph. | pass |
| `test_zooming_past_both_clamps_keeps_the_level_consistent` | 60 zoom-ins, then 120 zoom-outs. | pass: zoom and level clamp consistently |

### `test_gui_stress_codediff.py` (CodeDiffView, 4 pass and 1 xfail)

| Test | What it does | Result |
|---|---|---|
| `test_a_side_over_the_view_limit_is_cut_with_a_notice_and_stays_addressable` | A side of about 330 KB is cut at 200,000 characters with a notice; the last line is out of reach. | pass |
| `test_walking_two_thousand_hunks_visits_each_once_and_stops_at_both_ends` | `next_hunk` and `previous_hunk` over 2,000 hunks. | pass |
| `test_theme_and_highlighter_churn_keeps_both_panes_on_the_current_tokens` | 30 theme swaps with highlighter attach and detach. | pass |
| `test_copying_a_cut_side_is_bounded_and_carries_its_provenance` | Copy a cut side. | pass: provenance first, size bounded |
| `test_a_form_feed_inside_a_line_does_not_shift_later_rows` | Repro of QA-GUI-1. | **xfail (strict)** |

### `test_gui_stress_state.py` (StateView and NoticeStrip, 4 tests)

| Test | What it does | Result |
|---|---|---|
| `test_the_announcer_hears_exactly_the_state_text_changes_across_three_hundred_flips` | 300 state flips with repeats; the announcer must hear exactly the changes that have text. | pass |
| `test_a_flood_of_notices_shows_one_line_with_a_count_and_clears_to_nothing` | 400 notices; one announcement; a caution outranks them; all cleared, strip hidden. | pass |
| `test_a_dismissed_notice_returns_only_when_its_text_changes` | 50 dismiss and re-set cycles with the same text, then a new text. | pass |
| `test_a_project_change_brings_back_project_scope_dismissals_and_keeps_session_ones` | Project-scope dismissal returns after `project_changed`. | pass |

### `test_gui_stress_theme.py` (theme switching during load, 2 tests)

| Test | What it does | Result |
|---|---|---|
| `test_sixty_theme_switches_during_a_load_keep_every_surface_on_one_variant` | 60 switches between dark and system while a 40,000-step progress task runs. After each switch the stylesheet, host tokens and controller tokens all match the variant. | pass: the task's final progress and result arrive |
| `test_a_palette_change_mid_load_retokens_the_host_without_losing_the_result` | Change the application palette mid-load, then restore it. | pass |

### `test_gui_stress_teardown.py` (errors and teardown, 9 tests)

| Test | What it does | Result |
|---|---|---|
| `test_failing_factories_and_hooks_leave_the_other_panels_working` | A factory that raises, and a controller whose hooks all raise. | pass: one status line per failure; the other panel keeps working |
| `test_a_result_callback_that_raises_becomes_one_status_line` | A result callback raises `MemoryError`. | pass: a status line, no exception |
| `test_shutdown_with_a_hundred_blocked_tasks_joins_every_worker` | Shut down with 100 cooperatively blocked tasks; a second shutdown is a no-op; submit after shutdown is refused. | pass |
| `test_a_lane_whose_init_failed_fails_every_request_with_the_class_name` | A lane whose init raises; 20 requests. | pass: class name only |
| `test_every_worker_exception_crosses_as_its_class_name_only` (5 cases) | Five exception classes with paths and tokens in the message. | pass: message never crosses |
| `test_closing_a_window_with_floated_docks_and_running_tasks_is_clean` | Float every dock, run 10 blocked tasks, close the real window twice. | pass: no survivors, second close is a no-op |

## Bugs found

### QA-GUI-1: form feed, vertical tab, NEL or lone CR in a source line shifts every later row

- Severity: **medium**. Correctness of navigation and evidence display. The wrong line is highlighted and the hunk
  cursor lands one row early. No crash, no data loss, no silent write.
- Status: recorded as `xfail(strict=True)` in
  `tests/stress/test_gui_stress_codediff.py::test_a_form_feed_inside_a_line_does_not_shift_later_rows`. Not fixed here.
- Repro (offscreen, `CodeDiffView`):

  ```python
  old = ['int a;\fint b;', 'static void f(void)', '{', 'return;', '}']
  new = ['int a;\fint b;', 'static void f(void)', '{', 'return 1;', '}']
  pair = align_pair(old, new, [('equal', 0, 3, 0, 3), ('replace', 3, 4, 3, 4), ('equal', 4, 5, 4, 5)])
  view.set_pair(pair, ('old.c', 'new.c'))
  # pane has 6 blocks for 5 rows; hunks[0].start == 3 shows '{'; reveal('newer', 4, 4) marks '{' and not 'return 1;'
  ```

  Probe results: `\f`, `\v`, `\x85` and a lone `\r` each add one pane row and misplace the hunk. U+2028 is removed by
  the sanitizer and does not shift rows.
- Root cause: `codediff.set_pair` builds the pane text with `_capped` (`sanitize_text(..., multiline=True)`), which
  turns every break form (`\r`, `\v`, `\f`, `\x85`) into `\n`. The row count and line map come from `PairText`, which
  joins the raw lines with `\n` and counts one row per raw line. The two counts disagree once a raw line holds such a
  character. `_rows` is then computed from the sanitized text, so it is also wrong.
- Likely fix (not applied): sanitize each row on its own with `multiline=False` before joining, so a row holds no break
  characters. Or split the source with the same break set the sanitizer uses, so that counts agree. Either way, the
  xfail should then XPASS and be removed.
- Triggers in practice: C sources with `^L` page breaks, and binary-derived strings or disassembly text carrying `\v`,
  NEL or a lone CR.

## Leads checked and dropped

- Stale selection after a project switch (`PanelHost._selected` is not reset on `project_changed`): the navigator never
  fed a match id into the host in a real `MainWindow` probe, so there is no reproducible harm. Not reported.
- `VirtualTable.data()` call counts: about 8 to 10 per visible cell per paint. This is the framework's existing role
  fan-out, not a regression. The property that matters holds: counts are identical at 1k and 100k rows. The test checks
  that property rather than an absolute number.

## Gaps not covered

- Only 5 panels are built in this tree; 9 manifest entries are `not_built` (absent modules). Their panel-specific
  stress is not covered.
- Offscreen only. No Windows run, no real clipboard on a desktop session, and no High-DPI or accessibility-tree check.
- The full Linux and Windows CI gates were not run. Only `tests/stress` was run, per the brief.
