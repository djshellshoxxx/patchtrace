# SPEC-31 audit: gui card (read_model, read_text, pair_text, panel, ui_unified)

ID | severity | file:line | defect | status
---|---|---|---|---
GUI-01 | High | ui_unified.py start_run/_run_finished | run finished, then superseded (cancel, project switch, shutdown) before delivery: TaskRunner drops the payload with no callback, staged result dir never removed (disk leak) | fixed: test_a_run_whose_result_is_dropped_after_the_worker_finished_leaves_no_staged_directory (_StagedGuard weakref.finalize)
GUI-02 | Medium | read_model.py parse_column_widths | 5,000-digit `unified/columns` item -> int() ValueError -> panel construction crash; non-ASCII digits accepted | fixed: test_hostile_column_width_settings_are_ignored_not_fatal
GUI-03 | Low | ui_unified.py UnifiedTableModel.data/headerData | no column bound (IndexError), headerData(-1) answered last column | fixed: test_the_table_model_answers_out_of_range_queries_with_none
GUI-04 | Medium | ui_unified.py reload/start_run/_run_finished | non-UnifiedError from capture_plan/capture_request/publish swallowed by runner; panel stuck on Loading / progress with Cancel | fixed: test_an_unexpected_capture_failure_shows_a_failure_instead_of_leaving_the_panel_loading
GUI-05 | Medium | pair_text.py RowCodeSource.close | queued code load after close() reopened IrReaders never closed (Windows handle lock) | fixed: test_a_closed_row_code_source_opens_no_reader_and_says_the_result_is_unavailable
GUI-06 | Medium | read_model.py _labels | search_key `names hexes` cut at 512: group rows with long names lost addresses, address search missed them | fixed: test_search_by_address_still_finds_a_group_row_with_long_names
GUI-07 | Low | read_model.py STALE_REASONS | `sources`/`ghidriff_raw_sha256` words over-claimed | fixed: test_the_stale_reason_names_what_changed_without_a_generic_claim (test_read_model_states_and_precedence expectation updated for the new words only)
GUI-08 | Medium | ui_unified.py splitter/hunk label | table squeezed by equal-weight detail pane; hunk label middle-elided "No c...nges" | fixed: test_the_table_keeps_room_and_the_hunk_label_is_not_elided
GUI-09 | Medium | read_model.py request_from_service, ui_unified.reload | COR-08: results stored with --sources/--no-extract/--no-residual always stale vs default plan | fixed: test_a_result_stored_with_non_default_options_loads_current_and_stale_only_when_an_input_changes
GUI-10 | Medium | ui_unified.py copy_provenance/explain | records_for (decompress whole rows part, about 25 ms per 10k rows) runs on GUI thread | deferred: async copy changes timing pinned by existing tests; ask
GUI-11 | Low | read_model.py is_collapsed | `unchanged` collapses without checking proof UNCH/1 (store verify guarantees fact verdict equality, so unreachable on verified results) | deferred: existing tests build unchanged rows without facts
GUI-12 | Low | read_model.py request_from_plan | `attention` map never supplied by any caller (spec: optional) | ask
GUI-13 | Low | pair_text.py _c_side | group rows: decompiled text uses first side only; decompiled lines not capped by MAX_LINES (bounded by 4 MiB line cap; 100k-line diff probed 0.4 s) | deferred: bounded
GUI-14 | Info | read_model.py load | 30k-row load 2.3 s in worker (pydantic); table model sort/filter/reset at 30k rows < 20 ms | no defect

Checked clean: HTML injection (PlainLabel/SafeTextView/escaped template tooltips), thread lifecycle via TaskRunner (generation drops stale loads; `_row_changed` bumps detail generation), ir_opcodes/_pair property probes (3000 cases each: every line shown once in order, rows outside hunks equal).

ASKS: record `use_ir` and `residual` in run provenance (pipeline._provenance) so the read model need not try both; supply `attention` from the evidence ranking to request_from_plan. Trade-off of GUI-09: an S0 result with a ProgramIR placed afterwards reads current (cannot tell --no-extract from nothing placed).
GUI-10 | fixed 20261104 (w2b) | copy_provenance/explain read the sidecar on ACTION_CHANNEL (generation-guarded, project change/shutdown drop it) | tests/test_unified_w2b_async_actions.py::test_copy_provenance_returns_at_once_and_the_gui_thread_stays_responsive
