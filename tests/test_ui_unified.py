"""SPEC-31 S4b (07 s11): the Unified panel in the one main window. Offscreen Qt; every result is made up in code
(tests/unified_read_support.py), so nothing here is live evidence."""
from __future__ import annotations

import dataclasses
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from qt_support import (  # noqa: F401  (the fixtures are used by name)
    HOSTILE_PARAMS,
    a11y_audit,
    assert_lazy_model,
    join_gui_threads,
    main_window,
    settings,
    top_level_windows,
)
from unified_read_support import contested_row, make_row, material, publish, request

import patchtrace.ui_unified as ui_unified
from patchtrace.gui.tips import register_tips
from patchtrace.ui_unified import NO_PAIR_TEXT, UnifiedPanel, UnifiedTableModel
from patchtrace.unified import pipeline, read_model, store
from patchtrace.unified.exchange import fail
from patchtrace.unified.panel import TEMPLATES, TIPS
from patchtrace.unified.read_model import UnifiedLoadRequest, load_unified


@pytest.fixture(autouse=True)
def tips():
    register_tips(TIPS, TEMPLATES)


def pair(name, rva, **kw):
    return make_row([(rva, name)], [(rva + 0x80, name)], **kw)


def ready(tmp_path, *, status='complete', stale=False, rows=None, **kw):
    rows = rows if rows is not None else [
        contested_row(0x1000, 0x1080, 'contested_fn'),
        pair('plain_fn', 0x2000, materiality='unchanged', match_id='m-plain'),
        pair('cosmetic_fn', 0x3000, materiality='cosmetic', match_id='m-cos')]
    loaded = publish(tmp_path / 'result', rows, status=status)
    if stale:
        loaded = store.LoadedResult('stale', 'guard-moved', None, None, loaded.manifest, loaded.directory)
    return load_unified(request(loaded, extraction_configured=True, **kw))


def wait_for(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        QApplication.processEvents()
    assert condition()


@pytest.fixture
def panel(qtbot):
    widget = UnifiedPanel()
    qtbot.addWidget(widget)
    widget.resize(1100, 700)
    widget.show()
    return widget


# ---- states U0-U8 -------------------------------------------------------------------------------------------


def test_u0_and_u1_messages_hide_the_table(panel):
    panel.set_view_model(load_unified(UnifiedLoadRequest(None)))
    assert panel.status.full_text() == read_model.STATE_TEXT['U0'] and not panel.table.isVisible()
    panel.set_view_model(load_unified(request(None, extraction_configured=True)))
    assert panel.status.full_text() == read_model.STATE_TEXT['U1'] and not panel.table.isVisible()


def test_u2_progress_shows_cancel(panel):
    panel.show_text_state('U2', read_model.progress_text('ingest', 3, 9))
    assert panel.status.full_text() == 'Unified analysis: ingest 3/9' and panel.cancel_button.isVisible()
    panel.show_text_state('U2', read_model.progress_text('ingest', 0, None))
    assert panel.status.full_text() == 'Unified analysis: ingest (no counts available)'


def test_u3_lists_review_rows_and_counts_the_collapsed_ones(panel, tmp_path):
    vm = ready(tmp_path)
    panel.set_view_model(vm)
    assert vm.state == 'U3' and panel.table.isVisible()
    assert panel.model.rowCount() == 2                       # contested + decompiler-relative cosmetic stay
    assert panel.model.row_at(0).decision == 'contested'      # contested rows sort first
    assert 'cosmetic/unchanged hidden' in panel.summary.full_text()
    panel.show_hidden.setChecked(True)
    assert panel.model.rowCount() == 3 and 'hidden' not in panel.summary.full_text()


def test_u4_partial_is_announced_and_the_table_stays(panel, tmp_path):
    vm = ready(tmp_path, status='partial')
    panel.set_view_model(vm)
    assert vm.state == 'U4' and panel.status.full_text().startswith('Partial unified result')
    assert panel.table.isVisible()


def test_u5_failed_offers_retry_and_copy(panel):
    panel.set_view_model(load_unified(request(None, error='PT-UNIFIED-STORE: enrichment-unreadable')))
    assert panel.status.full_text().startswith('The unified result could not be produced')
    assert panel.retry_button.isVisible() and panel.copy_error_button.isVisible() and not panel.table.isVisible()


def test_u6_stale_keeps_the_table_and_names_the_reason(panel, tmp_path):
    vm = ready(tmp_path, stale=True, changed_inputs=('manual_digest',))
    panel.set_view_model(vm)
    assert vm.state == 'U6' and 'a manual correction changed the inputs' in panel.status.full_text()
    assert panel.table.isVisible()


def test_u7_notice_when_extraction_is_not_configured(panel, tmp_path):
    loaded = publish(tmp_path / 'r', [pair('f', 0x1000, materiality='review', classes=['callee'])])
    vm = load_unified(request(loaded, extraction_configured=False))
    panel.set_view_model(vm)
    assert vm.state == 'U3' and read_model.STATE_TEXT['U7'] in panel.banner.toPlainText()


def test_u8_too_many_rows_hides_the_table(panel, tmp_path, monkeypatch):
    monkeypatch.setattr(read_model, 'DISPLAY_ROW_CAP', 1)
    panel.set_view_model(ready(tmp_path))
    panel.show_hidden.setChecked(True)
    assert panel.status.full_text() == read_model.STATE_TEXT['U8'].format(n='3') and not panel.table.isVisible()
    assert panel.model.rowCount() == 0


# ---- table, filters, hostile text, accessibility --------------------------------------------------------------


def test_search_is_debounced_and_decision_filter_is_multi_select(panel, tmp_path):
    panel.set_view_model(ready(tmp_path))
    panel.show_hidden.setChecked(True)
    panel.search.setText('plain')
    assert panel.model.rowCount() == 3                       # nothing changes before the 150 ms timer fires
    wait_for(lambda: panel.model.rowCount() == 1)
    panel.search.setText('')
    wait_for(lambda: panel.model.rowCount() == 3)
    for key, action in panel.decision_filter.actions_by_key.items():
        action.setChecked(key == 'contested')
    assert panel.model.rowCount() == 1 and panel.model.row_at(0).decision == 'contested'


def test_column_sort_orders_by_one_sources_own_values_and_default_returns(panel, tmp_path):
    panel.set_view_model(ready(tmp_path))
    panel.show_hidden.setChecked(True)
    column = next(i for i, c in enumerate(read_model.columns(panel.model.vm)) if c.key.startswith('source:'))
    panel.model.sort(column, Qt.SortOrder.DescendingOrder)
    assert panel.model.rowCount() == 3
    panel.model.sort(-1)
    assert panel.model.row_at(0).decision == 'contested'


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_names_render_as_plain_text(panel, tmp_path, text):
    vm = ready(tmp_path, rows=[pair(text, 0x1000, materiality='review', classes=['callee'])])
    panel.set_view_model(vm)
    index = panel.model.index(0, 0)
    shown = panel.model.data(index)
    assert not set(shown) & set('\x00\x1b‮ ') and '\n' not in shown
    for role in (Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.AccessibleTextRole):
        assert not set(panel.model.data(index, role)) & set('\x00\x1b‮')


def test_controls_are_named_tipped_and_plain(panel):
    assert [p for p in a11y_audit(panel) if p != 'QHeaderView#?: not keyboard focusable'] == []   # as test_gui_table
    for name in ('run', 'cancel', 'retry', 'copy_error', 'view_switch', 'search', 'show_hidden', 'table', 'detail',
                 'goto', 'correct', 'copy', 'explain'):
        widget = panel.findChild(object, f'unified.{name}')
        assert widget is not None, name
        assert 'What:' in widget.toolTip(), name
    assert panel.status.accessibleName() == ''


def test_model_cost_is_what_it_shows(qtbot, tmp_path):
    base = ready(tmp_path, rows=[pair('seed', 0x1000, materiality='review', classes=['callee'])])
    seed = base.rows[0]

    every = tuple(dataclasses.replace(seed, row_id=f'{n:064x}') for n in range(100_000))   # built outside the timing

    def factory(size):
        model = UnifiedTableModel()
        model.set_view_model(dataclasses.replace(base, rows=every[:size]))
        return model
    assert_lazy_model(factory)


# ---- controller over the real window ---------------------------------------------------------------------------


@pytest.fixture
def unified(main_window, tmp_path):  # noqa: F811
    main_window.show()
    assert main_window.panels.show_panel('unified') is not None
    controller = main_window.panels.controller('unified')
    controller.loader = lambda req, token=None: ready(tmp_path)
    controller.engine_busy = lambda: False
    return main_window, controller


def loaded_controller(unified):
    window, controller = unified
    controller.reload()
    wait_for(lambda: controller.vm is not None and controller.vm.state == 'U3')
    return window, controller


def test_panel_is_a_tab_of_the_evidence_dock_in_the_one_window(unified):
    window, _ = unified
    assert window.panels.show_panel('evidence') is not None   # Qt reports tabs only between visible docks
    docks = window.panels.panels
    assert docks['unified'].dock in window.tabifiedDockWidgets(docks['evidence'].dock)
    assert top_level_windows() == [window]


def test_a_result_for_another_project_is_dropped(unified):
    _, controller = loaded_controller(unified)
    shown = controller.vm
    controller._loaded(('another', 'project'), dataclasses.replace(shown, state='U5'))
    assert controller.vm is shown


def test_goto_selects_the_ghidriff_match_or_says_the_text_is_unavailable(unified):
    _, controller = loaded_controller(unified)
    selected, shown = [], []
    controller.nav = SimpleNamespace(
        select_match=lambda match_id, clear_filters=False: selected.append((match_id, clear_filters)) or True,
        show_pair=lambda *args: shown.append(args))
    with_match = next(r for r in controller.vm.rows if r.ghidriff_match_id)
    without = next(r for r in controller.vm.rows if r.ghidriff_match_id is None)
    controller.show_row(with_match)
    controller.show_row(without)
    assert selected == [(with_match.ghidriff_match_id, True)]
    assert shown == [(NO_PAIR_TEXT, NO_PAIR_TEXT, f'Unified row {without.function_label}: unavailable')]
    controller.pair_texts = lambda vm, row: ('old', 'new', 'label')
    controller.show_row(without)
    assert shown[-1] == ('old', 'new', 'label')


def test_correct_match_opens_the_existing_dialog_over_the_selected_match(unified, monkeypatch):
    window, controller = loaded_controller(unified)
    calls = []
    controller.nav = SimpleNamespace(select_match=lambda match_id, clear_filters=False: calls.append(match_id) or True)
    monkeypatch.setattr(window, 'correct_match', lambda: calls.append('dialog'))
    row = dataclasses.replace(controller.vm.rows[0], ghidriff_match_id='m-1')
    controller.correct(row)
    controller.correct(dataclasses.replace(row, ghidriff_match_id=None))
    assert calls == ['m-1', 'dialog']


def test_explain_previews_the_bounded_context_and_sends_nothing(unified, monkeypatch):
    _, controller = loaded_controller(unified)
    seen = []
    monkeypatch.setattr(ui_unified.ExplainDialog, 'exec',
                        lambda self: seen.append(' '.join(label.text() for label in self.findChildren(
                            ui_unified.PlainLabel))))
    row = next(r for r in controller.vm.rows if r.ghidriff_match_id is None)
    controller.explain(row)
    assert seen and 'Nothing is sent from here' in seen[0]


def test_explain_of_a_row_with_a_ghidriff_match_feeds_the_existing_context_preview(unified, monkeypatch):
    window, controller = loaded_controller(unified)
    calls = []
    controller.nav = SimpleNamespace(select_match=lambda match_id, clear_filters=False: calls.append(match_id) or True)
    monkeypatch.setattr(window, 'preview_interpretation', lambda *a, notes=(): calls.append(('preview', list(notes))))
    monkeypatch.setattr(ui_unified.ExplainDialog, 'exec', lambda self: calls.append('own-dialog'))
    row = next(r for r in controller.vm.rows if r.ghidriff_match_id)
    controller.explain(row)
    fragment = read_model.explain_context(controller.vm, row)
    assert calls == [row.ghidriff_match_id, ('preview', [(fragment.title, fragment.text, fragment.omitted)])]


def test_explain_falls_back_to_its_own_preview_when_the_match_is_not_in_the_navigator(unified, monkeypatch):
    window, controller = loaded_controller(unified)
    calls = []
    controller.nav = SimpleNamespace(select_match=lambda match_id, clear_filters=False: False)
    monkeypatch.setattr(window, 'preview_interpretation', lambda *a, notes=(): calls.append('preview'))
    monkeypatch.setattr(ui_unified.ExplainDialog, 'exec', lambda self: calls.append('own-dialog'))
    controller.explain(next(r for r in controller.vm.rows if r.ghidriff_match_id))
    assert calls == ['own-dialog']


def test_copy_provenance_uses_the_shell_clipboard(unified):
    _, controller = loaded_controller(unified)
    copied = []
    controller._copy_text = lambda text: copied.append(text) or True
    controller.copy_provenance(controller.vm.rows[:1])
    assert copied and copied[0].startswith('PatchTrace unified comparison')


def test_run_is_off_by_default_and_names_the_reason(unified):
    _, controller = unified
    enabled, reason = controller.run_availability()
    assert not enabled and 'unified/enabled' in reason and not controller.panel.run_button.isEnabled()
    controller.settings.set('enabled', True)
    assert controller.run_availability()[0]
    controller.engine_busy = lambda: True
    assert 'engine run' in controller.run_availability()[1]


def run_fakes(monkeypatch, order, *, block=True):
    """prepare/execute/publish stand-ins; `order` records which thread each ran on (True = the GUI thread)."""
    monkeypatch.setattr(pipeline, 'prepare', lambda service, options=None: SimpleNamespace(plan=None))

    def execute(request_, cancel, emit):
        order.append(('execute', threading.current_thread() is threading.main_thread()))
        emit(SimpleNamespace(stage='ingest', done=1, total=2))
        if block:
            cancel.wait(5)
        return pipeline.WorkerOutput(None, fail('PT-UNIFIED-CANCEL', 'cancelled') if block else None, None)

    def publish_(service, request_, output):
        order.append(('publish', threading.current_thread() is threading.main_thread()))
        if output.error is not None:
            raise output.error
        return SimpleNamespace(status='ok')
    monkeypatch.setattr(pipeline, 'execute', execute)
    monkeypatch.setattr(pipeline, 'publish', publish_)


def test_run_executes_off_thread_and_publishes_on_the_gui_thread(unified, monkeypatch):
    _, controller = unified
    order = []
    run_fakes(monkeypatch, order, block=False)
    controller.settings.set('enabled', True)
    controller.start_run()
    wait_for(lambda: ('publish', True) in order)
    assert ('execute', False) in order


def test_cancel_during_run_keeps_the_previous_result(unified, monkeypatch):
    _, controller = loaded_controller(unified)
    order = []
    run_fakes(monkeypatch, order)
    controller.settings.set('enabled', True)
    controller.start_run()
    wait_for(lambda: ('execute', False) in order)
    assert controller.tasks.busy('unified-run')
    controller.cancel_run()
    wait_for(lambda: not controller.tasks.busy('unified-run'))
    assert ('publish', True) not in order and controller.vm.state == 'U3'


def test_project_switch_during_run_drops_the_result(unified, qtbot, monkeypatch):
    _, controller = unified
    order = []
    run_fakes(monkeypatch, order, block=False)
    controller.settings.set('enabled', True)
    keys = iter([('a', 'p1', 1), ('b', 'p2', 1), ('b', 'p2', 1)])
    controller.port = SimpleNamespace(project=lambda: object(), busy=lambda: False, key=lambda: next(keys))
    controller.start_run()
    wait_for(lambda: ('execute', False) in order)
    qtbot.wait(200)
    assert ('publish', True) not in order


def test_close_while_running_cancels_and_waits(unified, monkeypatch):
    window, controller = unified
    order = []
    run_fakes(monkeypatch, order)
    controller.settings.set('enabled', True)
    controller.start_run()
    wait_for(lambda: ('execute', False) in order)
    window.close()          # the autouse fixture then fails the test if any task thread survived


def test_filters_are_saved_and_restored(unified):
    _, controller = unified
    panel = controller.panel
    panel.show_hidden.setChecked(True)
    panel.decision_filter.set_checked({'contested'})
    panel.apply_filters()
    panel.show_hidden.blockSignals(True)         # a reset that does not save, to stand for a new session
    panel.show_hidden.setChecked(False)
    panel.show_hidden.blockSignals(False)
    panel.decision_filter.set_checked(panel.decision_filter.defaults)
    controller._restore_filters()
    assert panel.decision_filter.checked() == {'contested'} and panel.show_hidden.isChecked()


def test_row_detail_loads_off_thread(unified):
    window, controller = unified
    row, _ = material({'older': [(0x1000, 'f')], 'newer': [(0x1080, 'f')]})
    controller.loader = lambda req, token=None: load_unified(request(publish(window.service.root / 'ur', [row])))
    controller.reload()
    wait_for(lambda: controller.vm is not None and controller.vm.rows)
    controller.panel.table.setCurrentIndex(controller.panel.model.index(0, 0))
    wait_for(lambda: controller.panel.detail.toPlainText() not in ('', ui_unified.LOADING_DETAIL))
    assert 'Decision' in controller.panel.detail.toPlainText()
