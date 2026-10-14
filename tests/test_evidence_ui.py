"""C6 offscreen Qt tests for the evidence panel (spec §10.2): states E0-E8, hostile text, threads."""
from __future__ import annotations

import dataclasses
import os
import re
import sys
import threading

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QModelIndex, QSettings, Qt, QThread
from PySide6.QtGui import QAccessible, QFont, QGuiApplication
from PySide6.QtWidgets import QApplication, QStyleOptionViewItem, QWidget
from test_evidence_view import (
    NEW,
    OLD,
    RUN,
    bd,
    build,
    gmatch,
    mset,
    standard_sets,
    unknown_vm,
)

from patchtrace import ui_evidence
from patchtrace.secondary import evidence_panel_service as service_api
from patchtrace.secondary.contracts import Capability
from patchtrace.secondary.evidence_view import (
    FOOTER,
    STATE_TEXT,
    EngineOutcomeView,
    empty_model,
    format_provenance_blocks,
)
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow
from patchtrace.ui_evidence import (
    ADDRESS_ROLE,
    EngineRunThread,
    EvidenceController,
    EvidenceDelegate,
    EvidencePanel,
    EvidenceTableModel,
)


@pytest.fixture(autouse=True)
def join_evidence_threads():
    """Every evidence worker must be finished after each test; deferred deletes are flushed."""
    yield
    for thread in list(ui_evidence._LIVE_THREADS):
        if ui_evidence.thread_alive(thread):
            thread.cancel.set()
            assert thread.wait(5000), 'evidence worker still running after the test'
    QApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


HOSTILE = ['<b>pwn</b>', '<img src=x onerror=1>', '&lt;', '{0}', '%s', '\x1b[31m', '\u202erev', 'file:///C:/x']


@pytest.fixture
def settings(tmp_path):
    return QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)


@pytest.fixture
def panel(qtbot, settings):
    widget = EvidencePanel(settings)
    qtbot.addWidget(widget)
    widget.has_project = True
    return widget


def visible(widget):
    return not widget.isHidden()


def show(panel, vm):
    panel.set_view_model(vm)
    return panel


# ---- states ---------------------------------------------------------------------------------------


def test_state_no_project_disables_everything(qtbot, settings):
    widget = EvidencePanel(settings)
    qtbot.addWidget(widget)
    widget.set_project(False)
    assert widget.status.text() == STATE_TEXT['no-project']
    assert widget.stack.currentIndex() == 0
    for control in (widget.filter, widget.search, widget.table, widget.copy_button, widget.goto_button,
                    widget.run_button, widget.refresh_button, widget.probe_button, widget.import_button):
        assert not control.isEnabled(), control.objectName()


def test_state_no_engines_shows_ghidriff_only_message(panel):
    show(panel, build(sets=()))
    assert panel.state_label.text() == STATE_TEXT['no-engines']
    assert visible(panel.open_engines_button) and panel.open_engines_button.isEnabled()
    panel.open_engines_button.click()
    assert panel.tabs.currentIndex() == 1


def test_state_loading_shows_indeterminate_and_clears_table(panel):
    panel.set_loading(True)
    assert panel.stack.currentIndex() == 0 and visible(panel.loading_bar)
    assert panel.loading_bar.maximum() == 0 and panel.state_label.text() == STATE_TEXT['loading']
    assert not panel.filter.isEnabled()
    show(panel, build())
    panel.set_loading(True)  # refresh after a table was shown: no flicker, table stays
    assert panel.stack.currentIndex() == 1 and panel.status.text() == STATE_TEXT['refreshing']


def test_state_ready_three_engines_columns_headers_and_units(panel):
    show(panel, build())
    model = panel.model
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    assert headers[0].startswith('Match') and headers[1].startswith('Verdict')
    assert headers[2] == 'Ghidriff (baseline)\nmatch type (raw)'
    assert headers[3] == 'BinDiff 8\nsimilarity / algorithm'
    assert headers[4] == 'rz-diff 0.9.1\nbyte similarity (raw bytes)'
    assert model.rowCount() == 4 and panel.stack.currentIndex() == 1
    assert panel.footer.text() == FOOTER
    assert panel.status.text().startswith('Summary: 4 matches')


def test_state_one_engine_other_columns_read_not_run(panel):
    show(panel, build(sets=(standard_sets()[0],)))
    model = panel.model
    assert all(model.data(model.index(r, 4)) == 'not run' for r in range(model.rowCount()))


def test_state_contested_row_badge_text_glyph_and_alternatives_in_detail(panel):
    show(panel, build())
    model = panel.model
    assert model.data(model.index(0, 1)) == 'Contested'
    assert model.data(model.index(0, 1), Qt.ItemDataRole.AccessibleTextRole) == 'Verdict: Contested'
    panel.table.selectRow(0)
    text = panel.detail.toPlainText()
    assert 'Alternatives' in text and 'BinDiff: older 0x30 -> newer 0x99' in text
    assert 'Triage index' not in text
    panel.show_index_box.setChecked(True)
    assert 'Triage index 0 (uncalibrated, ordering aid only)' in panel.detail.toPlainText()


def test_state_partial_failed_engine_banner_and_other_columns_intact(panel):
    vm = build(sets=(standard_sets()[0],), outcomes=(EngineOutcomeView('rz-diff', 'failed',
                                                                       error_code='PT-SECONDARY-RUN'),))
    show(panel, vm)
    assert vm.state == 'partial' and visible(panel.partial_banner)
    assert "1 engine(s) did not produce results" in panel.partial_banner.text()
    model = panel.model
    assert model.data(model.index(0, 4)) == 'failed' and model.data(model.index(3, 3)).startswith('sim ')


def test_state_failed_assembly_shows_error_and_retry(panel, qtbot):
    show(panel, build(sets=(standard_sets()[0], standard_sets()[0])))
    assert panel.stack.currentIndex() == 0 and 'could not be assembled' in panel.state_label.text()
    assert visible(panel.retry_button) and visible(panel.copy_error_button)
    with qtbot.waitSignal(panel.refresh_requested, timeout=1000):
        panel.retry_button.click()
    panel.copy_error_button.click()
    assert 'PT-EVIDENCE-ASSEMBLY' in QGuiApplication.clipboard().text()


def test_state_stale_banner_greys_rows_disables_goto_keeps_copy(panel, qtbot):
    show(panel, build())
    panel.set_stale('the project changed after these results were loaded')
    assert visible(panel.stale_banner) and 'Engine evidence is stale' in panel.stale_banner.text()
    assert panel.model.stale
    panel.table.selectRow(0)
    assert not panel.goto_button.isEnabled() and panel.copy_button.isEnabled()
    with qtbot.assertNotEmitted(panel.match_activated):
        panel.activate_current()
    panel.copy_provenance()
    assert 'STALE: yes' in QGuiApplication.clipboard().text()


def test_state_unsupported_lists_reasons_and_offers_no_run(panel):
    outs = tuple(EngineOutcomeView(e, 'unsupported', message=f'{e} not installed') for e in ('bindiff', 'rz-diff'))
    show(panel, build(sets=(), outcomes=outs))
    assert 'rz-diff not installed' in panel.state_label.text()
    panel.set_capabilities({'rz-diff': Capability(engine='rz-diff', supported=False, version=None, path='',
                                                  supports_json=False, reason='missing')})
    assert not panel.engine_checks['rz-diff'].isEnabled() and not panel.run_button.isEnabled()


def test_state_too_large_guard(panel, monkeypatch):
    from patchtrace.secondary import evidence_view
    monkeypatch.setattr(evidence_view, 'DISPLAY_ROW_CAP', 1)
    show(panel, build())
    assert panel.stack.currentIndex() == 0 and 'Too many rows to display (4)' in panel.state_label.text()


# ---- untrusted text -------------------------------------------------------------------------------


def test_untrusted_function_name_is_plain_text(panel):
    matches = [gmatch(f'm{i}', f'{0x10 + i:x}', f'{0x20 + i:x}', name) for i, name in enumerate(HOSTILE)]
    sets = (mset('bindiff', *[bd(0x10 + i, 0x20 + i, algo='<a href="x">algo</a>') for i in range(len(HOSTILE))]),)
    show(panel, build(matches=matches, sets=sets))
    model = panel.model
    names = {model.data(model.index(r, 0)) for r in range(model.rowCount())}
    assert {'<b>pwn</b>', '<img src=x onerror=1>', '&lt;', '{0}', '%s', '[31m', 'rev', 'file:///C:/x'} == names
    for r in range(model.rowCount()):
        tip = model.data(model.index(r, 0), Qt.ItemDataRole.ToolTipRole)
        assert '<b>pwn' not in tip and '<img' not in tip and '<a href' not in tip
        cell_tip = model.data(model.index(r, 3), Qt.ItemDataRole.ToolTipRole)
        assert '<a href' not in cell_tip and '&lt;a href' in cell_tip
    panel.table.selectRow(0)
    detail = panel.detail.toPlainText()
    assert '<a href="x">algo</a>' in detail or '<b>pwn</b>' in detail
    assert not panel.detail.document().toHtml().count('<a href')
    for label in (panel.status, panel.state_label, panel.stale_banner, panel.engines_label):
        assert label.textFormat() == Qt.TextFormat.PlainText


def test_untrusted_engine_error_and_stderr_rendered_plain(panel):
    stderr = '\n'.join(f'<b>line {i}</b>\u202e' for i in range(100_000))
    tail = service_api._tail_lines(stderr)
    panel.set_engine_log('rz-diff', tail, 'Error code: <i>x</i>')
    panel.engine_table.clearSelection()
    lines = panel.engine_log.toPlainText().splitlines()
    assert 0 < len(lines) <= 200 and lines[-1] == '<b>line 99999</b>'
    panel.set_run_status('<b>bold</b>')
    assert panel.run_status.text() == '<b>bold</b>' and panel.run_status.textFormat() == Qt.TextFormat.PlainText


# ---- keyboard, clipboard, accessibility, sorting, filters --------------------------------------------


def test_keyboard_navigation_and_enter_emits_match_activated(panel, qtbot):
    show(panel, build())
    panel.show()
    panel.table.setFocus()
    panel.table.selectRow(0)
    qtbot.keyClick(panel.table, Qt.Key.Key_Down)
    assert panel.current_row().match_id == panel.model.row_at(1).match_id
    with qtbot.waitSignal(panel.match_activated, timeout=1000) as blocker:
        qtbot.keyClick(panel.table, Qt.Key.Key_Return)
    assert blocker.args == [panel.model.row_at(1).match_id]


def test_ctrl_c_copies_provenance_to_clipboard(panel, qtbot):
    vm = build()
    show(panel, vm)
    panel.table.selectRow(0)
    qtbot.keyClick(panel.table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert QGuiApplication.clipboard().text() == format_provenance_blocks(vm, [panel.model.row_at(0)])


def test_copy_button_multi_selection_caps(panel):
    matches = [gmatch(f'm{i}', f'{0x1000 + i:x}', f'{0x2000 + i:x}', f'f{i}') for i in range(300)]
    show(panel, build(matches=matches, sets=(mset('bindiff', bd(0x1000, 0x2000)),)))
    panel.table.selectAll()
    panel.copy_button.click()
    text = QGuiApplication.clipboard().text()
    assert len(text) <= 16 * 1024 and 'more omitted' in text


def test_accessible_names_and_descriptions_present(panel):
    show(panel, build())
    from test_tooltips import controls
    found = controls(panel)
    assert len(found) >= 20
    for widget in found:
        assert widget.accessibleName(), widget.objectName()
        assert widget.accessibleDescription(), widget.objectName()
    assert panel.table.accessibleName() == 'Per-match engine evidence table'
    # The status label keeps an EMPTY accessible name so QLabel.setText emits NameChanged itself and the
    # spoken name is the status text (a fixed name would suppress the event).
    assert panel.status.accessibleName() == ''
    interface = QAccessible.queryAccessibleInterface(panel.status)
    assert interface.text(QAccessible.Text.Name) == panel.status.text()
    panel.set_loading(True)
    assert QAccessible.queryAccessibleInterface(panel.status).text(QAccessible.Text.Name) == STATE_TEXT['refreshing']
    assert panel.table.verticalHeader().isHidden()
    model = panel.model
    spoken = model.data(model.index(3, 3), Qt.ItemDataRole.AccessibleTextRole)
    assert spoken == 'BinDiff similarity 0.97, algorithm name hash matching'
    assert 'verdict Agree' in model.data(model.index(3, 0), Qt.ItemDataRole.AccessibleTextRole)


def test_default_order_contested_first(panel):
    show(panel, unknown_vm())
    assert [panel.model.row_at(i).verdict for i in range(4)] == ['contested', 'unknown', 'single-engine', 'agree']


def test_sorting_by_engine_column_uses_that_engines_native_value(panel):
    matches = [gmatch(f'm{i}', f'{0x10 + i:x}', f'{0x20 + i:x}', f'f{i}') for i in range(3)]
    sets = (mset('bindiff', bd(0x10, 0x20, sim=500), bd(0x11, 0x21, sim=900)),
            mset('rz-diff', *[__import__('test_evidence_view').rz(0x10 + i, 0x20 + i, sim=s)
                              for i, s in enumerate((990, 100, 400))]))
    show(panel, build(matches=matches, sets=sets))
    panel._header_clicked(3)  # BinDiff, descending first
    assert [panel.model.row_at(i).match_id for i in range(3)] == ['m1', 'm0', 'm2']  # m2 no value -> last
    panel._header_clicked(4)  # rz-diff
    assert [panel.model.row_at(i).match_id for i in range(3)] == ['m0', 'm2', 'm1']
    panel._header_clicked(4)
    assert [panel.model.row_at(i).match_id for i in range(3)] == ['m1', 'm2', 'm0']


def test_filter_and_search_and_hide_agreed_update_row_count(panel, settings):
    show(panel, unknown_vm())
    panel.filter.setCurrentIndex(1)
    assert panel.model.rowCount() == 1
    panel.filter.setCurrentIndex(0)
    panel.hide_agreed.setChecked(True)
    assert panel.model.rowCount() == 3
    panel.search.setText('0x30')
    panel._apply_filter()
    assert panel.model.rowCount() == 1
    panel.filter.setCurrentIndex(5)
    panel.search.setText('')
    panel._apply_filter()
    assert panel.model.rowCount() == 1 and panel.model.row_at(0).verdict == 'engine-only'
    assert settings.value('evidence/filter') in (5, '5') and settings.value('evidence/hide_agreed') in (True, 'true')


def test_settings_persist_and_corrupt_values_fall_back(qtbot, settings):
    settings.setValue('evidence/show_index', 'true')
    settings.setValue('evidence/filter', 2)
    restored = EvidencePanel(settings)
    qtbot.addWidget(restored)
    assert restored.show_index and restored.filter.currentIndex() == 2
    settings.setValue('evidence/filter', 'garbage')
    settings.setValue('evidence/hide_agreed', [1, 2])
    settings.setValue('evidence/show_index', 'maybe')
    fallback = EvidencePanel(settings)
    qtbot.addWidget(fallback)
    assert fallback.filter.currentIndex() == 0 and not fallback.hide_agreed.isChecked() and not fallback.show_index


def test_selection_survives_filter_and_reload(panel):
    show(panel, build())
    target = panel.model.row_at(2).match_id
    panel.select_match(target)
    panel.search.setText('')
    panel._apply_filter()
    show(panel, build())
    assert panel.current_row().match_id == target


def test_highdpi_row_height_scales_with_font(panel):
    show(panel, build())
    delegate = panel.table.itemDelegate()
    assert isinstance(delegate, EvidenceDelegate)
    option = QStyleOptionViewItem()
    option.initFrom(panel.table)
    small = delegate.sizeHint(option, panel.model.index(0, 0)).height()
    big_font = QFont(panel.table.font())
    big_font.setPointSize(28)
    panel.table.setFont(big_font)
    option = QStyleOptionViewItem()
    option.initFrom(panel.table)
    assert delegate.sizeHint(option, panel.model.index(0, 0)).height() > small
    panel.setFont(big_font)
    assert panel.table.verticalHeader().defaultSectionSize() >= 2 * panel.table.fontMetrics().lineSpacing()


def test_delegate_paints_every_state_without_error(panel, qtbot):
    show(panel, unknown_vm())
    panel.resize(1100, 600)
    panel.show()
    qtbot.waitExposed(panel)
    panel.table.selectRow(0)
    panel.table.viewport().repaint()
    panel.set_stale('x')
    panel.table.viewport().repaint()
    assert panel.model.data(panel.model.index(0, 0), ADDRESS_ROLE) == '30 > 40'


# ---- performance gate (research flag F4) -----------------------------------------------------------


def visible_cells(table) -> int:
    viewport = table.viewport()
    first_row, last_row = table.rowAt(0), table.rowAt(viewport.height() - 1)
    first_col, last_col = table.columnAt(0), table.columnAt(viewport.width() - 1)
    last_row = table.model().rowCount() - 1 if last_row < 0 else last_row
    last_col = table.model().columnCount() - 1 if last_col < 0 else last_col
    return max(0, last_row - first_row + 1) * max(0, last_col - first_col + 1)


def many_rows_vm(n: int):
    """A view-model with n rows built cheaply from a small real one (Qt-side gate only)."""
    base = build()
    rows = tuple(dataclasses.replace(base.rows[i % len(base.rows)], match_id=f'm{i:06}',
                                     function_label=f'fn{i}', search_key=f'fn{i} {i:x}', order=i)
                 for i in range(n))
    return dataclasses.replace(base, rows=rows, engine_only=(), total_rows=n)


@pytest.mark.parametrize('n', [10_000, 100_000])
def test_large_models_stay_lazy_with_data_call_ceilings(panel, n):
    """Research flag F4 / hard-problems plan section 3: call ceilings are exact, times have 5x slack."""
    import time
    vm = many_rows_vm(n)
    panel.resize(900, 500)
    panel.show()
    QApplication.processEvents()
    model = panel.model
    model.data_calls = 0
    start = time.perf_counter()
    show(panel, vm)
    QApplication.processEvents()
    reset_time = time.perf_counter() - start
    ceiling = int(7 * visible_cells(panel.table) * 1.2) + 20
    assert 0 < model.data_calls <= ceiling, (model.data_calls, ceiling)  # independent of n
    model.data_calls = 0
    start = time.perf_counter()
    panel._header_clicked(3)
    QApplication.processEvents()
    sort_time = time.perf_counter() - start
    assert model.data_calls <= ceiling, model.data_calls  # sorting never calls data() per comparison
    model.data_calls = 0
    start = time.perf_counter()
    panel.search.setText('fn99')
    panel._apply_filter()
    QApplication.processEvents()
    filter_time = time.perf_counter() - start
    assert model.data_calls <= ceiling, model.data_calls
    assert model.rowCount() == sum(1 for r in vm.rows if 'fn99' in r.search_key)
    limits = {10_000: (0.25, 0.25, 0.25), 100_000: (0.75, 1.0, 0.75)}[n]
    assert reset_time < limits[0] and sort_time < limits[1] and filter_time < limits[2], (
        reset_time, sort_time, filter_time)


def test_sort_keeps_selection_on_the_same_match(panel):
    show(panel, build())
    target = panel.model.row_at(3).match_id
    panel.select_match(target)
    panel.model.sort(0, Qt.SortOrder.AscendingOrder)  # direct model sort: persistent indexes must follow
    assert panel.current_row().match_id == target
    assert [r.match_id for r in panel.selected_rows()] == [target]


def test_forbidden_qt_apis_absent():
    """Proxy sorting, contents-based resizing, rich text and parented threads are banned in the adapter."""
    from pathlib import Path
    source = Path(ui_evidence.__file__).read_text(encoding='utf-8')
    for banned in ('lessThan', 'QSortFilterProxyModel', 'ResizeToContents', 'resizeColumnsToContents',
                   'resizeRowsToContents', 'setHtml', 'setMarkdown', 'RichText', '.terminate('):
        assert banned not in source, banned
    assert not re.search(r'Thread\([^)]*self\.panel', source)


def test_badge_and_focus_colours_meet_contrast():
    from patchtrace.ui_evidence import (
        BADGE_BORDER,
        BADGE_COLORS,
        BADGE_TEXT,
        THEME_BACKGROUND,
        contrast_ratio,
    )
    assert contrast_ratio('#000000', '#ffffff') == pytest.approx(21.0)
    for verdict, fill in BADGE_COLORS.items():
        assert contrast_ratio(BADGE_TEXT, fill) >= 4.5, verdict          # WCAG 1.4.3 text
        assert contrast_ratio(BADGE_BORDER, fill) >= 3.0, verdict        # WCAG 1.4.11 border
        assert contrast_ratio(fill, THEME_BACKGROUND) >= 3.0, verdict    # badge boundary on the dark theme
    assert BADGE_COLORS['contested'] != '#ff0000'


def test_tooltips_never_carry_live_markup(panel):
    """Tooltips are rich text by design (QTipLabel auto-detects); only the registry wrapper may be markup."""
    matches = [gmatch(f'm{i}', f'{0x10 + i:x}', f'{0x20 + i:x}', name) for i, name in enumerate(HOSTILE)]
    show(panel, build(matches=matches, sets=(mset('bindiff', *[bd(0x10 + i, 0x20 + i) for i in range(8)]),)))
    model = panel.model
    for r in range(model.rowCount()):
        for c in range(model.columnCount()):
            tip = model.data(model.index(r, c), Qt.ItemDataRole.ToolTipRole)
            inner = re.sub(r'^<p style="white-space:pre-wrap">|</p>$', '', tip).replace('<br>', '\n')
            assert '<' not in inner and '>' not in inner, inner[:120]
            display = model.data(model.index(r, c))
            assert '\u202e' not in display and '\x1b' not in display


# ---- teardown matrix (hard-problems plan section 4.4) -------------------------------------------------


def gated_loader(gate):
    def loader(request, cancel):
        gate.wait(5)
        return service_api.load_evidence(request, cancel)
    return loader


def test_close_window_while_loading_joins_thread(qtbot, tmp_path, settings):
    for _ in range(5):
        view = MainWindow(ProjectService.sample(tmp_path / f's{_}'), settings, tmp_path / 'profiles')
        qtbot.addWidget(view)
        gate = threading.Event()
        view.evidence.loader = gated_loader(gate)
        view.evidence.auto_probe = False
        view.show()
        view.evidence.action.trigger()
        qtbot.waitUntil(lambda v=view: v.evidence.load_thread is not None, timeout=5000)
        thread = view.evidence.load_thread
        threading.Timer(0.05, gate.set).start()
        view.close()  # closeEvent -> shutdown: cancel + join before the service closes
        assert not ui_evidence.thread_alive(thread)


def test_project_switch_mid_load_drops_old_generation(window, qtbot, tmp_path):
    gate = threading.Event()
    window.evidence.loader = gated_loader(gate)
    window.evidence.auto_probe = False
    window.show()
    window.evidence.action.trigger()
    qtbot.waitUntil(lambda: window.evidence.load_thread is not None, timeout=5000)
    old_generation = window.evidence.generation
    window.evidence.loader = service_api.load_evidence
    window.set_service(ProjectService.sample(tmp_path / 'other'))
    gate.set()
    qtbot.waitUntil(lambda: not window.evidence.panel.loading, timeout=5000)
    assert window.evidence.generation > old_generation
    assert window.evidence.panel.vm.project_id == window.project.id


def test_started_thread_without_reference_survives_gc(qtbot):
    import gc
    gate = threading.Event()
    request = service_api.EvidenceRequest('p', RUN, 0, OLD, NEW, (), ())
    thread = ui_evidence.EvidenceLoadThread(request, gated_loader(gate))
    thread.start()
    del thread
    gc.collect()  # the registry holds it: no 'QThread: Destroyed while thread is still running' abort
    gate.set()
    qtbot.waitUntil(lambda: not any(ui_evidence.thread_alive(t) for t in list(ui_evidence._LIVE_THREADS)),
                    timeout=5000)


def test_panel_deleted_while_thread_runs(qtbot, tmp_path, settings):
    view = MainWindow(ProjectService.sample(tmp_path / 's'), settings, tmp_path / 'profiles')
    gate = threading.Event()
    view.evidence.loader = gated_loader(gate)
    view.evidence.auto_probe = False
    view.evidence.reload()
    thread = view.evidence.load_thread
    assert thread.parent() is None  # never parented: deleting the panel cannot destroy it
    view.evidence.dock.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    gate.set()
    thread.wait()
    view.evidence.shutdown()
    view.service.close()
    view.service = None
    view.deleteLater()


# ---- controller and threads -----------------------------------------------------------------------


@pytest.fixture
def window(qtbot, tmp_path, settings):
    view = MainWindow(ProjectService.sample(tmp_path / 's'), settings, tmp_path / 'profiles')
    qtbot.addWidget(view)
    yield view
    view.evidence.shutdown()
    if view.service:
        view.service.close()
        view.service = None


def open_dock(window, qtbot):
    window.evidence.auto_probe = False
    window.show()
    window.evidence.action.trigger()
    qtbot.waitUntil(lambda: window.evidence.panel.vm.state != 'no-project' and not window.evidence.panel.loading,
                    timeout=5000)


def test_mainwindow_dock_loads_no_engines_and_action_shortcut(window, qtbot):
    assert window.evidence.action.shortcut().toString() == 'Ctrl+Shift+E'
    assert window.evidence.dock.isHidden()
    open_dock(window, qtbot)
    assert window.evidence.panel.vm.state == 'no-engines'


def test_mainwindow_seam_is_minimal():
    from pathlib import Path
    text = (Path(ui_evidence.__file__).parent / 'ui.py').read_text(encoding='utf-8')
    assert 'EvidenceTableModel' not in text and 'EvidenceDelegate' not in text
    seam = [line for line in text.splitlines() if re.search(r'self\.evidence\b(?!_)', line) or 'EvidenceController' in line
            or "hasattr(self, 'evidence')" in line]
    assert len(seam) <= 10, seam  # the coordination budget is <= 15 lines in ui.py


class FakeRun:
    """Stands in for execute_run; records the thread it ran on and returns canned outcomes."""

    def __init__(self, outcomes, gate=None):
        self.outcomes, self.gate, self.thread = outcomes, gate, None

    def __call__(self, request, cancel, *, on_event=None, on_outcome=None):
        self.thread = QThread.currentThread()
        assert QApplication.instance().thread() is not self.thread
        for outcome in self.outcomes:
            if self.gate is not None:
                self.gate.wait(5)
            if on_event:
                on_event(type('E', (), {'engine': outcome.run.engine, 'phase': 'started'})())
            if on_outcome:
                on_outcome(outcome)
        return tuple(self.outcomes)


def real_outcomes(window, tmp_path, engines):
    """Real EngineOutcome objects from the scheduler with fake adapters."""
    from test_evidence_panel_service import GOOD, FakeRz
    sides = {a.side: a.sha256 for a in window.project.artifacts}
    registry = {'rz-diff': FakeRz(GOOD), 'bindiff': FakeRz('import sys; sys.exit(3)')}
    registry['bindiff'].id = 'bindiff'
    request = service_api.RunRequest('p', 0, 1, engines, 1, 60, tmp_path / 'o', tmp_path / 'n',
                                     sides['older'], sides['newer'])
    return service_api.execute_run(request, threading.Event(), registry=registry, env={})


def supported():
    return {'rz-diff': Capability(engine='rz-diff', supported=True, version='0.9.1', path=sys.executable,
                                  supports_json=True),
            'bindiff': Capability(engine='bindiff', supported=True, version='8', path='x', supports_json=False)}


def start(window, qtbot, fake, engines=('rz-diff',)):
    controller = window.evidence
    controller.run_execute = fake
    controller.capabilities = supported()
    controller.panel.set_capabilities(controller.capabilities)
    controller.update_controls()
    controller.start_run({'engines': engines, 'max_parallel': 1, 'timeout_s': 60})
    return controller


def test_run_success_stores_set_on_gui_thread_and_refreshes(window, qtbot, tmp_path, monkeypatch):
    open_dock(window, qtbot)
    seen = []
    original = service_api.persist_outcome

    def spy(service, request, view):
        seen.append(QThread.currentThread() is QApplication.instance().thread())
        return original(service, request, view)
    monkeypatch.setattr(service_api, 'persist_outcome', spy)
    fake = FakeRun(real_outcomes(window, tmp_path, ('rz-diff',)))
    controller = start(window, qtbot, fake)
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=10000)
    qtbot.waitUntil(lambda: controller.panel.vm.engine('rz-diff').state == 'ready', timeout=5000)
    assert seen == [True]
    assert fake.thread is not QApplication.instance().thread()
    assert controller.panel.vm.state in ('ready', 'partial')


def test_run_one_engine_fails_other_result_kept(window, qtbot, tmp_path):
    open_dock(window, qtbot)
    controller = start(window, qtbot, FakeRun(real_outcomes(window, tmp_path, ('rz-diff', 'bindiff'))),
                       ('rz-diff', 'bindiff'))
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=10000)
    qtbot.waitUntil(lambda: controller.panel.vm.engine('rz-diff').state == 'ready', timeout=5000)
    assert controller.outcomes['bindiff'].status == 'failed'
    assert controller.panel.vm.engine('bindiff').state == 'failed'
    rows = {r.engine: r for r in controller.panel.engine_model.rows}
    assert rows['bindiff'].state == 'failed' and 'PT-SECONDARY-RUN' in rows['bindiff'].detail
    assert controller.panel.engine_errors['bindiff'].startswith('Engine: BinDiff')


def test_cancel_discards_and_marks_cancelled(window, qtbot, tmp_path):
    open_dock(window, qtbot)
    from test_evidence_panel_service import GOOD, FakeRz
    sides = {a.side: a.sha256 for a in window.project.artifacts}
    cancel = threading.Event()
    cancel.set()
    request = service_api.RunRequest('p', 0, 1, ('rz-diff',), 1, 60, tmp_path, tmp_path, sides['older'],
                                     sides['newer'])
    outcomes = service_api.execute_run(request, cancel, registry={'rz-diff': FakeRz(GOOD)}, env={})
    controller = start(window, qtbot, FakeRun(outcomes))
    controller.cancel_run()
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=10000)
    assert controller.outcomes['rz-diff'].status == 'cancelled'
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.secondary.store import current_sets
    assert current_sets(EnrichmentStore(window.service.store)) == []


def test_project_switch_during_run_drops_result(window, qtbot, tmp_path):
    open_dock(window, qtbot)
    gate = threading.Event()
    controller = start(window, qtbot, FakeRun(real_outcomes(window, tmp_path, ('rz-diff',)), gate))
    old_service = window.service
    window.set_service(ProjectService.sample(tmp_path / 'other'))
    gate.set()
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=10000)
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.secondary.store import current_sets
    assert current_sets(EnrichmentStore(window.service.store)) == []
    assert old_service is not window.service


def test_run_disabled_while_ghidriff_job_active(window, qtbot):
    open_dock(window, qtbot)
    controller = window.evidence
    controller.panel.set_capabilities(supported())
    controller.panel.engine_checks['rz-diff'].setChecked(True)
    controller.update_controls()
    assert controller.panel.run_button.isEnabled()
    window.worker = object()
    controller.update_controls()
    assert not controller.panel.run_button.isEnabled()
    window.worker = None
    controller.update_controls()


def test_close_window_cancels_and_waits(window, qtbot, tmp_path):
    open_dock(window, qtbot)
    gate = threading.Event()
    controller = start(window, qtbot, FakeRun(real_outcomes(window, tmp_path, ('rz-diff',)), gate))
    thread = controller.run_thread
    threading.Timer(0.2, gate.set).start()
    controller.shutdown()
    assert not thread.isRunning() and controller.threads == []


def test_worker_never_touches_widgets(window, qtbot, tmp_path, monkeypatch):
    open_dock(window, qtbot)
    app_thread = QApplication.instance().thread()
    violations = []
    original_init = QWidget.__init__

    def guarded(self, *args, **kwargs):
        if QThread.currentThread() is not app_thread:
            violations.append(type(self).__name__)
        original_init(self, *args, **kwargs)
    monkeypatch.setattr(QWidget, '__init__', guarded)
    loader_threads = []

    def loader(request, cancel):
        loader_threads.append(QThread.currentThread() is not app_thread)
        assert isinstance(request, service_api.EvidenceRequest)
        return service_api.load_evidence(request, cancel)
    window.evidence.loader = loader
    window.evidence.reload()
    qtbot.waitUntil(lambda: not window.evidence.panel.loading, timeout=5000)
    controller = start(window, qtbot, FakeRun(real_outcomes(window, tmp_path, ('rz-diff',))))
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=10000)
    assert loader_threads and all(loader_threads) and violations == []


def test_stale_generation_result_is_dropped(window, qtbot):
    open_dock(window, qtbot)
    controller = window.evidence
    before = controller.panel.vm
    controller._model_ready(empty_model('failed', error='old'), controller.generation - 1)
    assert controller.panel.vm is before


def test_navigator_link_both_ways(window, qtbot):
    from patchtrace.enrichment.storage import EnrichmentStore, Guard
    from patchtrace.secondary.store import publish_engine_set
    project = window.project
    run = service_api.latest_run(project)
    sides = {a.side: a.sha256 for a in project.artifacts}
    match = next(m for m in project.matches if len(m.older) == 1 and len(m.newer) == 1)
    older, newer = int(match.older[0].address, 16), int(match.newer[0].address, 16)
    match_set = mset('bindiff', bd(older, newer))
    match_set = match_set.model_copy(update={'older_sha256': sides['older'], 'newer_sha256': sides['newer']})
    guard = Guard(project.id, run.id, run.raw_sha256, match_set.file_sha256)
    publish_engine_set(EnrichmentStore(window.service.store), guard, guard, project.revision, match_set)
    open_dock(window, qtbot)
    panel = window.evidence.panel
    assert panel.vm.state in ('ready', 'partial'), panel.vm.error
    assert panel.select_match(match.id)
    panel.activate_current()
    assert window.current_match().id == match.id
    other = next(m for m in project.matches if m.id != match.id)
    window.evidence.follow_match(other)
    assert panel.current_row().match_id == other.id


def test_engine_run_thread_reports_failure_class_only(qtbot, tmp_path):
    def boom(request, cancel, **kw):
        raise RuntimeError('secret-token')
    request = service_api.RunRequest('p', 0, 7, ('rz-diff',), 1, 60, tmp_path, tmp_path, OLD, NEW, RUN)
    thread = EngineRunThread(request, boom)
    with qtbot.waitSignal(thread.run_failed, timeout=5000) as blocker:
        thread.start()
    thread.wait()
    assert blocker.args == ['PT-SECONDARY-RUN: RuntimeError', 7]


def test_table_model_empty_is_safe():
    model = EvidenceTableModel()
    assert model.rowCount() == 0 and model.data(model.index(0, 0)) is None
    assert model.rowCount(QModelIndex()) == 0


def test_controller_without_project(qtbot, settings, tmp_path):
    empty = MainWindow(None, settings, tmp_path / 'profiles')
    qtbot.addWidget(empty)
    assert isinstance(empty.evidence, EvidenceController)
    assert empty.evidence.panel.status.text() == STATE_TEXT['no-project']
    empty.evidence.shutdown()
