# ruff: noqa: F811
"""Calls panel inspection slice in Qt: DOT export through a user-chosen path, call-site reveal with the anchor to the
caller's code, and the diagram minimap (docs/specs/panels/graph-inspection.md). Offscreen; synthetic data only."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads  # noqa: F401
from test_ui_graph_panel import audit, select_change, settle, start, status

from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph.call_sites import NO_CODE_TEXT, call_site_view
from patchtrace.callgraph.view_model import CALLSITE_MISSING
from patchtrace.gui.anchors import NavResult

SITE_TAB, DIAGRAM_TAB = 4, 3


class Dialog:
    """Stands in for the native save dialog: records every call and answers with the chosen path."""

    def __init__(self, answer: str = '') -> None:
        self.answer, self.calls = answer, []

    def __call__(self, _parent, name: str) -> str:
        self.calls.append(name)
        return self.answer


def seeded(qtbot, label: str = 'DriverEntry'):
    controller, project, nav, shell = start(qtbot)
    select_change(qtbot, controller, label)
    return controller, project, nav, shell


def select_edge(controller, caller: str, callee: str) -> None:
    table = controller.panel.edges
    model = table.table_model
    for row in range(model.rowCount()):
        texts = model.texts_at(row)
        if texts[0] == caller and texts[1] == callee:
            table.selectRow(row)
            return
    raise AssertionError(f'no edge {caller} -> {callee}: {[model.texts_at(r) for r in range(model.rowCount())]}')


def put_code(controller, name: str, code: str) -> None:
    """Give the project copy the workers read a stored decompiled text for a function."""
    for match in controller.project_copy.matches:
        for record in (*match.older, *match.newer):
            if record.name == name:
                record.code = code


# ---- DOT export -------------------------------------------------------------------------------------------------

def test_export_is_disabled_until_a_graph_is_shown_and_nothing_is_written_silently(qtbot, tmp_path):
    controller, *_ = start(qtbot)
    dialog = Dialog(str(tmp_path / 'x.dot'))
    controller.save_dialog = dialog
    button = controller.panel.buttons['export_dot']
    assert not button.isEnabled() and dialog.calls == []
    select_change(qtbot, controller, 'DriverEntry')
    assert button.isEnabled() and dialog.calls == [] and list(tmp_path.iterdir()) == []


def test_export_writes_the_visible_graph_only_to_the_chosen_path(qtbot, tmp_path):
    controller, _p, _n, shell = seeded(qtbot)
    target = tmp_path / 'chosen.dot'
    dialog = Dialog(str(target))
    controller.save_dialog = dialog
    controller.panel.buttons['export_dot'].click()
    settle(qtbot, controller)
    qtbot.waitUntil(target.exists, timeout=5000)
    settle(qtbot, controller)
    assert target.read_text(encoding='utf-8') == pd.dot_text(controller.data, controller.found)
    assert len(dialog.calls) == 1 and dialog.calls[0].startswith('callgraph-') and dialog.calls[0].endswith('.dot')
    assert sorted(p.name for p in tmp_path.iterdir()) == ['chosen.dot']  # no temp file left behind
    assert any('chosen.dot' in s for s in shell.statuses)


def test_cancelled_dialog_writes_nothing_and_says_so(qtbot, tmp_path):
    controller, _p, _n, shell = seeded(qtbot)
    controller.save_dialog = Dialog('')
    controller.export_dot()
    settle(qtbot, controller)
    assert list(tmp_path.iterdir()) == [] and any('Nothing was written' in s for s in shell.statuses)
    assert controller.panel.state.kind in ('ready', 'partial')


def test_export_replaces_a_file_the_dialog_already_confirmed(qtbot, tmp_path):
    controller, *_ = seeded(qtbot)
    target = tmp_path / 'old.dot'
    target.write_text('old', encoding='utf-8')
    controller.save_dialog = Dialog(str(target))
    controller.export_dot()
    qtbot.waitUntil(lambda: target.read_text(encoding='utf-8') != 'old', timeout=5000)
    assert target.read_text(encoding='utf-8').startswith('// patchtrace call graph export')


def test_oversize_export_is_refused_before_any_dialog(qtbot, tmp_path, monkeypatch):
    from patchtrace.callgraph import export_json
    controller, _p, _n, shell = seeded(qtbot)
    dialog = Dialog(str(tmp_path / 'big.dot'))
    controller.save_dialog = dialog
    monkeypatch.setattr(export_json, 'MAX_EXPORT_BYTES', 50)
    controller.export_dot()
    settle(qtbot, controller)
    assert dialog.calls == [] and list(tmp_path.iterdir()) == []
    assert any('PT-GRAPH-EXPORT' in s for s in shell.statuses)
    assert controller.found is not None  # the call view is untouched


def test_unwritable_target_is_reported_and_leaves_the_view_alone(qtbot, tmp_path):
    controller, _p, _n, shell = seeded(qtbot)
    controller.save_dialog = Dialog(str(tmp_path / 'missing-dir' / 'x.dot'))
    controller.export_dot()
    qtbot.waitUntil(lambda: any('PT-GRAPH-EXPORT' in s for s in shell.statuses), timeout=5000)
    assert controller.found is not None and not (tmp_path / 'missing-dir').exists()


def test_export_result_after_a_project_switch_never_opens_the_dialog(qtbot, tmp_path):
    controller, *_ = seeded(qtbot)
    dialog = Dialog(str(tmp_path / 'late.dot'))
    controller.save_dialog = dialog
    old = controller.epoch
    controller.project_changed(None)
    controller._dot_ready('digraph x {}\n', old)
    assert dialog.calls == [] and list(tmp_path.iterdir()) == []


def test_hostile_labels_reach_the_file_as_escaped_text(qtbot, tmp_path):
    controller, *_ = start(qtbot, 'hostile_names')
    select_change(qtbot, controller, 'Dispatch')
    target = tmp_path / 'h.dot'
    controller.save_dialog = Dialog(str(target))
    controller.export_dot()
    qtbot.waitUntil(target.exists, timeout=5000)
    settle(qtbot, controller)
    text = target.read_text(encoding='utf-8')
    assert '\x00' not in text and '‮' not in text and '\r' not in text and text.count('digraph') == 1


# ---- call sites -------------------------------------------------------------------------------------------------

def test_call_sites_tab_lists_the_edges_of_the_seed_with_addresses(qtbot):
    controller, *_ = seeded(qtbot)
    model = controller.panel.edges.table_model
    assert model.rowCount() >= 1
    row = [model.texts_at(r) for r in range(model.rowCount())]
    assert any(t[0] == 'DriverEntry' and t[2] == '0x140001000' for t in row)
    assert controller.panel.tabs.tabText(SITE_TAB) == 'Call sites'
    assert not controller.panel.buttons['callsite'].isEnabled()  # no edge selected yet


def test_selecting_an_edge_and_show_call_site_reveals_the_matching_lines(qtbot):
    controller, *_ = seeded(qtbot)
    put_code(controller, 'DriverEntry', 'void DriverEntry() {\n  FUN_140001640(1);\n  FUN_140001640(2);\n}')
    controller.panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    button = controller.panel.buttons['callsite']
    assert button.isEnabled()
    button.click()
    qtbot.waitUntil(lambda: controller.panel.sites.table_model.rowCount() == 2, timeout=5000)
    model = controller.panel.sites.table_model
    assert [model.texts_at(r)[0] for r in range(2)] == ['2', '3']
    assert controller.panel.site_note.full_text() == '2 text matches in decompiled code'


def test_missing_call_site_and_missing_text_use_the_exact_copy(qtbot):
    controller, *_ = seeded(qtbot)
    controller.panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    controller.show_call_site()
    qtbot.waitUntil(lambda: controller.panel.site_note.full_text() == NO_CODE_TEXT, timeout=5000)
    put_code(controller, 'DriverEntry', 'void DriverEntry() { other(); }')
    controller.show_call_site()
    qtbot.waitUntil(lambda: controller.panel.site_note.full_text() == CALLSITE_MISSING, timeout=5000)
    assert controller.panel.sites.table_model.rowCount() == 0


def test_enter_on_an_edge_row_reveals_the_call_site(qtbot):
    controller, *_ = seeded(qtbot)
    put_code(controller, 'DriverEntry', 'FUN_140001640();')
    controller.panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    controller.panel.edges.setFocus()
    QTest.keyClick(controller.panel.edges, Qt.Key.Key_Return)
    qtbot.waitUntil(lambda: controller.panel.sites.table_model.rowCount() == 1, timeout=5000)


def test_open_on_an_edge_emits_the_caller_function_anchor(qtbot):
    controller, _p, nav, _s = seeded(qtbot)
    controller.panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    controller.open()
    anchor = nav.anchors[-1]
    assert (anchor.kind, anchor.side, anchor.run_id, anchor.revision, anchor.origin) == (
        'function', 'newer', 'run-1', 1, 'graph')
    assert anchor.label == 'DriverEntry'
    nav.result = NavResult.not_found('x', 'run-1')
    before = controller.panel.edges.currentIndex().row()
    controller.open()
    assert controller.panel.edges.currentIndex().row() == before


def test_late_call_site_result_for_another_edge_or_epoch_is_dropped(qtbot):
    controller, *_ = seeded(qtbot)
    put_code(controller, 'DriverEntry', 'FUN_140001640();')
    controller.panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    view = call_site_view('a();\nb();', 'a')
    controller._sites_ready(view, controller.epoch, 'some-other-edge')
    assert controller.panel.sites.table_model.rowCount() == 0
    controller._sites_ready(view, controller.epoch - 1, controller.current_edge().edge_id)
    assert controller.panel.sites.table_model.rowCount() == 0


def test_project_switch_empties_the_call_site_views(qtbot):
    controller, *_ = seeded(qtbot)
    put_code(controller, 'DriverEntry', 'FUN_140001640();')
    controller.panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    controller.show_call_site()
    qtbot.waitUntil(lambda: controller.panel.sites.table_model.rowCount() == 1, timeout=5000)
    controller.project_changed(None)
    assert controller.panel.edges.table_model.rowCount() == 0 and controller.panel.sites.table_model.rowCount() == 0
    assert not controller.panel.buttons['callsite'].isEnabled() and not controller.panel.buttons['export_dot'].isEnabled()


# ---- minimap ----------------------------------------------------------------------------------------------------

def test_minimap_shows_one_dot_per_node_and_describes_the_viewport(qtbot):
    controller, *_ = seeded(qtbot)
    panel = controller.panel
    panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    QApplication.processEvents()
    assert panel.minimap.isVisibleTo(panel)
    assert len(panel.minimap.model.dots) == panel.canvas.node_count
    assert panel.minimap.accessibleName() == 'Diagram minimap'
    assert panel.minimap.accessibleDescription().startswith('Viewport covers ')


def test_minimap_is_empty_and_hidden_without_a_graph(qtbot):
    controller, *_ = start(qtbot)
    controller.panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    assert not controller.panel.minimap.isVisibleTo(controller.panel)
    assert controller.panel.minimap.model.dots == ()


def test_minimap_click_centres_the_canvas_on_that_point(qtbot):
    controller, *_ = seeded(qtbot)
    panel = controller.panel
    panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    panel.canvas.set_zoom(2.0)
    QApplication.processEvents()
    model = panel.minimap.model
    x, y = model.dots[0]
    QTest.mouseClick(panel.minimap, Qt.MouseButton.LeftButton, pos=QPoint(round(x), round(y)))
    centre = panel.canvas.mapToScene(panel.canvas.viewport().rect().center())
    scene = panel.canvas.sceneRect()
    wanted_x = min(max(panel.canvas.node_center(next(iter(panel.canvas._nodes))).x(), scene.left()), scene.right())
    assert abs(centre.x() - wanted_x) < scene.width() * 0.2


def test_minimap_keyboard_pans_zooms_and_fits_the_canvas(qtbot):
    controller, *_ = seeded(qtbot)
    panel = controller.panel
    panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    panel.canvas.set_zoom(3.0)
    panel.canvas.centerOn(panel.canvas.sceneRect().center())
    QApplication.processEvents()
    panel.minimap.setFocus()
    before = panel.canvas.mapToScene(panel.canvas.viewport().rect().center()).x()
    QTest.keyClick(panel.minimap, Qt.Key.Key_Right)
    after = panel.canvas.mapToScene(panel.canvas.viewport().rect().center()).x()
    assert after > before
    zoom = panel.canvas.zoom
    QTest.keyClick(panel.minimap, Qt.Key.Key_Plus)
    assert panel.canvas.zoom > zoom
    QTest.keyClick(panel.minimap, Qt.Key.Key_Minus)
    QTest.keyClick(panel.minimap, Qt.Key.Key_0)
    assert panel.minimap.model.coverage_percent >= 90


def test_minimap_toggle_button_and_m_key_show_and_hide_it(qtbot):
    controller, *_ = seeded(qtbot)
    panel = controller.panel
    panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    QApplication.processEvents()
    assert panel.minimap_toggle.isChecked() and panel.minimap.isVisibleTo(panel)
    panel.minimap_toggle.click()
    assert not panel.minimap.isVisibleTo(panel)
    panel.canvas.setFocus()
    QTest.keyClick(panel.canvas, Qt.Key.Key_M)
    assert panel.minimap_toggle.isChecked() and panel.minimap.isVisibleTo(panel)


def test_minimap_never_writes_state_or_opens_windows(qtbot):
    controller, _p, nav, shell = seeded(qtbot)
    panel = controller.panel
    panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    seed, history = controller.seed, list(controller.history)
    QTest.mouseClick(panel.minimap, Qt.MouseButton.LeftButton, pos=QPoint(5, 5))
    QTest.keyClick(panel.minimap, Qt.Key.Key_Down)
    assert (controller.seed, controller.history, nav.anchors, shell.copied) == (seed, history, [], [])
    assert [w for w in QApplication.topLevelWidgets() if w.isVisible() and w is not panel] == []


# ---- accessibility and tooltips -------------------------------------------------------------------------------------

def test_new_controls_are_named_tipped_and_audit_clean_in_every_state(qtbot):
    controller, *_ = start(qtbot)
    panel = controller.panel
    assert audit(panel) == []
    select_change(qtbot, controller, 'DriverEntry')
    panel.tabs.setCurrentIndex(SITE_TAB)
    select_edge(controller, 'DriverEntry', 'FUN_140001640')
    panel.tabs.setCurrentIndex(DIAGRAM_TAB)
    assert audit(panel) == []
    for widget in (panel.buttons['callsite'], panel.buttons['export_dot'], panel.minimap_toggle, panel.minimap,
                   panel.edges, panel.sites):
        assert widget.accessibleName() and 'Source:' in widget.whatsThis(), widget.objectName()
    assert panel.buttons['export_dot'].accessibleName() == 'Export DOT file'
    assert panel.buttons['callsite'].accessibleName() == 'Show call site'
    controller.project_changed(None)
    assert audit(panel) == []
    assert status(controller)


def test_tab_order_reaches_the_new_controls_from_the_keyboard(qtbot):
    controller, *_ = seeded(qtbot)
    panel = controller.panel
    for widget in (panel.buttons['callsite'], panel.buttons['export_dot'], panel.minimap_toggle, panel.edges,
                   panel.sites, panel.minimap):
        assert widget.focusPolicy() != Qt.FocusPolicy.NoFocus, widget.objectName()


def test_the_new_tips_are_unique_and_complete():
    from patchtrace.callgraph.panel import PANEL
    for tip_id in ('graph.callsite', 'graph.export_dot', 'graph.minimap', 'graph.edges',
                   'graph.callsites'):
        entry = PANEL.tips[tip_id]
        assert entry.what and entry.why and entry.effect and entry.source and '<' not in entry.what + entry.why
    whats = [e.what for e in PANEL.tips.values()]
    assert len(whats) == len(set(whats))


def test_export_path_is_in_the_status_only_as_a_file_name(qtbot, tmp_path):
    controller, _p, _n, shell = seeded(qtbot)
    target = Path(tmp_path) / 'name.dot'
    controller.save_dialog = Dialog(str(target))
    controller.export_dot()
    qtbot.waitUntil(lambda: any('name.dot' in s for s in shell.statuses), timeout=5000)
    assert not any(str(tmp_path) in s for s in shell.statuses)
