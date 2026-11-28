"""Current Calls worker/canvas ownership, font scaling and bounded-layout fallback."""
from __future__ import annotations

import threading

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QGraphicsPathItem, QGraphicsRectItem
from qt_support import join_gui_threads  # noqa: F401
from test_ui_graph_panel import select_change, settle, start, status

from patchtrace.callgraph import layout as lay
from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph.limits import GraphError


def test_layout_runs_on_query_worker_and_routes_reach_the_current_canvas(qtbot, monkeypatch):
    original, threads = pd.layout_view, []

    def observed(*args, **kwargs):
        threads.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(pd, 'layout_view', observed)
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    assert threads and threading.get_ident() not in threads
    diagram, canvas = controller.found.diagram, controller.panel.canvas
    assert isinstance(diagram, lay.Layout)
    sx, sy = (v / unit for v, unit in zip(canvas.node_dimensions(), (lay.NODE_W, lay.NODE_H), strict=True))
    expected = sorted(tuple((x * sx, y * sy) for x, y in edge.points) for edge in diagram.edges)
    paths = [item.path() for item in canvas.scene().items() if isinstance(item, QGraphicsPathItem)]
    actual = sorted(tuple((path.elementAt(i).x, path.elementAt(i).y) for i in range(path.elementCount()))
                    for path in paths)
    assert actual == expected
    assert len(controller.panel.minimap.model.dots) == len(diagram.nodes)


def test_large_font_boxes_do_not_overlap_and_metric_change_rescales_without_layout(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    canvas, found = controller.panel.canvas, controller.found
    old_dimensions = canvas.node_dimensions()
    canvas.focus_node(found.focus_id)
    canvas.toggle_selected(found.focus_id)

    def forbidden(*args, **kwargs):
        raise AssertionError('font scaling must reuse the accepted worker geometry')

    monkeypatch.setattr(pd, 'layout_view', forbidden)
    font = QFont(canvas.font())
    font.setPointSize(32)
    canvas.setFont(font)
    boxes = {item.data(0): item.rect() for item in canvas.scene().items()
             if isinstance(item, QGraphicsRectItem) and item.data(0)}
    dimensions = canvas.node_dimensions()
    assert dimensions[0] > old_dimensions[0] and dimensions[1] > old_dimensions[1]
    assert all((rect.width(), rect.height()) == dimensions for rect in boxes.values())
    for node in found.diagram.nodes:
        for other in found.diagram.nodes:
            if node.id != other.id:
                assert not boxes[node.id].intersects(boxes[other.id])
    assert controller.found is found and canvas.focused_key == found.focus_id
    assert canvas.selected_keys == frozenset({found.focus_id})
    assert len(controller.panel.minimap.model.dots) == len(boxes)
    QTest.keyClick(canvas, Qt.Key.Key_Right)
    assert canvas.focused_key in boxes


def test_diagram_failure_clears_old_geometry_but_keeps_current_table_tree_and_dot(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    before = controller.found
    before_dot = pd.dot_text(controller.data, before)

    def timeout(*args, **kwargs):
        raise GraphError('PT-GRAPH-LAYOUT-LIMIT', 'the diagram layout reached its time limit')

    monkeypatch.setattr(pd, 'layout_view', timeout)
    controller._query()
    settle(qtbot, controller)
    assert controller.found.view == before.view and controller.found.rows == before.rows
    assert controller.panel.neighbours.table_model.rowCount() > 0 and controller.panel.tree.topLevelItemCount() == 1
    assert controller.panel.canvas.node_count == 0 and not controller.panel.minimap.isVisible()
    assert 'time limit' in controller.panel.diagram_note.full_text()
    assert pd.dot_text(controller.data, controller.found) == before_dot
    assert controller.panel.buttons['export_dot'].isEnabled()


def test_canvas_limit_also_clears_the_previous_diagram_only(qtbot):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    found = controller.found
    controller.panel.canvas.max_nodes = 1
    controller._fill_diagram(found)
    assert controller.panel.canvas.node_count == 0 and controller.found is found
    assert controller.panel.neighbours.table_model.rowCount() > 0
    assert 'Too large to draw' in controller.panel.diagram_note.full_text()


def test_typed_layout_cancellation_preserves_the_accepted_view(qtbot):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    found, scene = controller.found, controller.panel.canvas.scene()
    controller.loading = True
    controller._queried(pd.Failure('PT-GRAPH-CANCEL', 'cancelled'), controller.epoch)
    assert controller.found is found and controller.panel.canvas.scene() is scene
    assert controller.panel.state.kind == 'cancelled' and not controller.loading


def test_revision_change_while_layout_is_running_rejects_result(qtbot, monkeypatch):
    controller, project, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    found, scene = controller.found, controller.panel.canvas.scene()
    original, entered, release = pd.layout_view, threading.Event(), threading.Event()

    def deferred(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(pd, 'layout_view', deferred)
    controller._query()
    qtbot.waitUntil(entered.is_set)
    project.revision += 1
    release.set()
    settle(qtbot, controller)
    assert controller.found is found and controller.panel.canvas.scene() is scene
    assert controller.panel.state.kind == 'stale' and 'project changed' in status(controller)


def test_cancel_running_layout_preserves_view_and_allows_the_next_query(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    found, scene = controller.found, controller.panel.canvas.scene()
    original, entered = pd.layout_view, threading.Event()

    def waits(*args, **kwargs):
        entered.set()
        assert kwargs['cancel'].wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(pd, 'layout_view', waits)
    controller._query()
    qtbot.waitUntil(entered.is_set)
    controller.cancel()
    settle(qtbot, controller)
    assert controller.found is found and controller.panel.canvas.scene() is scene
    assert controller.panel.state.kind == 'cancelled'
    monkeypatch.setattr(pd, 'layout_view', original)
    controller._query()
    settle(qtbot, controller)
    assert controller.found is not found and controller.panel.state.kind != 'cancelled'


def test_late_layout_after_project_switch_cannot_restore_the_old_graph(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    original, entered, release = pd.layout_view, threading.Event(), threading.Event()

    def deferred(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(pd, 'layout_view', deferred)
    controller._query()
    qtbot.waitUntil(entered.is_set)
    controller.project_changed(None)
    release.set()
    settle(qtbot, controller)
    assert controller.found is None and controller.panel.canvas.node_count == 0
    assert controller.panel.state.kind == 'no-project'
