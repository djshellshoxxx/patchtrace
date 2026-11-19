"""The real Calls canvas consumes bounded layout results from its query worker."""
from __future__ import annotations

import threading

from PySide6.QtGui import QFont
from test_ui_graph_panel import select_change, start

from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph.layout import Layout
from patchtrace.callgraph.limits import GraphError


def test_layout_runs_on_worker_and_gui_only_consumes_its_result(qtbot, monkeypatch):
    owner = threading.get_ident()
    calls = []
    original = pd.layout_view

    def observed(*args, **kwargs):
        calls.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(pd, 'layout_view', observed)
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    assert calls and all(ident != owner for ident in calls)
    found = controller.found
    assert isinstance(found.diagram, Layout)
    assert controller.panel.canvas.node_count == len(found.diagram.nodes)
    assert controller.panel.canvas.edge_count == len(found.diagram.edges)
    assert set(controller.panel.canvas._points) == set(pd.positions(found))
    before = len(calls)
    controller._fill_diagram(found)
    assert len(calls) == before


def test_layout_refusal_leaves_neighbours_and_dot_available(qtbot, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise GraphError('PT-GRAPH-LIMIT', 'authored layout refusal')

    monkeypatch.setattr(pd, 'layout_view', refuse)
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    assert isinstance(controller.found.diagram, pd.Failure)
    assert controller.panel.neighbours.table_model.rowCount() > 0
    assert controller.panel.canvas.node_count == 0
    assert 'PT-GRAPH-LIMIT' in controller.panel.diagram_note.full_text()
    assert 'digraph' in pd.dot_text(controller.data, controller.found)
    assert controller.panel.state.kind != 'error'


def test_layout_omissions_are_visible_without_cutting_query_evidence(qtbot, monkeypatch):
    original = pd.layout_view

    def tiny(*args, **kwargs):
        return original(*args, **{**kwargs, 'max_nodes': 1})

    monkeypatch.setattr(pd, 'layout_view', tiny)
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    found = controller.found
    assert len(found.view.nodes) > 1
    assert controller.panel.canvas.node_count == 1
    assert controller.panel.neighbours.table_model.rowCount() > 0
    assert 'nodes beyond the display limit' in controller.panel.diagram_note.full_text()
    assert len(pd.dot_export(controller.data, found).newer.nodes) == len(found.view.nodes)


def test_larger_canvas_font_retains_nonoverlapping_node_boxes(qtbot):
    controller, *_ = start(qtbot, fixture='cycle_hub')
    names = controller.panel.changes.table_model
    match = names.row_at(0).match_id
    controller._set_seed(match, remember=False)
    from test_ui_graph_panel import settle
    settle(qtbot, controller)
    canvas = controller.panel.canvas
    font = QFont(canvas.font())
    font.setPointSize(32)
    canvas.setFont(font)
    controller._fill_diagram(controller.found)
    groups = {}
    for key, layer in pd.layers(controller.found).items():
        groups.setdefault(layer, []).append(canvas._boxes[key].rect())
    assert sum(map(len, groups.values())) > 1
    for boxes in groups.values():
        boxes.sort(key=lambda box: box.y())
        assert all(a.bottom() <= b.top() for a, b in zip(boxes, boxes[1:], strict=False))
