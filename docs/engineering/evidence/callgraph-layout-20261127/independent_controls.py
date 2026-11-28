"""Independent bounded controls against frozen layout 4448f4a9; temporary review file."""
from __future__ import annotations

import random
import threading
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QGraphicsPathItem, QGraphicsRectItem
from qt_support import join_gui_threads  # noqa: F401
from test_ui_graph_panel import names, select_change, settle, start

from patchtrace.callgraph import layout as lay
from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph.limits import GraphError


@pytest.mark.parametrize('seed', range(24))
def test_independent_random_cyclic_endpoint_and_geometry_oracle(seed):
    rng = random.Random(9000 + seed)
    nodes = [f'k{i:02d}' for i in range(26)]
    edges = [(nodes[0], node) for node in nodes[1:]]
    edges += [tuple(rng.choices(nodes, k=2)) for _ in range(90)]
    edges += [(node, node) for node in nodes[::5]]
    result = lay.layout_graph(nodes, edges, nodes[0])
    assert not result.notes
    assert {(edge.src, edge.dst) for edge in result.edges} == set(edges)
    boxes = {node.id: node for node in result.nodes}
    assert set(boxes) == set(nodes)
    for left in boxes.values():
        assert 0 <= left.x < left.x + left.w <= result.width
        assert 0 <= left.y < left.y + left.h <= result.height
        for right in boxes.values():
            if left.id != right.id:
                assert (left.x + left.w <= right.x or right.x + right.w <= left.x
                        or left.y + left.h <= right.y or right.y + right.h <= left.y)
    for edge in result.edges:
        source, target = boxes[edge.src], boxes[edge.dst]
        first, last = edge.points[0], edge.points[-1]
        assert 2 <= len(edge.points) <= 16
        assert all(0 <= x <= result.width and 0 <= y <= result.height for x, y in edge.points)
        if edge.src == edge.dst:
            assert edge.kind == 'self'
            assert first[0] == last[0] == source.x + source.w
            assert source.y < first[1] < last[1] < source.y + source.h
        else:
            assert first[1] == source.y + source.h / 2
            assert last[1] == target.y + target.h / 2
            if source.layer < target.layer:
                assert edge.kind == 'forward' and first[0] == source.x + source.w and last[0] == target.x
            elif source.layer > target.layer:
                assert edge.kind == 'back' and first[0] == source.x and last[0] == target.x + target.w
            else:
                assert edge.kind == 'same-layer'
                assert first[0] == source.x + source.w and last[0] == target.x + target.w
    rng.shuffle(nodes)
    rng.shuffle(edges)
    assert lay.layout_graph(iter(nodes), iter(edges + edges), 'k00') == result


@pytest.mark.parametrize('dummy_cap', [0, 1, 3, 20, 20_000])
def test_independent_routes_only_drop_spanning_edges_under_dummy_pressure(dummy_cap):
    nodes = ['s'] + [f'l{i}' for i in range(1, 5)] + [f'r{i}' for i in range(1, 5)]
    edges = [('l1', 's'), ('s', 'r1')]
    edges += [(f'l{i + 1}', f'l{i}') for i in range(1, 4)]
    edges += [(f'r{i}', f'r{i + 1}') for i in range(1, 4)]
    edges += [('l4', 'r4'), ('l3', 'r3'), ('l2', 'r2'), ('s', 's')]
    result = lay.layout_graph(nodes, edges, 's', max_dummies=dummy_cap)
    layers = {node.id: node.layer for node in result.nodes}
    kept = {(edge.src, edge.dst) for edge in result.edges}
    assert kept <= set(edges)
    assert all(abs(layers[src] - layers[dst]) > 1 for src, dst in set(edges) - kept)
    assert sum(max(0, abs(layers[src] - layers[dst]) - 1) for src, dst in kept) <= dummy_cap
    assert sum(note.dropped for note in result.notes if note.kind == 'long-edges') == len(set(edges) - kept)


def test_new_seed_diagram_failure_never_keeps_previous_seed_scene(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    old_found = controller.found
    old_scene = controller.panel.canvas.scene()
    other = next(name for name in names(controller.panel.changes) if name != 'DriverEntry')

    def deadline(*_args, **_kwargs):
        raise GraphError('PT-GRAPH-LAYOUT-LIMIT', 'independent deadline refusal')

    monkeypatch.setattr(pd, 'layout_view', deadline)
    select_change(qtbot, controller, other)
    found = controller.found
    assert found is not None and found.spec.match_id != old_found.spec.match_id
    assert controller.panel.canvas.scene() is not old_scene
    assert controller.panel.canvas.node_count == controller.panel.canvas.edge_count == 0
    assert controller.panel.neighbours.table_model.rowCount() == len(found.rows)
    assert controller.panel.tree.topLevelItemCount() == 1
    assert pd.dot_export(controller.data, found).match_id == found.spec.match_id
    assert controller.panel.buttons['export_dot'].isEnabled()
    assert 'independent deadline refusal' in controller.panel.diagram_note.full_text()


def test_late_success_ignoring_cancel_cannot_replace_newer_query(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    before = controller.found
    original = pd.layout_view
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    calls = 0
    lock = threading.Lock()

    def delayed(view, seed, **kwargs):
        nonlocal calls
        with lock:
            calls += 1
            first = calls == 1
        if first:
            entered.set()
            assert release.wait(5)
            try:
                return original(view, seed, cancel=lambda: False)
            finally:
                finished.set()
        return original(view, seed, **kwargs)

    monkeypatch.setattr(pd, 'layout_view', delayed)
    controller._query()
    try:
        qtbot.waitUntil(entered.is_set)
        controller.panel.depth.setValue(2)
        qtbot.waitUntil(lambda: controller.found is not before, timeout=5000)
        accepted, scene = controller.found, controller.panel.canvas.scene()
        assert accepted.spec.depth == 2
        release.set()
        qtbot.waitUntil(finished.is_set)
        qtbot.wait(25)
        assert controller.found is accepted and controller.panel.canvas.scene() is scene
    finally:
        release.set()
    settle(qtbot, controller)


def test_actual_panel_render_and_repeated_font_scale_keep_current_geometry(qtbot, monkeypatch):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    panel, accepted = controller.panel, controller.found
    panel.tabs.setCurrentWidget(panel.diagram)
    canvas = panel.canvas
    canvas.focus_node(accepted.focus_id)
    canvas.toggle_selected(accepted.focus_id)

    def forbidden(*_args, **_kwargs):
        raise AssertionError('font changes may not relaunch layout')

    monkeypatch.setattr(pd, 'layout_view', forbidden)
    for size in [8, 12, 28, 48, 14]:
        font = QFont(canvas.font())
        font.setPointSize(size)
        canvas.setFont(font)
        QApplication.processEvents()
        boxes = [item.rect() for item in canvas.scene().items()
                 if isinstance(item, QGraphicsRectItem) and item.data(0)]
        assert len(boxes) == len(accepted.diagram.nodes)
        assert all((box.width(), box.height()) == canvas.node_dimensions() for box in boxes)
        assert all(not box.intersects(other) for i, box in enumerate(boxes) for other in boxes[i + 1:])
        paths = [item for item in canvas.scene().items() if isinstance(item, QGraphicsPathItem)]
        assert len(paths) == len(accepted.diagram.edges)
        assert canvas.focused_key == accepted.focus_id
        assert canvas.selected_keys == frozenset({accepted.focus_id})
        assert len(panel.minimap.model.dots) == len(boxes)
    QTest.keyClick(canvas, Qt.Key.Key_Right)
    assert canvas.focused_key in {node.id for node in accepted.diagram.nodes}
    image = panel.grab()
    assert not image.isNull()
    assert image.save(str(Path('/workspace/scratch/e3f205d85f15/layout-evidence/independent-panel.png')))
