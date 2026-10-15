"""Stress: GraphCanvas swapped at its maximum size (2,000 nodes, 8,000 edges) and back (GUI plan 8.4, F6b).

A swap builds a fresh scene and deletes the old one; these tests check the counts, the focus and selection that
survive a swap, the refusal of an oversized graph that keeps the old one on screen, and that no old scene leaks."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication, QGraphicsScene
from qt_support import flush_deferred_deletes, join_gui_threads  # noqa: F401

from patchtrace.gui import graph_view as gv
from patchtrace.gui.graph_view import GraphEdgeView, GraphNodeView, GraphTooLargeError
from patchtrace.gui.qt.canvas import GraphCanvas
from patchtrace.gui.registry import GRAPH_EDGES_MAX, GRAPH_NODES_MAX

COLUMNS = 50
OFFSETS = (1, 2, 50, 51)


def grid(count: int, offset_pool: tuple[int, ...] = OFFSETS) -> tuple[list[GraphNodeView], list[GraphEdgeView]]:
    """A torus-like grid: every node has four outgoing edges to nearby nodes."""
    nodes = [GraphNodeView(f'n{i}', f'node {i}', (i % COLUMNS) * 120.0, (i // COLUMNS) * 90.0,
                           'plain' if i % 3 else 'error') for i in range(count)]
    edges = [GraphEdgeView(f'n{i}', f'n{(i + step) % count}') for i in range(count) for step in offset_pool]
    return nodes, edges


@pytest.fixture
def canvas(qtbot):
    view = GraphCanvas(max_nodes=GRAPH_NODES_MAX, max_edges=GRAPH_EDGES_MAX)
    qtbot.addWidget(view)
    view.resize(800, 600)
    view.show()
    QApplication.processEvents()
    return view


def scenes_of(view: GraphCanvas) -> int:
    flush_deferred_deletes()
    return len(view.findChildren(QGraphicsScene))


def test_the_maximum_graph_loads_with_every_node_and_edge(canvas):
    nodes, edges = grid(GRAPH_NODES_MAX)
    assert len(edges) == GRAPH_EDGES_MAX
    canvas.set_graph(nodes, edges)
    assert (canvas.node_count, canvas.edge_count) == (GRAPH_NODES_MAX, GRAPH_EDGES_MAX)
    assert canvas.level == gv.detail_level(canvas.zoom)
    assert canvas.zoom <= gv.ZOOM_MAX and canvas.zoom >= gv.ZOOM_MIN


def test_swapping_between_maximum_and_small_graphs_ten_times_leaks_no_scene(canvas):
    big, big_edges = grid(GRAPH_NODES_MAX)
    small, small_edges = grid(500)
    for round_ in range(10):
        nodes, edges = (big, big_edges) if round_ % 2 == 0 else (small, small_edges)
        canvas.set_graph(nodes, edges)
        assert (canvas.node_count, canvas.edge_count) == (len(nodes), len(edges))
        assert scenes_of(canvas) == 1, 'an old scene survived its deleteLater'


def test_a_focus_and_selection_survive_a_swap_while_their_nodes_do(canvas):
    big, big_edges = grid(GRAPH_NODES_MAX)
    canvas.set_graph(big, big_edges)
    canvas.focus_node('n1500')
    canvas.toggle_selected('n1500')
    canvas.toggle_selected('n7')
    small, small_edges = grid(500)
    canvas.set_graph(small, small_edges)
    assert canvas.focused_key is None  # n1500 is not in the 500-node graph
    assert canvas.selected_keys == frozenset({'n7'})
    canvas.set_graph(big, big_edges)
    assert canvas.focused_key is None and canvas.selected_keys == frozenset({'n7'})
    canvas.focus_node('n7')
    canvas.set_graph(big, big_edges)
    assert canvas.focused_key == 'n7'


def test_an_oversized_graph_is_refused_and_the_current_one_stays_on_screen(canvas):
    nodes, edges = grid(GRAPH_NODES_MAX)
    canvas.set_graph(nodes, edges)
    too_many = nodes + [GraphNodeView('extra', 'extra', 0.0, 0.0)]
    with pytest.raises(GraphTooLargeError):
        canvas.set_graph(too_many, edges)
    assert (canvas.node_count, canvas.edge_count) == (GRAPH_NODES_MAX, GRAPH_EDGES_MAX)
    assert scenes_of(canvas) == 1


def test_an_edge_past_the_ceiling_is_refused_before_anything_is_built(canvas):
    nodes, edges = grid(GRAPH_NODES_MAX)
    with pytest.raises(GraphTooLargeError):
        canvas.set_graph(nodes, edges + [GraphEdgeView('n0', 'n1')])
    assert canvas.node_count == 0  # nothing was on screen before this call


def test_arrow_keys_walk_the_maximum_graph_and_always_land_on_a_real_node(canvas, qtbot):
    nodes, edges = grid(GRAPH_NODES_MAX)
    canvas.set_graph(nodes, edges)
    canvas.focus_node('n0')
    visited = {canvas.focused_key}
    for key in (Qt.Key.Key_Right, Qt.Key.Key_Down, Qt.Key.Key_Right, Qt.Key.Key_Left, Qt.Key.Key_Up) * 20:
        QApplication.sendEvent(canvas, QKeyEvent(QKeyEvent.Type.KeyPress, key, Qt.KeyboardModifier.NoModifier))
        assert canvas.focused_key in {node.key for node in nodes}
        visited.add(canvas.focused_key)
    assert len(visited) > 1


def test_zooming_past_both_clamps_keeps_the_level_consistent(canvas):
    nodes, edges = grid(GRAPH_NODES_MAX)
    canvas.set_graph(nodes, edges)
    for _ in range(60):
        canvas.zoom_in()
    assert canvas.zoom == gv.ZOOM_MAX and canvas.level == gv.detail_level(gv.ZOOM_MAX)
    for _ in range(120):
        canvas.zoom_out()
    assert canvas.zoom == gv.ZOOM_MIN and canvas.level == gv.detail_level(gv.ZOOM_MIN)
    assert canvas.node_count == GRAPH_NODES_MAX


def test_minimap_over_the_maximum_graph_stays_bounded_and_follows_zoom_and_panning(canvas):
    from patchtrace.callgraph.minimap import MAX_DOTS
    from patchtrace.callgraph.minimap_qt import MinimapWidget
    nodes, edges = grid(GRAPH_NODES_MAX)
    canvas.set_graph(nodes, edges)
    minimap = MinimapWidget(canvas)
    minimap.set_points({n.key: (n.x, n.y) for n in nodes}, 'n0')
    minimap.show()
    assert len(minimap.model.dots) == min(GRAPH_NODES_MAX, MAX_DOTS)
    fitted = minimap.model.coverage_percent
    for _ in range(8):
        canvas.zoom_in()
    QApplication.processEvents()
    assert minimap.model.coverage_percent < fitted
    for _ in range(30):
        QApplication.sendEvent(minimap, QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Right, Qt.KeyboardModifier.NoModifier))
    minimap.grab()  # a full repaint of 2,000 dots must not raise
    assert 0 <= minimap.model.coverage_percent <= 100
