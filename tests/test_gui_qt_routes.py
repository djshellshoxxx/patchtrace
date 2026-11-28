"""Stock path items paint feature-owned routes without replacing canvas behavior."""
from __future__ import annotations

import pytest
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QGraphicsLineItem, QGraphicsPathItem, QGraphicsRectItem

from patchtrace.gui.graph_view import GraphEdgeView, GraphNodeView
from patchtrace.gui.qt.canvas import GraphCanvas


@pytest.fixture
def canvas(qtbot):
    view = GraphCanvas()
    qtbot.addWidget(view)
    view.resize(800, 600)
    view.show()
    return view


def test_routes_are_stock_paths_in_original_point_order_and_lines_remain_lines(canvas):
    points = ((30.0, 0.0), (70.0, 50.0), (170.0, 50.0))
    canvas.set_graph([GraphNodeView('a', 'A', 0, 0), GraphNodeView('b', 'B', 200, 50)],
                     [GraphEdgeView('a', 'b', 'call', points), GraphEdgeView('b', 'a')])
    paths = [item for item in canvas.scene().items() if isinstance(item, QGraphicsPathItem)]
    assert len(paths) == 1 and type(paths[0]) is QGraphicsPathItem
    path = paths[0].path()
    assert tuple((path.elementAt(i).x, path.elementAt(i).y) for i in range(path.elementCount())) == points
    assert paths[0].zValue() == -1 and paths[0].pen().isCosmetic()
    assert sum(isinstance(item, QGraphicsLineItem) for item in canvas.scene().items()) == 1
    assert canvas.edge_count == 2 and canvas.node_count == 2


def test_routed_scene_replacement_keeps_focus_and_selection(canvas):
    nodes = [GraphNodeView('a', 'A', 0, 0), GraphNodeView('b', 'B', 200, 50)]
    canvas.set_graph(nodes, [])
    canvas.focus_node('b')
    canvas.toggle_selected('a')
    previous = canvas.scene()
    canvas.set_graph(nodes, [GraphEdgeView('a', 'b', points=((0, 0), (100, 70), (200, 50)))])
    assert canvas.scene() is not previous
    assert canvas.focused_key == 'b' and canvas.selected_keys == frozenset({'a'})


def test_node_dimensions_are_the_actual_font_derived_box_size(canvas):
    small = canvas.node_dimensions()
    font = QFont(canvas.font())
    font.setPointSize(32)
    canvas.setFont(font)
    large = canvas.node_dimensions()
    canvas.set_graph([GraphNodeView('a', 'A', 0, 0)], [])
    box = next(item for item in canvas.scene().items() if isinstance(item, QGraphicsRectItem) and item.data(0))
    assert large == (box.rect().width(), box.rect().height())
    assert large[0] > small[0] and large[1] > small[1]


def test_invalid_route_cannot_replace_an_existing_scene(canvas):
    canvas.set_graph([GraphNodeView('a', 'A', 0, 0)], [])
    scene = canvas.scene()
    with pytest.raises(ValueError):
        canvas.set_graph([GraphNodeView('a', 'A', 0, 0)],
                         [GraphEdgeView('a', 'a', points=((0, 0), (float('nan'), 1)))])
    assert canvas.scene() is scene and canvas.node_count == 1
