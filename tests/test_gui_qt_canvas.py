"""GUI slice F6b: GraphCanvas (GUI plan 8.4, 8.9, 8.11). Offscreen; time bounds are loose regression guards."""
from __future__ import annotations

import time

import pytest
from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtGui import QPainter, QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QGraphicsLineItem, QGraphicsRectItem, QGraphicsSimpleTextItem
from qt_support import (  # noqa: F401, F811
    HOSTILE_PARAMS,
    RecordingAnnouncer,
    flush_deferred_deletes,
    join_gui_threads,
    slot_timer,
)

from patchtrace.gui.graph_view import GraphEdgeView, GraphNodeView, GraphTooLargeError
from patchtrace.gui.qt.canvas import GraphCanvas

STOCK = (QGraphicsRectItem, QGraphicsLineItem, QGraphicsSimpleTextItem)


def grid(columns: int, rows: int, chip: str = 'info') -> list[GraphNodeView]:
    return [GraphNodeView(f'n{r}_{c}', f'node {r} {c}', c * 200.0, r * 80.0, chip) for r in range(rows)
            for c in range(columns)]


def links(nodes: list[GraphNodeView], count: int) -> list[GraphEdgeView]:
    return [GraphEdgeView(nodes[i % len(nodes)].key, nodes[(i * 7 + 1) % len(nodes)].key) for i in range(count)]


def texts(view: GraphCanvas) -> list[QGraphicsSimpleTextItem]:
    return [i for i in view.scene().items() if isinstance(i, QGraphicsSimpleTextItem)]


def boxes(view: GraphCanvas) -> list[QGraphicsRectItem]:
    return [i for i in view.scene().items() if isinstance(i, QGraphicsRectItem) and i.data(0)]


@pytest.fixture
def announcer() -> RecordingAnnouncer:
    return RecordingAnnouncer()


@pytest.fixture
def canvas(qtbot, announcer):
    view = GraphCanvas(announcer)
    qtbot.addWidget(view)
    view.resize(800, 600)
    view.show()
    return view


def test_empty_canvas_is_accessible_and_focusable(canvas):
    assert canvas.accessibleName() == 'Graph' and canvas.focusPolicy() == Qt.FocusPolicy.StrongFocus
    assert canvas.scene().minimumRenderSize() == 1.0 and canvas.node_count == 0


def test_builds_items_and_fits(canvas):
    nodes = grid(4, 3)
    canvas.set_graph(nodes, links(nodes, 5))
    assert (canvas.node_count, canvas.edge_count) == (12, 5)
    assert sum(isinstance(i, QGraphicsLineItem) for i in canvas.scene().items()) == 5
    assert 0.05 <= canvas.zoom <= 8


@pytest.mark.parametrize('size', [(500, 2000), (2000, 8000)], ids=['default', 'maximum'])
def test_budget_sizes_use_only_stock_items(qtbot, size):
    node_limit, edge_limit = size
    view = GraphCanvas(max_nodes=node_limit, max_edges=edge_limit)
    qtbot.addWidget(view)
    view.resize(800, 600)
    view.show()
    nodes = grid(50, node_limit // 50)
    start = time.perf_counter()
    view.set_graph(nodes, links(nodes, edge_limit))
    assert time.perf_counter() - start < 5.0  # measured 13-86 ms in the plan; only a gross regression trips this
    assert all(type(item) in STOCK for item in view.scene().items())
    assert (view.node_count, view.edge_count) == (node_limit, edge_limit)
    assert not view.grab().isNull()


def test_too_large_raises_and_keeps_the_old_graph(canvas):
    canvas.set_graph(grid(2, 2), [])
    scene = canvas.scene()
    assert scene.minimumRenderSize() == 1.0
    with pytest.raises(GraphTooLargeError, match='PT-GUI-GRAPH-TOO-LARGE'):
        canvas.set_graph(grid(30, 20), [])
    with pytest.raises(GraphTooLargeError):
        canvas.set_graph(grid(2, 2), [GraphEdgeView('n0_0', 'n0_1')] * 2001)
    assert canvas.scene() is scene and canvas.node_count == 4


def test_ceilings_are_constructor_arguments_within_the_maximum(qtbot):
    small = GraphCanvas(max_nodes=3, max_edges=1)
    qtbot.addWidget(small)
    with pytest.raises(GraphTooLargeError):
        small.set_graph(grid(2, 2), [])
    for nodes_n, edges_n in ((2_001, 10), (10, 8_001)):
        with pytest.raises(ValueError):
            GraphCanvas(max_nodes=nodes_n, max_edges=edges_n)


def test_scene_is_swapped_and_the_old_one_deleted(canvas):
    canvas.set_graph(grid(2, 2), [])
    old = canvas.scene()
    destroyed = []
    old.destroyed.connect(lambda *_: destroyed.append(True))
    canvas.set_graph(grid(3, 3), [])
    assert canvas.scene() is not old
    flush_deferred_deletes()
    assert destroyed


@pytest.mark.parametrize('zoom,level,labels', [(1.0, 'label', True), (0.3, 'box', False), (0.1, 'mark', False)],
                         ids=['label', 'box', 'mark'])
def test_level_of_detail_follows_zoom(canvas, zoom, level, labels):
    canvas.set_graph(grid(3, 3), [])
    canvas.set_zoom(zoom)
    assert canvas.level == level and len(texts(canvas)) == 9
    assert all(t.isVisible() == labels for t in texts(canvas))


def test_marks_have_no_outline_and_boxes_do(canvas):
    canvas.set_graph(grid(2, 1), [])
    canvas.set_zoom(0.1)
    assert all(b.pen().style() == Qt.PenStyle.NoPen for b in boxes(canvas))
    canvas.set_zoom(0.3)
    assert all(b.pen().style() == Qt.PenStyle.SolidLine for b in boxes(canvas))


def test_zoom_is_clamped_and_keys_zoom(canvas):
    canvas.set_graph(grid(2, 2), [])
    canvas.set_zoom(100)
    assert canvas.zoom == 8
    canvas.set_zoom(0)
    assert canvas.zoom == 0.05
    canvas.set_zoom(1)
    QTest.keyClick(canvas, Qt.Key.Key_Plus)
    assert canvas.zoom > 1
    QTest.keyClick(canvas, Qt.Key.Key_Minus)
    assert canvas.zoom == pytest.approx(1)
    canvas.set_zoom(5)
    QTest.keyClick(canvas, Qt.Key.Key_0)
    assert canvas.zoom != 5


def test_antialiasing_is_off_above_200_items(canvas):
    canvas.set_graph(grid(10, 10), [])
    assert canvas.renderHints() & QPainter.RenderHint.Antialiasing
    canvas.set_graph(grid(15, 14), [])
    assert not canvas.renderHints() & QPainter.RenderHint.Antialiasing


def test_arrow_keys_move_focus_and_announce(canvas, announcer):
    canvas.set_graph(grid(3, 3), [GraphEdgeView('n0_0', 'n0_1'), GraphEdgeView('n0_1', 'n1_1')])
    seen = []
    canvas.node_focused.connect(seen.append)
    QTest.keyClick(canvas, Qt.Key.Key_Right)  # nothing focused: the top-left node
    assert canvas.focused_key == 'n0_0'
    QTest.keyClick(canvas, Qt.Key.Key_Right)
    QTest.keyClick(canvas, Qt.Key.Key_Down)
    QTest.keyClick(canvas, Qt.Key.Key_Up)
    assert seen == ['n0_0', 'n0_1', 'n1_1', 'n0_1']
    QTest.keyClick(canvas, Qt.Key.Key_Up)  # nothing above: stays and says nothing
    assert canvas.focused_key == 'n0_1' and len(announcer.texts) == 4
    assert announcer.messages[0] == ('node 0 0, 1 connection', False)
    assert announcer.texts[1] == 'node 0 1, 2 connections'


def test_enter_activates_and_space_selects(canvas):
    canvas.set_graph(grid(2, 1), [])
    activated, selected = [], []
    canvas.node_activated.connect(activated.append)
    canvas.node_selected.connect(lambda key, on: selected.append((key, on)))
    QTest.keyClick(canvas, Qt.Key.Key_Return)  # nothing focused yet
    assert activated == []
    QTest.keyClick(canvas, Qt.Key.Key_Left)
    QTest.keyClick(canvas, Qt.Key.Key_Return)
    QTest.keyClick(canvas, Qt.Key.Key_Space)
    assert canvas.selected_keys == {'n0_0'}
    QTest.keyClick(canvas, Qt.Key.Key_Space)
    assert activated == ['n0_0'] and selected == [('n0_0', True), ('n0_0', False)]
    assert canvas.selected_keys == frozenset()


def test_selected_state_is_announced(canvas, announcer):
    canvas.set_graph(grid(2, 1), [])
    canvas.focus_node('n0_0')
    canvas.toggle_selected('n0_0')
    canvas.focus_node('n0_1')
    canvas.focus_node('n0_0')
    assert announcer.texts[-1] == 'node 0 0, 0 connections, selected'
    with pytest.raises(KeyError):
        canvas.focus_node('missing')


def test_click_focuses_and_double_click_activates(canvas):
    canvas.set_graph(grid(2, 2), [])
    canvas.set_zoom(1.0)
    activated = []
    canvas.node_activated.connect(activated.append)
    QTest.mouseClick(canvas.viewport(), Qt.MouseButton.LeftButton, pos=canvas.mapFromScene(canvas.node_center('n0_1')))
    assert canvas.focused_key == 'n0_1'
    QTest.mouseDClick(canvas.viewport(), Qt.MouseButton.LeftButton,
                      pos=canvas.mapFromScene(canvas.node_center('n1_0')))
    assert activated == ['n1_0']


def test_focus_and_selection_follow_keys_across_a_swap(canvas, announcer):
    nodes = grid(2, 2)
    canvas.set_graph(nodes, [])
    canvas.focus_node('n1_1')
    canvas.toggle_selected('n1_1')
    canvas.toggle_selected('n0_0')
    count = len(announcer.messages)
    canvas.set_graph(nodes[1:], [])  # n0_0 is gone
    assert canvas.focused_key == 'n1_1' and canvas.selected_keys == {'n1_1'}
    assert len(announcer.messages) == count  # a refresh is not announced
    canvas.set_graph(grid(1, 1), [])
    assert canvas.focused_key is None and canvas.selected_keys == frozenset()


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_labels_stay_plain(canvas, announcer, text):
    canvas.set_graph([GraphNodeView('k', text, 0, 0)], [])
    assert len(texts(canvas)) == 1
    canvas.focus_node('k')
    for shown in [texts(canvas)[0].text(), announcer.texts[-1]]:
        assert not any(c in shown for c in '\x00\x1b‮ ')


def test_long_labels_are_elided(canvas):
    canvas.set_graph([GraphNodeView('k', 'x' * 150, 0, 0)], [])
    shown = texts(canvas)[0].text()
    assert len(shown) < 40 and shown.endswith('…')


def test_ctrl_wheel_zooms_and_plain_wheel_does_not(canvas):
    canvas.set_graph(grid(2, 2), [])
    canvas.set_zoom(1)
    pos = QPointF(10, 10)

    def wheel(modifier):
        canvas.wheelEvent(QWheelEvent(pos, canvas.mapToGlobal(pos), QPoint(), QPoint(0, 120),
                                      Qt.MouseButton.NoButton, modifier, Qt.ScrollPhase.NoScrollPhase, False))
    wheel(Qt.KeyboardModifier.NoModifier)
    assert canvas.zoom == 1
    wheel(Qt.KeyboardModifier.ControlModifier)
    assert canvas.zoom > 1


def test_keyboard_navigation_stays_in_the_callback_budget(canvas, slot_timer):  # noqa: F811
    nodes = grid(10, 10)
    canvas.set_graph(nodes, links(nodes, 50))
    canvas.node_focused.connect(slot_timer.wrap(lambda key: None))
    canvas.focus_node('n0_0')
    for _ in range(9):
        QTest.keyClick(canvas, Qt.Key.Key_Right)
    assert len(slot_timer.durations) == 10
    assert slot_timer.maximum < 1.0  # the 50 ms budget is asserted on Windows hardware, not on shared CI
