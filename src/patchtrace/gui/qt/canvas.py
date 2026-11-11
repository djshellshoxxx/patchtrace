"""GraphCanvas: a QGraphicsView over immutable node and edge views (GUI plan 8.4, slice F6b).

Every item is a stock Qt item (rectangles, text, lines): no Python ``paint()``, so the 2,000 node and 8,000 edge
maximum stays cheap. A graph is replaced by building a new scene, swapping it in and ``deleteLater`` on the old one
(``scene.clear()`` is 20 times slower). Level of detail changes only when the zoom crosses a threshold. Scene items
are invisible to UI Automation, so a focused node is announced and the feature supplies the textual adjacency table.
Layout is the feature's: positions come with the node views.
"""
from __future__ import annotations

from typing import Protocol

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QKeyEvent, QMouseEvent, QPainter, QPen, QTransform, QWheelEvent
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QWidget,
)

from .. import graph_view as gv
from ..graph_view import GraphEdgeView, GraphNodeView
from ..registry import GRAPH_EDGES, GRAPH_NODES
from ..tips import apply_tip, register_gui_tips
from .metrics import Metrics
from .theme import DARK, ThemeTokens, chip_text_color

NODE_WIDTH_EM = 9
ZOOM_STEP = 1.25
_KEY_DIRECTIONS = {Qt.Key.Key_Left: 'left', Qt.Key.Key_Right: 'right', Qt.Key.Key_Up: 'up', Qt.Key.Key_Down: 'down'}
_ZOOM_IN = (Qt.Key.Key_Plus, Qt.Key.Key_Equal)
_ZOOM_OUT = (Qt.Key.Key_Minus, Qt.Key.Key_Underscore)
_ACTIVATE = (Qt.Key.Key_Return, Qt.Key.Key_Enter)


class Announcer(Protocol):
    def announce(self, text: str, assertive: bool = False) -> None: ...


class GraphCanvas(QGraphicsView):
    node_focused = Signal(str)    # key; also announced (polite)
    node_activated = Signal(str)  # Enter or double click
    node_selected = Signal(str, bool)  # key, selected (Space or click toggles)

    def __init__(self, announcer: Announcer | None = None, tokens: ThemeTokens = DARK,
                 max_nodes: int = GRAPH_NODES, max_edges: int = GRAPH_EDGES, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        gv.check_ceilings(max_nodes, max_edges)
        self._announcer = announcer
        self._tokens = tokens
        self.max_nodes, self.max_edges = max_nodes, max_edges
        self._nodes: dict[str, GraphNodeView] = {}
        self._boxes: dict[str, QGraphicsRectItem] = {}
        self._labels: list[QGraphicsSimpleTextItem] = []
        self._edges: list[QGraphicsLineItem] = []
        self._points: dict[str, tuple[float, float]] = {}
        self._connections: dict[str, int] = {}
        self._selected: set[str] = set()
        self._focused: str | None = None
        self._ring = self._make_ring()
        self._zoom = 1.0
        self._level = gv.detail_level(self._zoom)
        self.setObjectName('graph.canvas')
        self.setAccessibleName('Graph')
        register_gui_tips()
        apply_tip(self, 'gui.graph')
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setBackgroundBrush(QBrush(QColor(tokens.surface_alt)))
        self.setScene(self._new_scene())
        self.scene().addItem(self._ring)

    # -- state --
    @property
    def zoom(self) -> float:
        return self._zoom

    @property
    def level(self) -> str:
        return self._level

    @property
    def focused_key(self) -> str | None:
        return self._focused

    @property
    def selected_keys(self) -> frozenset[str]:
        return frozenset(self._selected)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # -- content --
    def set_graph(self, nodes: list[GraphNodeView], edges: list[GraphEdgeView]) -> None:
        """Replace the graph. Raises `GraphTooLargeError` (PT-GUI-GRAPH-TOO-LARGE) before touching anything, so
        the earlier graph stays on screen. Focus and selection follow node keys that survive."""
        gv.validate_graph(nodes, edges, self.max_nodes, self.max_edges)
        keep_focus, keep_selected = self._focused, self._selected
        old = self.scene()
        scene = self._new_scene()
        self._ring = self._make_ring()
        self._build(scene, nodes, edges)
        scene.addItem(self._ring)
        self.setScene(scene)
        old.deleteLater()
        self._selected = {key for key in keep_selected if key in self._nodes}
        for key in self._selected:
            self._paint_node(key)
        self._focused = None
        self._focus(keep_focus if keep_focus in self._nodes else None, announce=False)
        self._apply_quality()
        self.fit()

    def _new_scene(self) -> QGraphicsScene:
        scene = QGraphicsScene(self)
        scene.setMinimumRenderSize(1.0)  # items under one pixel are skipped
        return scene

    def _build(self, scene: QGraphicsScene, nodes: list[GraphNodeView], edges: list[GraphEdgeView]) -> None:
        metrics = Metrics.of(self)
        width, height = metrics.em * NODE_WIDTH_EM, metrics.row_height
        self._nodes = {node.key: node for node in nodes}
        self._points = {node.key: (node.x, node.y) for node in nodes}
        self._connections = gv.adjacency(edges)
        self._boxes, self._labels = {}, []
        edge_pen = QPen(QColor(self._tokens.border), 1)
        edge_pen.setCosmetic(True)
        self._edges = []
        for edge in edges:
            (x1, y1), (x2, y2) = self._points[edge.source], self._points[edge.target]
            line = QGraphicsLineItem(x1, y1, x2, y2)
            line.setPen(edge_pen)
            line.setZValue(-1)
            scene.addItem(line)
            self._edges.append(line)
        for node in nodes:
            box = QGraphicsRectItem(node.x - width / 2, node.y - height / 2, width, height)
            colors = self._tokens.chip(node.chip)
            box.setBrush(QBrush(QColor(colors.fill)))
            box.setData(0, node.key)
            scene.addItem(box)
            self._boxes[node.key] = box
            label = QGraphicsSimpleTextItem(self._elide(node.label, width), box)
            label.setBrush(QBrush(QColor(chip_text_color(self._tokens, node.chip))))
            label.setPos(node.x - width / 2 + metrics.gap_small, node.y - metrics.line / 2)
            self._labels.append(label)
            self._paint_node(node.key)
        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-width, -height, width, height))
        self._apply_level()

    def _elide(self, text: str, width: float) -> str:
        room = max(1, int(width / max(1, self.fontMetrics().horizontalAdvance('M'))))
        return text if len(text) <= room else text[:room - 1] + '…'

    def _make_ring(self) -> QGraphicsRectItem:
        ring = QGraphicsRectItem()
        pen = QPen(QColor(self._tokens.focus_ring), 3)
        pen.setCosmetic(True)
        ring.setPen(pen)
        ring.setZValue(10)
        ring.setVisible(False)
        return ring

    def _paint_node(self, key: str) -> None:
        box = self._boxes[key]
        colors = self._tokens.chip(self._nodes[key].chip)
        if self._level == 'mark':
            box.setPen(QPen(Qt.PenStyle.NoPen))
            return
        selected = key in self._selected
        pen = QPen(QColor(self._tokens.accent if selected else colors.edge), 3 if selected else 1)
        pen.setCosmetic(True)
        box.setPen(pen)

    # -- level of detail and quality --
    def _apply_level(self) -> None:
        shown = self._level == 'label'
        for label in self._labels:
            label.setVisible(shown)
        for key in self._boxes:
            self._paint_node(key)

    def _apply_quality(self) -> None:
        self.setRenderHint(QPainter.RenderHint.Antialiasing, gv.antialias(len(self._boxes) + len(self._edges)))

    def set_zoom(self, zoom: float) -> None:
        self._zoom = gv.clamp_zoom(zoom)
        self.setTransform(QTransform.fromScale(self._zoom, self._zoom))
        level = gv.detail_level(self._zoom)
        if level != self._level:
            self._level = level
            self._apply_level()

    def zoom_in(self) -> None:
        self.set_zoom(self._zoom * ZOOM_STEP)

    def zoom_out(self) -> None:
        self.set_zoom(self._zoom / ZOOM_STEP)

    def fit(self) -> None:
        """Fit the whole graph, within the zoom clamp."""
        rect = self.scene().sceneRect()
        if not self._boxes or rect.isEmpty() or self.viewport().width() < 1 or self.viewport().height() < 1:
            self.set_zoom(1.0)
            return
        self.set_zoom(min(self.viewport().width() / rect.width(), self.viewport().height() / rect.height()))
        self.centerOn(rect.center())

    # -- focus, selection, activation --
    def focus_node(self, key: str) -> None:
        if key not in self._nodes:
            raise KeyError(key)
        self._focus(key, announce=True)

    def _focus(self, key: str | None, announce: bool) -> None:
        if key == self._focused:
            return
        self._focused = key
        if key is None:
            self._ring.setVisible(False)
            return
        box = self._boxes[key]
        self._ring.setRect(box.rect().adjusted(-3, -3, 3, 3))
        self._ring.setVisible(True)
        self.ensureVisible(box, 20, 20)
        if announce:
            self.node_focused.emit(key)
            if self._announcer:
                self._announcer.announce(self._announcement(key))

    def _announcement(self, key: str) -> str:
        node = self._nodes[key]
        count = self._connections.get(key, 0)
        parts = [node.label, f'{count} connection{"" if count == 1 else "s"}']
        if key in self._selected:
            parts.append('selected')
        if node.description:
            parts.append(node.description)
        return ', '.join(parts)

    def toggle_selected(self, key: str) -> None:
        if key not in self._nodes:
            raise KeyError(key)
        self._selected ^= {key}
        self._paint_node(key)
        self.node_selected.emit(key, key in self._selected)

    # -- input --
    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if key in _KEY_DIRECTIONS and self._points:
            target = (gv.first_node(self._points) if self._focused is None
                      else gv.nearest_in_direction(self._points, self._focused, _KEY_DIRECTIONS[key]))
            if target is not None:
                self._focus(target, announce=True)
        elif key in _ACTIVATE and self._focused:
            self.node_activated.emit(self._focused)
        elif key == Qt.Key.Key_Space and self._focused:
            self.toggle_selected(self._focused)
        elif key in _ZOOM_IN:
            self.zoom_in()
        elif key in _ZOOM_OUT:
            self.zoom_out()
        elif key == Qt.Key.Key_0:
            self.fit()
        else:
            super().keyPressEvent(event)
            return
        event.accept()

    def wheelEvent(self, event: QWheelEvent) -> None:
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            (self.zoom_in if event.angleDelta().y() > 0 else self.zoom_out)()
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        super().mousePressEvent(event)
        key = self._key_at(event.position().toPoint())
        if key and event.button() == Qt.MouseButton.LeftButton:
            self._focus(key, announce=True)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        key = self._key_at(event.position().toPoint())
        if key:
            self._focus(key, announce=True)
            self.node_activated.emit(key)
        else:
            super().mouseDoubleClickEvent(event)

    def _key_at(self, point) -> str | None:
        item: QGraphicsItem | None = self.itemAt(point)
        if item is not None and item.parentItem() is not None:
            item = item.parentItem()
        key = item.data(0) if item is not None else None
        return key if key in self._nodes else None

    def node_center(self, key: str) -> QPointF:
        """Scene position of a node centre (tests and features map it with `mapFromScene`)."""
        return QPointF(*self._points[key])

    def node_rect(self, key: str) -> QRectF:
        return self._boxes[key].rect()
