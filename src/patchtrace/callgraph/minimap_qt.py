"""Qt view of the Calls diagram minimap (docs/specs/panels/graph-inspection.md section 3). Read-only: it draws the model
of `minimap.py` and only moves the canvas viewport (mouse, arrow keys, plus, minus, zero). No timer runs here; it
repaints when the canvas viewport, scroll range or graph changes."""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QKeyEvent, QMouseEvent, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from ..gui.qt.canvas import GraphCanvas
from .minimap import MinimapModel, build_minimap, pan_target, to_scene

_ARROWS = {Qt.Key.Key_Left: 'left', Qt.Key.Key_Right: 'right', Qt.Key.Key_Up: 'up', Qt.Key.Key_Down: 'down'}
WIDTH_EM, HEIGHT_EM = 14, 9
NAME = 'Diagram minimap'


class MinimapWidget(QWidget):
    def __init__(self, canvas: GraphCanvas, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName('graph.minimap_view')
        self.setAccessibleName(NAME)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        height = self.fontMetrics().height()
        self.setFixedSize(WIDTH_EM * height, HEIGHT_EM * height)
        self._canvas = canvas
        self._points: dict[str, tuple[float, float]] = {}
        self._focus: str | None = None
        self._model: MinimapModel | None = None
        self._stamp: tuple | None = None
        for bar in (canvas.horizontalScrollBar(), canvas.verticalScrollBar()):
            bar.valueChanged.connect(self.refresh)
            bar.rangeChanged.connect(self.refresh)
        canvas.viewport().installEventFilter(self)  # a zoom that leaves the scroll bars unchanged still repaints
        self.refresh()

    # ---- data ------------------------------------------------------------------------------------------------

    def set_points(self, points: dict[str, tuple[float, float]], focus: str | None = None) -> None:
        self._points, self._focus, self._stamp = dict(points), focus, None
        self.refresh()

    def clear(self) -> None:
        self.set_points({}, None)

    @property
    def model(self) -> MinimapModel:
        if self._model is None:
            self.refresh()
        assert self._model is not None
        return self._model

    def _geometry(self) -> tuple[tuple[float, float, float, float], tuple[float, float, float, float]]:
        scene = self._canvas.sceneRect()
        view = self._canvas.mapToScene(self._canvas.viewport().rect()).boundingRect()
        return (scene.x(), scene.y(), scene.width(), scene.height()), (view.x(), view.y(), view.width(), view.height())

    def refresh(self, *_args) -> None:
        scene, view = self._geometry()
        size = (self.width(), self.height())
        stamp = (scene, view, size, self._focus, len(self._points))
        if stamp == self._stamp and self._model is not None:
            return
        self._stamp = stamp
        self._model = build_minimap(self._points, scene, view, size, self._focus)
        self.setAccessibleDescription(self._model.description)
        self.update()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() in (QEvent.Type.Paint, QEvent.Type.Resize):
            self.refresh()
        return False

    # ---- painting --------------------------------------------------------------------------------------------

    def paintEvent(self, _event: QPaintEvent) -> None:  # noqa: N802
        model = self.model
        palette = self.palette()
        painter = QPainter(self)
        painter.fillRect(self.rect(), palette.base())
        ink, accent = palette.color(palette.ColorRole.Text), palette.color(palette.ColorRole.Highlight)
        muted = QColor(ink)
        muted.setAlpha(150)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(muted)
        for index, (x, y) in enumerate(model.dots):
            if index != model.focus_index:
                painter.drawEllipse(QPointF(x, y), 1.5, 1.5)
        if model.focus_index is not None:
            painter.setBrush(accent)
            x, y = model.dots[model.focus_index]
            painter.drawEllipse(QPointF(x, y), 3.0, 3.0)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(accent, 2))
        vx, vy, vw, vh = model.viewport
        painter.drawRect(QRectF(vx, vy, vw, vh))
        painter.setPen(QPen(palette.color(palette.ColorRole.Highlight if self.hasFocus() else palette.ColorRole.Mid), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))
        painter.end()

    # ---- input: only the canvas viewport moves ------------------------------------------------------------------

    def _centre_on(self, x: float, y: float) -> None:
        self._canvas.centerOn(QPointF(x, y))
        self.refresh()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.setFocus(Qt.FocusReason.MouseFocusReason)
            self._centre_on(*to_scene(self.model, event.position().x(), event.position().y()))
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.buttons() & Qt.MouseButton.LeftButton:
            self._centre_on(*to_scene(self.model, event.position().x(), event.position().y()))
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        key = event.key()
        if key in _ARROWS:
            scene, view = self._geometry()
            self._centre_on(*pan_target(scene, view, _ARROWS[key]))
        elif key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self._canvas.zoom_in()
        elif key in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
            self._canvas.zoom_out()
        elif key == Qt.Key.Key_0:
            self._canvas.fit()
        else:
            super().keyPressEvent(event)
            return
        self.refresh()
        event.accept()
