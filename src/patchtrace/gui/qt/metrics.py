"""DPI-safe layout metrics derived from the widget's font, never from pixel constants (GUI plan 8.6)."""
from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QEvent, QObject, Signal
from PySide6.QtWidgets import QWidget

MIN_ROW_HEIGHT = 28  # logical px: the 8.4 row-height floor, max(2 * lineSpacing + 6, 28)
_RECOMPUTE = frozenset({QEvent.Type.FontChange, QEvent.Type.DevicePixelRatioChange, QEvent.Type.StyleChange,
                        QEvent.Type.PaletteChange})


@dataclass(frozen=True, slots=True)
class Metrics:
    em: int            # width of 'M'
    line: int          # line spacing
    row_height: int
    gap: int           # between controls (half an em)
    gap_small: int     # inside a control group (quarter of an em)

    @classmethod
    def of(cls, widget: QWidget) -> Metrics:
        font = widget.fontMetrics()
        em, line = font.horizontalAdvance('M'), font.lineSpacing()
        return cls(em, line, max(2 * line + 6, MIN_ROW_HEIGHT), max(1, em // 2), max(1, em // 4))


class MetricsWatcher(QObject):
    """Event filter on one widget: recomputes ``metrics`` on font, DPI, style and palette changes and emits
    ``changed`` only when a value differs."""
    changed = Signal(object)

    def __init__(self, widget: QWidget) -> None:
        super().__init__(widget)
        self._widget = widget
        self.metrics = Metrics.of(widget)
        widget.installEventFilter(self)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self._widget and event.type() in _RECOMPUTE:
            self.refresh()
        return False

    def refresh(self) -> None:
        current = Metrics.of(self._widget)
        if current != self.metrics:
            self.metrics = current
            self.changed.emit(current)
