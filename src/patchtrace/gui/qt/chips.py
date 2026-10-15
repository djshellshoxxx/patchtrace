"""Status chips: text + ASCII glyph + shape, with colour only as a redundant extra (GUI plan 8.4, 8.6).

``paint_chip`` is the one drawing routine; ``ChipLabel`` (a widget) and ``ChipDelegate`` (a table column) share
it. A model hands the delegate a ``ChipSpec`` under ``CHIP_ROLE`` and keeps the plain text under the display and
accessible-text roles, so sorting, copying and screen readers never depend on the drawing. In high contrast
(``tokens.high_contrast``) the fill is dropped, the edge is two pixels of the palette text colour and the state is
carried by the glyph, the words and the shape; widgets then read the live palette, not stored colours.
"""
from __future__ import annotations

from PySide6.QtCore import QModelIndex, QPointF, QRect, QRectF, QSize, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPalette,
    QPen,
    QPolygonF,
)
from PySide6.QtWidgets import QSizePolicy, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QWidget

from ..state import ChipSpec
from ..text import sanitize_text
from ..tips import apply_tip
from .theme import DARK, ThemeTokens, chip_text_color, system_tokens

CHIP_ROLE = Qt.ItemDataRole.UserRole + 41


def chip_text(spec: ChipSpec) -> str:
    """What is drawn inside the chip: the glyph, then the words."""
    return f'{spec.glyph} {spec.text}'


def chip_accessible_text(prefix: str, spec: ChipSpec) -> str:
    """The accessible text of a chip, e.g. "Verdict: Contested"; the words, not the glyph."""
    prefix = sanitize_text(prefix, 40)
    return f'{prefix}: {spec.text}' if prefix else spec.text


def _font_for(font: QFont, spec: ChipSpec) -> QFont:
    chip_font = QFont(font)
    chip_font.setBold(chip_font.bold() or spec.token == 'plain')  # the KEV badge: bold text carries the emphasis
    return chip_font


def chip_size(font: QFont, spec: ChipSpec) -> QSize:
    metrics = QFontMetrics(_font_for(font, spec))
    height = metrics.lineSpacing() + metrics.height() // 3
    pad = _padding(metrics, spec.shape, height)
    return QSize(metrics.horizontalAdvance(chip_text(spec)) + 2 * pad, height)


def _padding(metrics: QFontMetrics, shape: str, height: int) -> int:
    pad = max(2, metrics.horizontalAdvance('M') // 2)
    return pad + (height // 3 if shape in ('round', 'diamond') else 0)


def _outline(shape: str, body: QRectF) -> QPainterPath:
    path = QPainterPath()
    if shape == 'round':
        path.addRoundedRect(body, body.height() / 2, body.height() / 2)
    elif shape == 'diamond':
        slant = body.height() / 2
        path.addPolygon(QPolygonF([QPointF(body.left(), body.center().y()), QPointF(body.left() + slant, body.top()),
                                   QPointF(body.right() - slant, body.top()), QPointF(body.right(), body.center().y()),
                                   QPointF(body.right() - slant, body.bottom()),
                                   QPointF(body.left() + slant, body.bottom())]))
        path.closeSubpath()
    else:  # square and dashed
        path.addRoundedRect(body, 2, 2)
    return path


def paint_chip(painter: QPainter, rect: QRect, spec: ChipSpec, tokens: ThemeTokens, font: QFont) -> None:
    colors = tokens.chip(spec.token)
    chip_font = _font_for(font, spec)
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    inset = 1.0 if tokens.high_contrast else 0.5  # the wider pen must stay inside the rectangle
    path = _outline(spec.shape, QRectF(rect).adjusted(inset, inset, -inset, -inset))
    if spec.token != 'plain' and not tokens.high_contrast:
        painter.fillPath(path, QColor(colors.fill))
    pen = QPen(QColor(colors.edge), 2.0 if tokens.high_contrast else 1.0)
    pen.setStyle(Qt.PenStyle.DashLine if spec.shape == 'dashed' else Qt.PenStyle.SolidLine)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(path)
    painter.setFont(chip_font)
    plain_text = spec.token == 'plain' or tokens.high_contrast
    painter.setPen(QColor(tokens.text if plain_text else chip_text_color(tokens, spec.token)))
    pad = _padding(QFontMetrics(chip_font), spec.shape, rect.height())
    painter.drawText(rect.adjusted(pad, 0, -pad, 0), Qt.AlignmentFlag.AlignCenter, chip_text(spec))
    painter.restore()


def _live(tokens: ThemeTokens, palette: QPalette) -> ThemeTokens:
    """In high contrast the widget's own palette is the truth (it follows the platform per widget); otherwise the
    theme's tokens."""
    return system_tokens(palette, high_contrast=True) if tokens.high_contrast else tokens


class ChipLabel(QWidget):
    """One chip as a widget; its accessible name is "<prefix>: <words>"."""

    def __init__(self, spec: ChipSpec, parent: QWidget | None = None, *, prefix: str = '',
                 tokens: ThemeTokens = DARK) -> None:
        super().__init__(parent)
        self._prefix = prefix
        self._tokens = tokens
        self._spec = spec
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.set_spec(spec)

    @property
    def spec(self) -> ChipSpec:
        return self._spec

    def set_spec(self, spec: ChipSpec) -> None:
        self._spec = spec
        self.setAccessibleName(chip_accessible_text(self._prefix, spec))
        self.updateGeometry()
        self.update()

    def set_tokens(self, tokens: ThemeTokens) -> None:
        self._tokens = tokens
        self.update()

    def set_tip(self, tip_id: str, **values: object) -> None:
        """The tooltip through a registered template, so untrusted values are escaped."""
        apply_tip(self, tip_id, **values)

    def sizeHint(self) -> QSize:  # noqa: N802
        return chip_size(self.font(), self._spec)

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        painter = QPainter(self)
        paint_chip(painter, self.rect(), self._spec, _live(self._tokens, self.palette()), self.font())
        painter.end()


class ChipDelegate(QStyledItemDelegate):
    """Draws the ``ChipSpec`` a model returns for ``CHIP_ROLE``; any other cell is drawn as usual."""

    def __init__(self, parent: QWidget | None = None, tokens: ThemeTokens = DARK) -> None:
        super().__init__(parent)
        self._tokens = tokens

    def set_tokens(self, tokens: ThemeTokens) -> None:
        self._tokens = tokens

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        spec = index.data(CHIP_ROLE)
        if not isinstance(spec, ChipSpec):
            super().paint(painter, option, index)
            return
        styled = QStyleOptionViewItem(option)
        self.initStyleOption(styled, index)
        styled.text = ''  # the chip carries the words; the item view only draws the selection and focus background
        widget = option.widget
        style = widget.style() if widget else None
        if style is not None:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, styled, painter, widget)
        size = chip_size(option.font, spec)
        margin = max(1, (option.rect.height() - size.height()) // 2)
        area = QRect(option.rect.left() + margin, option.rect.top() + margin,
                     min(size.width(), option.rect.width() - 2 * margin), size.height())
        paint_chip(painter, area, spec, _live(self._tokens, option.palette), option.font)

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:  # noqa: N802
        spec = index.data(CHIP_ROLE)
        if not isinstance(spec, ChipSpec):
            return super().sizeHint(option, index)
        size = chip_size(option.font, spec)
        return QSize(size.width() + 8, size.height() + 8)
