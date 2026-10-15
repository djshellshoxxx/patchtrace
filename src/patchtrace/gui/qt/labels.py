"""Plain-text labels and views for untrusted text (GUI plan 8.4 and 8.11). One implementation of the three copies.

Qt labels, tooltips and message boxes guess rich text from the content, so ``<b>x</b>`` would render. Everything
here forces plain text, turns links off and passes every value through ``sanitize_text`` first.
"""
from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import QLabel, QPlainTextEdit, QSizePolicy, QWidget

from ..text import LABEL_LIMIT, VIEW_LIMIT, sanitize_text
from ..tips import escaped_tip

_SELECTABLE = Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard


class PlainLabel(QLabel):
    """A label whose text is data. Single line labels middle-elide to their width and show the full text, escaped,
    as a tooltip; ``wrap=True`` labels wrap instead. Selectable only when asked; ``multiline=True`` keeps line breaks."""

    def __init__(self, text: str = '', parent: QWidget | None = None, *, limit: int = LABEL_LIMIT, elide: bool = True,
                 wrap: bool = False, selectable: bool = False, multiline: bool = False) -> None:
        super().__init__(parent)
        self._limit = limit
        self._multiline = multiline
        self._elide = elide and not wrap
        self._full = ''
        self._auto_tip = False
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setOpenExternalLinks(False)
        self.setWordWrap(wrap)
        self.setTextInteractionFlags(_SELECTABLE if selectable else Qt.TextInteractionFlag.NoTextInteraction)
        if self._elide:
            self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.setText(text)

    def setText(self, text: object) -> None:  # noqa: N802 (Qt name)
        self._full = sanitize_text(text, self._limit, multiline=self._multiline)
        self._show()

    def full_text(self) -> str:
        """The sanitized text before elision."""
        return self._full

    def sizeHint(self) -> QSize:  # noqa: N802
        hint = super().sizeHint()
        if not self._elide:
            return hint
        return QSize(self.fontMetrics().horizontalAdvance(self._full) + 2 * self.margin(), hint.height())

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        hint = super().minimumSizeHint()
        return QSize(self.fontMetrics().horizontalAdvance('M') * 4, hint.height()) if self._elide else hint

    def resizeEvent(self, event: QResizeEvent) -> None:  # noqa: N802
        super().resizeEvent(event)
        if self._elide:
            self._show()

    def _show(self) -> None:
        shown = self._full
        if self._elide and self.width() > 1:
            room = max(0, self.contentsRect().width() - 2 * self.margin())
            shown = self.fontMetrics().elidedText(self._full, Qt.TextElideMode.ElideMiddle, room)
        super().setText(shown)
        if shown != self._full:
            self.setToolTip(escaped_tip(self._full))
            self._auto_tip = True
        elif self._auto_tip:  # never clear a tooltip that someone else set
            self.setToolTip('')
            self._auto_tip = False


class SafeTextView(QPlainTextEdit):
    """A read-only plain-text view for details, logs and advisory text: bounded, sanitized, never rich."""

    def __init__(self, accessible_name: str, parent: QWidget | None = None, *, limit: int = VIEW_LIMIT,
                 wrap: bool = False) -> None:
        super().__init__(parent)
        self._limit = limit
        self.setReadOnly(True)
        self.setAccessibleName(accessible_name)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if wrap else QPlainTextEdit.LineWrapMode.NoWrap)

    def setPlainText(self, text: object) -> None:  # noqa: N802
        super().setPlainText(sanitize_text(text, self._limit, multiline=True))


def labelled(field: QWidget, text: str, parent: QWidget | None = None) -> PlainLabel:
    """A sibling label for ``field`` with the buddy link and the explicit accessible name that UI Automation needs
    (a buddy name only reaches it for labels in the same parent). The name is the noun phrase without the colon."""
    name = sanitize_text(text).rstrip(': ')
    label = PlainLabel(f'{name}:', parent or field.parentWidget(), wrap=True)
    label.setBuddy(field)
    field.setAccessibleName(name)
    return label
