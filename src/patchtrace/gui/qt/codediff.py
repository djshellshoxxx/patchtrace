"""Two-pane code diff view and the one writer of extra selections (GUI plan 8.4, 8.9, 8.11; slice F6a).

`compose_selections(view, layer, selections)` works on any ``QPlainTextEdit``: each layer keeps its own list and the
view receives all layers in the order diff < search < anchor < mark, so a later layer paints over an earlier one
and a search hit or a mark never replaces a hunk. `CodeDiffView` feeds two read-only plain-text panes from a
``PairText`` (plain text only: never a QTextBrowser, never HTML), caps each side, and offers the hunk API.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from weakref import WeakKeyDictionary

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import (
    QColor,
    QFontDatabase,
    QGuiApplication,
    QPalette,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
)
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..pair_text import PairHunk, PairText
from ..text import sanitize_text
from ..theme_math import TEXT_CONTRAST, ensure_contrast
from .labels import PlainLabel
from .theme import DARK, ThemeTokens

LAYERS = ('diff', 'search', 'anchor', 'mark')
MAX_VIEW_CHARS = 200_000
TRUNCATION_NOTICE = '[View truncated at 200,000 characters; provenance copy uses full records.]'
SIDES = ('older', 'newer')
PANE_NAMES = {'older': 'Older artifact code', 'newer': 'Newer artifact code'}
PROVENANCE_LIMIT = 400

_layers: WeakKeyDictionary[QPlainTextEdit, dict[str, list[QTextEdit.ExtraSelection]]] = WeakKeyDictionary()


def compose_selections(view: QPlainTextEdit, layer: str, selections: Sequence[QTextEdit.ExtraSelection]) -> None:
    """Replace one layer of ``view``'s extra selections and apply all layers in order. This is the only code that
    calls ``setExtraSelections``; an empty list clears the layer."""
    if layer not in LAYERS:
        raise ValueError(f'unknown selection layer {layer!r}; expected one of {LAYERS}')
    stored = _layers.setdefault(view, {})
    stored[layer] = list(selections)
    view.setExtraSelections([item for name in LAYERS for item in stored.get(name, ())])


def clear_selections(view: QPlainTextEdit, *layers: str) -> None:
    """Clear the named layers (all when none are named)."""
    for layer in layers or LAYERS:
        compose_selections(view, layer, [])


def hunk_background(operation: str, tokens: ThemeTokens) -> str:
    """The tint of a hunk, or the plain pane colour when the text would fall below 4.5:1 on it (a palette that
    makes the fixed tint unreadable must never hide code)."""
    fill = tokens.hunk_replace if operation == 'replace' else tokens.hunk_other
    return ensure_contrast(fill, tokens.text, tokens.surface_alt, TEXT_CONTRAST)


def row_selection(view: QPlainTextEdit, first_row: int, last_row: int, color: str,
                   underline: str | None = None) -> QTextEdit.ExtraSelection | None:
    """A full-width background over aligned rows (underlined in ``underline`` when given: high contrast drops
    the tint, so the mark must not be colour alone), or None when a row is not in the document."""
    document = view.document()
    first, last = document.findBlockByNumber(first_row), document.findBlockByNumber(last_row)
    if not first.isValid() or not last.isValid():
        return None
    selection = QTextEdit.ExtraSelection()
    selection.cursor = QTextCursor(first)
    selection.cursor.setPosition(last.position() + last.length() - 1, QTextCursor.MoveMode.KeepAnchor)
    selection.format.setBackground(QColor(color))
    if underline:
        selection.format.setFontUnderline(True)
        selection.format.setUnderlineColor(QColor(underline))
    selection.format.setProperty(QTextCharFormat.Property.FullWidthSelection, True)
    return selection


def _capped(text: str) -> tuple[str, bool]:
    """Sanitized text of at most MAX_VIEW_CHARS characters (cut before sanitizing, so a huge value costs no more)
    and whether anything was cut."""
    return sanitize_text(text[:MAX_VIEW_CHARS], MAX_VIEW_CHARS, multiline=True), len(text) > MAX_VIEW_CHARS


class _Pane(QPlainTextEdit):
    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setAccessibleName(name)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))


class CodeDiffView(QWidget):
    """Older and newer code side by side, one aligned row per line. Feed it with ``set_pair``."""

    hunk_changed = Signal(int)  # the current hunk index, -1 when there is none

    def __init__(self, parent: QWidget | None = None, *, tokens: ThemeTokens = DARK) -> None:
        super().__init__(parent)
        self._tokens = tokens
        self._pair = PairText()
        self._hunks: tuple[PairHunk, ...] = ()
        self._maps: dict[str, tuple[int, ...]] = {side: () for side in SIDES}
        self._rows = 0
        self._current = -1
        self._sync = True
        self._syncing = False
        self._highlighters: dict[str, QSyntaxHighlighter] = {}
        self.panes: dict[str, QPlainTextEdit] = {side: _Pane(PANE_NAMES[side]) for side in SIDES}
        self._provenance = {side: PlainLabel(limit=PROVENANCE_LIMIT) for side in SIDES}
        self._raw_provenance = dict.fromkeys(SIDES, '')
        self._notice = PlainLabel(TRUNCATION_NOTICE, wrap=True)
        self._notice.hide()
        self._build()
        self.set_tokens(tokens)

    def _build(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        for side in SIDES:
            column = QWidget()
            layout = QVBoxLayout(column)
            layout.setContentsMargins(0, 0, 0, 0)
            header = QHBoxLayout()
            header.addWidget(self._provenance[side], 1)
            button = QPushButton('Copy')
            button.setAccessibleName(f'Copy {side} artifact code')
            button.clicked.connect(lambda _checked=False, which=side: self.copy_side(which))
            header.addWidget(button)
            layout.addLayout(header)
            layout.addWidget(self.panes[side], 1)
            splitter.addWidget(column)
        splitter.setAccessibleName('Panel divider')
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._notice)
        outer.addWidget(splitter, 1)
        for side, other in (('older', 'newer'), ('newer', 'older')):
            for kind in ('verticalScrollBar', 'horizontalScrollBar'):
                getattr(self.panes[side], kind)().valueChanged.connect(
                    lambda value, kind=kind, other=other: self._follow(kind, other, value))

    # --- content ---

    def pane(self, side: str) -> QPlainTextEdit:
        return self.panes[side]

    def set_pair(self, pair: PairText, provenance: tuple[str, str] = ('', '')) -> None:
        """Show ``pair``. Each side is sanitized and capped at 200,000 characters with an explicit notice; hunks
        and line maps beyond the shown rows are dropped. Layers are reset, since their cursors die with the text."""
        self._pair = pair
        texts, cut = {}, False
        for side in SIDES:
            texts[side], was_cut = _capped(getattr(pair, side))
            cut = cut or was_cut
        # A cut side ends mid-line, so only its complete lines count as shown rows.
        self._rows = min(text.count('\n') + (0 if cut else 1) for text in texts.values())
        for side in SIDES:
            self.panes[side].setPlainText(texts[side] + (f'\n{TRUNCATION_NOTICE}' if cut else ''))
            clear_selections(self.panes[side])
            self._maps[side] = tuple(row for row in pair.line_map(side) if row < self._rows)
        self._notice.setVisible(cut)
        self._hunks = tuple(PairHunk(h.start, min(h.length, self._rows - h.start), h.operation)
                            for h in pair.hunks if h.start < self._rows)
        for side, text in zip(SIDES, provenance, strict=True):
            self._raw_provenance[side] = sanitize_text(text, PROVENANCE_LIMIT)
            self._provenance[side].setText(text)
        self._current = -1
        self._paint_hunks()
        self.hunk_changed.emit(-1)

    def set_message(self, text: str) -> None:
        """Show one message in both panes (no selection, no function) and reset the hunks."""
        self.set_pair(PairText(text, text))

    def copy_side(self, side: str) -> None:
        """Copy the side's provenance and the code as shown (sanitized, capped) to the clipboard."""
        body = self.panes[side].toPlainText()
        head = self._raw_provenance[side]
        QGuiApplication.clipboard().setText(f'{head}\n\n{body}' if head else body)

    # --- theme ---

    def set_tokens(self, tokens: ThemeTokens) -> None:
        self._tokens = tokens
        for pane in self.panes.values():
            palette = pane.palette()
            palette.setColor(QPalette.ColorRole.Base, QColor(tokens.surface_alt))
            palette.setColor(QPalette.ColorRole.Text, QColor(tokens.text))
            pane.setPalette(palette)
        self._paint_hunks()

    def _paint_hunks(self) -> None:
        for pane in self.panes.values():
            mark = self._tokens.text if self._tokens.high_contrast else None
            selections = (row_selection(pane, h.start, h.start + h.length - 1,
                                         hunk_background(h.operation, self._tokens), mark) for h in self._hunks)
            compose_selections(pane, 'diff', [item for item in selections if item is not None])

    # --- hunks ---

    @property
    def hunks(self) -> tuple[PairHunk, ...]:
        return self._hunks

    @property
    def current_hunk(self) -> int:
        return self._current

    def select_hunk(self, index: int) -> bool:
        """Move both panes to hunk ``index``; False (and no change) when it does not exist."""
        if not 0 <= index < len(self._hunks):
            return False
        self._current = index
        for pane in self.panes.values():
            self._place(pane, self._hunks[index].start)
        self.hunk_changed.emit(index)
        return True

    def next_hunk(self) -> bool:
        """Select the next hunk (the first when none is current). False at the last one: no wrap, so the caller
        can continue into the next function."""
        return self.select_hunk(self._current + 1)

    def previous_hunk(self) -> bool:
        return self.select_hunk(len(self._hunks) - 1 if self._current < 0 else self._current - 1)

    def reveal(self, side: str, start: int, end: int) -> bool:
        """Scroll ``side`` to original lines ``start``..``end`` (one-based, inclusive) and mark them on the anchor
        layer. False, with nothing changed, when the lines are not shown (unknown, or past the truncation)."""
        mapping = self._maps[_side(side)]
        if not 1 <= start <= end or end > len(mapping):
            return False
        first, last = mapping[start - 1], mapping[end - 1]
        color = ensure_contrast(self._tokens.focus_ring, self._tokens.text, self._tokens.surface_alt)
        selection = row_selection(self.panes[side], first, last, color)
        if selection is None:
            return False
        compose_selections(self.panes[side], 'anchor', [selection])
        self._place(self.panes[side], first)
        return True

    def _place(self, pane: QPlainTextEdit, row: int) -> None:
        block = pane.document().findBlockByNumber(row)
        if block.isValid():
            pane.setTextCursor(QTextCursor(block))
            pane.centerCursor()

    # --- scrolling ---

    @property
    def sync_scroll(self) -> bool:
        return self._sync

    @sync_scroll.setter
    def sync_scroll(self, enabled: bool) -> None:
        self._sync = bool(enabled)

    def _follow(self, kind: str, other: str, value: int) -> None:
        if not self._sync or self._syncing:
            return
        self._syncing = True
        try:
            getattr(self.panes[other], kind)().setValue(value)
        finally:
            self._syncing = False

    # --- highlighter slot ---

    def attach_highlighter(self, side: str, factory: Callable[[QTextDocument], QSyntaxHighlighter]) -> QSyntaxHighlighter:
        """Create the side's highlighter with the pane's document as its parent and keep it (a highlighter only
        Python references can be collected, which aborts the process). Install the model before ``set_pair``:
        attaching to a non-empty document queues a one-off full rehighlight."""
        self.detach_highlighter(side)
        document = self.panes[_side(side)].document()
        highlighter = factory(document)
        if highlighter.document() is not document or highlighter.parent() is not document:
            highlighter.setDocument(None)
            raise ValueError('the highlighter must be parented to the document it is given')
        self._highlighters[side] = highlighter
        return highlighter

    def detach_highlighter(self, side: str) -> None:
        highlighter = self._highlighters.pop(_side(side), None)
        if highlighter is not None:
            highlighter.setDocument(None)
            highlighter.deleteLater()


def _side(side: str) -> str:
    if side not in SIDES:
        raise ValueError(f'side must be older or newer, not {side!r}')
    return side


__all__ = ['CodeDiffView', 'LAYERS', 'MAX_VIEW_CHARS', 'TRUNCATION_NOTICE', 'clear_selections', 'compose_selections',
           'hunk_background']
