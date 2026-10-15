"""Qt side of code colours and token marks (WBQ S9): a windowed `QSyntaxHighlighter` per code pane, the "Line changes"
label and the F8 walk. The pure parts are `codetext` (tokens, marks, model) and `codetext_view` (copy, window, looks).

Lifetime and cost rules, each with a test (tests/test_ui_codetext.py):
* a highlighter is parented to its pane's document (a Python-only reference can be collected and abort the process);
* nothing calls `rehighlight()`; block state is always -1 (a state change cascades through every following block);
* the model and the window are installed BEFORE the text is set, so Qt's first pass formats only the window;
* `highlightBlock` fails closed: an exception turns colours off for the session and posts the notice, never a crash;
* a format never sets a family or size (the pane's font owns them) and never bold when bold changes the advance;
* the panes' extra selections (hunks, search hits) are untouched: syntax lives in character formats.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextDocument,
    QTextOption,
)
from PySide6.QtWidgets import QPlainTextEdit

from .codetext import CodeTextModel, FormatSpan, Language, Palette, StyleKey
from .codetext_view import (
    DISABLED_AFTER_ERROR,
    LABEL_NAME,
    NO_CHANGE_STOP,
    SCAN_LIMITED,
    TIPS,
    WINDOW_MARGIN,
    Look,
    look,
    model_for_pair,
    window_bounds,
)
from .gui.pair_text import PairText
from .gui.qt.labels import PlainLabel
from .gui.tips import apply_tip, register_gui_tips, register_tips

_UNDERLINES = {'single': QTextCharFormat.UnderlineStyle.SingleUnderline,
               'dotted': QTextCharFormat.UnderlineStyle.DotLine,
               'dashed': QTextCharFormat.UnderlineStyle.DashUnderline}


class CodeHighlighter(QSyntaxHighlighter):
    """Formats the blocks of one pane that lie inside the controller's window; everything else stays plain."""

    def __init__(self, document: QTextDocument, side: str, controller: CodeTextController) -> None:
        super().__init__(document)
        self._side = side
        self._controller = controller

    def highlightBlock(self, text: str) -> None:  # noqa: N802 (Qt name)
        self.setCurrentBlockState(-1)
        controller = self._controller
        try:
            for span in controller.spans(self._side, self.currentBlock().blockNumber(), text):
                self.setFormat(span.start, span.length, controller.format_for(span.style_key))
        except Exception:  # noqa: BLE001 - fail closed: plain text and a notice, never an exception into Qt
            controller.fail()


class CodeTextController(QObject):
    """Owns the highlighters, the model and the window of the two code panes.

    Order of use: `begin(pair, language)` BEFORE the panes get their text, then the caller sets the text (a
    `CodeDiffView.set_pair`, or `setPlainText` on legacy panes), then `finish()`. `show_pair` does the three for a
    `CodeDiffView`. `configure` is the Setup toggles; both off removes the highlighters and restores plain text."""

    notice = Signal(str)  # a status line for the host (the error notice)
    walked = Signal(int)  # the row the F8 walk moved to

    def __init__(self, older: QPlainTextEdit, newer: QPlainTextEdit, *, announce: Callable[[str], None] | None = None,
                 palette: Palette | None = None, live_base: Callable[[], str | None] | None = None,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        register_gui_tips()
        register_tips(TIPS)
        self._panes = {'older': older, 'newer': newer}
        self._announce = announce or (lambda text: None)
        self._palette = palette or Palette('dark')
        # The app themes by stylesheet, so QPalette.Base says nothing about what is drawn: the host that knows the
        # real pane colour passes it here and the runtime guard checks every colour against it as well.
        self._live_base = live_base or (lambda: None)
        self._colors = self._marks = False
        self._failed = False
        self._model: CodeTextModel | None = None
        self._source: tuple[PairText, Language, tuple[int, ...]] | None = None
        self._windows: dict[str, tuple[int, int]] = {'older': (0, -1), 'newer': (0, -1)}
        self._marked: dict[str, set[int]] = {'older': set(), 'newer': set()}
        self._formats: dict[tuple, QTextCharFormat] = {}
        self._highlighters: dict[str, CodeHighlighter] = {}
        self._last_summary = ''
        self.label = PlainLabel(wrap=True, limit=600)
        self.label.setAccessibleName(LABEL_NAME)
        apply_tip(self.label, 'viewer.line_changes')
        for pane in self._panes.values():
            pane.verticalScrollBar().valueChanged.connect(self.refresh)
            pane.cursorPositionChanged.connect(self._cursor_moved)

    # -- configuration --

    @property
    def enabled(self) -> bool:
        return (self._colors or self._marks) and not self._failed

    def configure(self, colors: bool, marks: bool) -> None:
        """Switch code colours and token marks. Rebuilds the model from the last pair, so no text is set again."""
        if self._failed:
            return
        self._colors, self._marks = colors, marks
        self._rebuild()

    def _rebuild(self) -> None:
        self._formats.clear()
        if not self.enabled:
            self._detach()
            self._model = None
            self.label.setText('')
            return
        self._attach()
        if self._source is not None:
            pair, language, chrome = self._source
            self._model = model_for_pair(pair, language, chrome=chrome, colors=self._colors, marks=self._marks)
        self._clear_marked()
        self.refresh()

    def _clear_marked(self) -> None:
        for rows in self._marked.values():
            rows.clear()

    def _attach(self) -> None:
        for side, pane in self._panes.items():
            if side not in self._highlighters:
                self._highlighters[side] = CodeHighlighter(pane.document(), side, self)

    def _detach(self) -> None:
        for highlighter in self._highlighters.values():
            highlighter.setDocument(None)  # clears the formats it drew
            highlighter.setParent(None)
            highlighter.deleteLater()
        self._highlighters.clear()

    # -- the three steps around a text change --

    def begin(self, pair: PairText, language: Language | None, chrome: Iterable[int] = ()) -> None:
        """Install the model and the first window. Call BEFORE the text changes; the old model is dropped first."""
        self._model = None
        self._clear_marked()
        self._last_summary = ''
        self._source = None if language is None else (pair, language, tuple(chrome))
        self.label.setText('')
        if language is None or not self.enabled:
            return
        self._attach()
        self._model = model_for_pair(pair, language, chrome=self._source[2], colors=self._colors, marks=self._marks)
        self._windows = dict.fromkeys(self._panes, (0, WINDOW_MARGIN + self._visible_rows()))

    def finish(self) -> None:
        """Call after the text is set: compute the first window's marks and format it."""
        self._clear_marked()
        self.refresh()

    def show_pair(self, view, pair: PairText, language: Language | None, provenance: tuple[str, str] = ('', ''),
                  chrome: Iterable[int] = ()) -> None:
        """`begin`, `view.set_pair(pair, provenance)`, `finish` for a `CodeDiffView`."""
        self.begin(pair, language, chrome)
        view.set_pair(pair, provenance)
        self.finish()

    # -- the highlighter's questions --

    def spans(self, side: str, row: int, text: str) -> Sequence[FormatSpan]:
        model = self._model
        if model is None or self._failed or not self._windows[side][0] <= row <= self._windows[side][1]:
            return ()
        return model.spans(side, row, text)

    def fail(self) -> None:
        """An exception inside a highlighter: stop colouring now, detach on the next event-loop turn (detaching
        inside `highlightBlock` would re-enter Qt)."""
        if self._failed:
            return
        self._failed = True
        self._model = None
        self.notice.emit(DISABLED_AFTER_ERROR)
        QTimer.singleShot(0, self._rebuild)

    def format_for(self, key: StyleKey) -> QTextCharFormat:
        live = self._live_base()
        cache_key = (key, live, self._colors)
        found = self._formats.get(cache_key)
        if found is None:
            grounds = (*self._palette.backgrounds, *([live] if live else []))
            found = self._formats[cache_key] = self._build(look(key, self._palette, grounds, colors=self._colors),
                                                           self._panes['older'].font())
        return found

    @staticmethod
    def _build(spec: Look, font: QFont) -> QTextCharFormat:
        fmt = QTextCharFormat()  # no family and no size: apply_font owns them
        if spec.color is not None:
            fmt.setForeground(QColor(spec.color))
        if spec.bold and _bold_keeps_advance(font):
            fmt.setFontWeight(QFont.Weight.Bold)
        if spec.italic:
            fmt.setFontItalic(True)
        if spec.underline is not None:
            fmt.setUnderlineStyle(_UNDERLINES[spec.underline])
            fmt.setUnderlineColor(QColor(spec.underline_color))
        return fmt

    # -- the window --

    def _visible_rows(self) -> int:
        pane = self._panes['older']
        return pane.viewport().height() // max(1, QFontMetrics(pane.font()).lineSpacing()) + 1

    def refresh(self, *_: object) -> None:
        """Move the window to the visible blocks, compute the marks inside it (bounded), and format the blocks that
        have not been formatted with them yet. Cost is the window, never the document."""
        model = self._model
        if model is None or self._failed:
            return
        pending = 0
        for side, pane in self._panes.items():
            first, last = self._windows[side] = window_bounds(pane.firstVisibleBlock().blockNumber(),
                                                              self._visible_rows(), model.rows)
            pending += model.refresh(first, last).pending
            highlighter = self._highlighters.get(side)
            if highlighter is None:
                continue
            for number in range(first, last + 1):
                if number in self._marked[side]:
                    continue
                block = pane.document().findBlockByNumber(number)
                if block.isValid():
                    highlighter.rehighlightBlock(block)
            if not pending:
                self._marked[side].update(range(first, last + 1))
        if pending:
            QTimer.singleShot(0, self.refresh)  # the per-call limit left rows without marks: continue next turn

    # -- the label and the F8 walk --

    def _cursor_moved(self) -> None:
        model = self._model
        if model is None:
            return
        sender = self.sender()
        pane = sender if isinstance(sender, QPlainTextEdit) else self._panes['older']
        text = model.summary(pane.textCursor().blockNumber())
        self.label.setText(text)
        if text and text != self._last_summary:
            self._announce(text)
        self._last_summary = text

    def step_change(self, step: int) -> bool:
        """Move both panes to the next (`step` > 0) or previous row with a `changed` mark. False, with the reason
        announced, when there is none or the scan stopped at its limit."""
        model = self._model
        if model is None or not self._marks:
            return False
        focus = next((pane for pane in self._panes.values() if pane.hasFocus()), self._panes['older'])
        found = model.find_change(focus.textCursor().blockNumber(), step)
        if found.row is None:
            self._announce(NO_CHANGE_STOP if found.complete else SCAN_LIMITED)
            return False
        for pane in self._panes.values():
            block = pane.document().findBlockByNumber(found.row)
            cursor = pane.textCursor()
            cursor.setPosition(block.position())
            pane.setTextCursor(cursor)
            pane.centerCursor()
        self.walked.emit(found.row)
        return True

    # -- theme and teardown --

    def theme_changed(self) -> None:
        self._formats.clear()
        self._clear_marked()
        self.refresh()

    def set_suppress_colors(self, suppress: bool) -> None:
        """High-contrast or "no syntax colours": drop foreground colours; underline, bold and italic survive."""
        for pane in self._panes.values():
            option = pane.document().defaultTextOption()
            flags = option.flags()
            option.setFlags(flags | QTextOption.Flag.SuppressColors if suppress
                            else flags & ~QTextOption.Flag.SuppressColors)
            pane.document().setDefaultTextOption(option)

    def shutdown(self) -> None:
        self._detach()
        self._model = None


def _bold_keeps_advance(font: QFont) -> bool:
    """Bold in a monospace font must not change the character advance, or columns would drift."""
    bold = QFont(font)
    bold.setBold(True)
    sample = 'MWi.0 '
    return QFontMetrics(bold).horizontalAdvance(sample) == QFontMetrics(font).horizontalAdvance(sample)

