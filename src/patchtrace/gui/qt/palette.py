"""The command palette (GUI plan 8.3): a transient popup that is a child of the main window, not a window.

Search box plus list over every command: panel commands, the host's panel commands and every action in the menus
and toolbars. Disabled commands stay listed as "(unavailable: reason)". Plain substring filter on title and
keywords (no fuzzy dependency), at most `PALETTE_RESULTS` rows, Enter runs, Escape closes. The result count is
announced politely after 300 ms without typing. The palette never holds a command it cannot name: titles are
sanitized text, shown as plain text.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtWidgets import QFrame, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from ..registry import PALETTE_RESULTS
from ..text import LABEL_LIMIT, sanitize_text
from ..tips import apply_tip
from .state_view import Announcer

IDLE_MS = 300
RECENT_LIMIT = 8
RECENT_KEY = 'gui/palette/recent'


@dataclass(frozen=True, slots=True)
class PaletteEntry:
    id: str
    title: str
    run: Callable[[], None]
    keywords: tuple[str, ...] = ()
    shortcut: str = ''
    enabled: bool = True
    reason: str = ''  # why a disabled command cannot run now

    def label(self) -> str:
        text = sanitize_text(self.title, LABEL_LIMIT)
        if self.shortcut:
            text += f'  [{sanitize_text(self.shortcut, 40)}]'
        return text if self.enabled else f'{text}  (unavailable: {sanitize_text(self.reason or "not available now", 120)})'


def matches(entries: Iterable[PaletteEntry], query: str, recent: tuple[str, ...] = ()) -> list[PaletteEntry]:
    """Entries whose title or a keyword contains every word of `query`. An empty query lists recently run commands
    first, then the rest in their given order."""
    words = query.casefold().split()
    found = [entry for entry in entries
             if all(word in ' '.join((entry.title, *entry.keywords)).casefold() for word in words)]
    if not words and recent:
        rank = {command_id: index for index, command_id in enumerate(recent)}
        found.sort(key=lambda entry: rank.get(entry.id, len(rank)))  # stable: the rest keep their order
    return found[:PALETTE_RESULTS]


class CommandPalette(QFrame):
    """Overlay on the main window. `source()` is asked for the entries each time it opens, so panels built later and
    availability changes are always current."""

    def __init__(self, window: QWidget, source: Callable[[], list[PaletteEntry]], settings: object | None = None,
                 announcer: Announcer | None = None, status: Callable[[str], None] | None = None) -> None:
        super().__init__(window)
        self._source, self._settings, self._announcer, self._status = source, settings, announcer, status
        self._entries: list[PaletteEntry] = []
        self._shown: list[PaletteEntry] = []
        self._return_to: QWidget | None = None
        self.setObjectName('gui.palette_frame')
        self.setAccessibleName('Command palette')
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.search = QLineEdit()
        self.search.setObjectName('gui.palette')
        self.search.setAccessibleName('Search commands')
        self.search.setClearButtonEnabled(False)
        self.results = QListWidget()
        self.results.setObjectName('gui.palette_list')
        self.results.setAccessibleName('Matching commands')
        apply_tip(self.search, 'gui.palette')
        apply_tip(self.results, 'gui.palette_list')
        layout = QVBoxLayout(self)
        layout.addWidget(self.search)
        layout.addWidget(self.results)
        self._idle = QTimer(self)
        self._idle.setSingleShot(True)
        self._idle.setInterval(IDLE_MS)
        self._idle.timeout.connect(self._announce_count)
        self.search.textChanged.connect(self._filter)
        self.search.installEventFilter(self)
        self.results.itemActivated.connect(self._activated)
        self.hide()

    # ---- opening and closing -----------------------------------------------------------------

    def open(self) -> None:
        self._return_to = self.window().focusWidget()
        self._entries = self._source()
        self.search.clear()
        self._filter('')
        width = max(360, min(640, self.parentWidget().width() * 2 // 3))
        self.setGeometry((self.parentWidget().width() - width) // 2, 24, width, min(360, self.parentWidget().height() - 48))
        self.show()
        self.raise_()
        self.search.setFocus()

    def close_palette(self) -> None:
        self._idle.stop()
        self.hide()
        if self._return_to is not None:
            self._return_to.setFocus()
            self._return_to = None

    # ---- filtering and running ---------------------------------------------------------------

    def _recent(self) -> tuple[str, ...]:
        value = self._settings.value(RECENT_KEY) if self._settings is not None else None
        if isinstance(value, str):
            value = [value]
        return tuple(item for item in value if isinstance(item, str)) if isinstance(value, list | tuple) else ()

    def _filter(self, query: str) -> None:
        self._shown = matches(self._entries, query, self._recent())
        self.results.clear()
        for entry in self._shown:
            item = QListWidgetItem(entry.label())
            item.setData(Qt.ItemDataRole.UserRole, entry.id)
            self.results.addItem(item)
        if self._shown:
            self.results.setCurrentRow(0)
        self._idle.start()

    def _announce_count(self) -> None:
        if self._announcer is not None:
            count = len(self._shown)
            self._announcer.announce(f'{count} command{"" if count == 1 else "s"}')

    def _activated(self, item: QListWidgetItem) -> None:
        self.run_entry(self._shown[self.results.row(item)])

    def run_current(self) -> None:
        row = self.results.currentRow()
        if 0 <= row < len(self._shown):
            self.run_entry(self._shown[row])

    def run_entry(self, entry: PaletteEntry) -> None:
        if not entry.enabled:
            if self._status is not None:  # explain, and stay open so another command can be chosen
                self._status(f'{sanitize_text(entry.title)} is unavailable: {sanitize_text(entry.reason or "not available now")}')
            return
        self.close_palette()
        self._remember(entry.id)
        entry.run()

    def _remember(self, command_id: str) -> None:
        if self._settings is None:
            return
        recent = [command_id, *(item for item in self._recent() if item != command_id)]
        self._settings.setValue(RECENT_KEY, recent[:RECENT_LIMIT])

    # ---- keys ----------------------------------------------------------------------------------

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        kind = event.type()
        if watched is self.search and kind in (QEvent.Type.KeyPress, QEvent.Type.ShortcutOverride):
            key = event.key()
            if key == Qt.Key.Key_Escape:  # the window's Escape ("Cancel job") must not fire while the palette is open
                if kind == QEvent.Type.ShortcutOverride:
                    event.accept()
                else:
                    self.close_palette()
                return True
            if kind == QEvent.Type.KeyPress and key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self.run_current()
                return True
            if kind == QEvent.Type.KeyPress and key in (Qt.Key.Key_Up, Qt.Key.Key_Down):
                step = -1 if key == Qt.Key.Key_Up else 1
                self.results.setCurrentRow(max(0, min(self.results.count() - 1, self.results.currentRow() + step)))
                return True
        return super().eventFilter(watched, event)
