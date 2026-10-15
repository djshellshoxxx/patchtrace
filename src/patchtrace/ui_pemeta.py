"""Qt presentation of the PE build-facts tab (WBQ S6): short facts, the imported-API delta and the notes that explain
a gap. A self-contained widget the Files panel hosts as a tab ("Build facts"); it owns no thread and no project
state. The pure side (rows, copy, state, preparation) is `pemeta_view`.

The long list uses the framework `VirtualTable` over a `PreparedTable` built off the GUI thread, so 100,000 rows cost
what they show. Enter on an API row emits `show_callers(dll, name)`; the host decides what that navigates to.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QLineEdit, QSplitter, QVBoxLayout, QWidget

from .gui.qt.labels import PlainLabel
from .gui.qt.state_view import Announcer, StateView
from .gui.qt.table import VirtualTable
from .gui.state import StateModel
from .gui.table_spec import prepare_table
from .gui.tips import apply_tip, register_gui_tips, register_tips
from .pemeta_view import (
    API_COLUMNS,
    API_SPEC,
    FACT_COLUMNS,
    FACT_SPEC,
    LOADING,
    TITLE,
    PeMetaSnapshot,
    PreparedMeta,
    panel_state,
    prepare_meta,
)
from .tooltips import TooltipEntry

FACTS_NAME = 'Version and build facts'
API_NAME = 'Imported API changes'
FILTER_NAME = 'Filter imported API changes'
RICH_NOTE = 'Not a finding: a toolchain change usually explains many cosmetic differences.'
TIPS = {
    'overview.pe_meta_table': TooltipEntry(
        'Version, manifest and import facts of the older and the newer file, side by side.',
        'See what the build records say before reading any code.',
        'Read-only display; nothing is executed and no value is a finding by itself.',
        'Version and manifest resources and the import table of the verified artifact copies.',
        'Needs an open project whose files are PE images.'),
    'overview.api_delta_table': TooltipEntry(
        'Imported functions that only the newer file (added) or only the older file (removed) lists.',
        'A new import is a lead to inspect, not evidence of a change in behaviour.',
        'Read-only; Enter asks for the callers of the selected function.',
        'The static import table only; delay-load and runtime-resolved imports are not parsed.',
        'Needs both import tables to be readable.'),
    'overview.api_delta_filter': TooltipEntry(
        'Narrow the imported-API changes to those whose DLL or name contains the text.',
        'Find one function among thousands of changes.',
        'Only changes what is listed; the result is not modified.'),
}


class PeMetaWidget(QWidget):
    """The tab. `set_prepared` takes the result of `prepare_meta` (built by a worker); `set_snapshot` prepares inline
    for the small cases and tests."""

    show_callers = Signal(str, str)  # DLL, API name

    def __init__(self, announcer: Announcer | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        register_gui_tips()  # idempotent: the host has done it, a test or a bare embed has not
        register_tips(TIPS)
        self.setObjectName('pemeta.widget')
        self.setAccessibleName(f'{TITLE} panel')
        self._prepared: PreparedMeta | None = None
        self.state = StateView('pemeta', TITLE, announcer)
        self.facts = VirtualTable(FACTS_NAME)
        self.api = VirtualTable(API_NAME)
        self.filter = QLineEdit()
        self.filter.setAccessibleName(FILTER_NAME)
        self.filter.setPlaceholderText('Filter by DLL or name')
        self.notes = PlainLabel(wrap=True, limit=4000, multiline=True, selectable=True)
        self.notes.setAccessibleName('Notes on the build facts')
        self.hint = PlainLabel(RICH_NOTE, wrap=True)
        apply_tip(self.facts, 'overview.pe_meta_table')
        apply_tip(self.api, 'overview.api_delta_table')
        apply_tip(self.filter, 'overview.api_delta_filter')
        self.facts.set_prepared(prepare_table(FACT_SPEC, FACT_COLUMNS, ()))
        self.api.set_prepared(prepare_table(API_SPEC, API_COLUMNS, ()))
        self.filter.textChanged.connect(self.api.set_filter)
        self.api.activated_key.connect(self._activated)
        self.state.set_content(self._content())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.state, 1)
        self.setFocusProxy(self.facts)

    def _content(self) -> QWidget:
        lower = QWidget()
        column = QVBoxLayout(lower)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.filter)
        column.addWidget(self.api, 1)
        splitter = QSplitter(Qt.Orientation.Vertical)
        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.addWidget(self.facts, 1)
        top_layout.addWidget(self.notes)
        top_layout.addWidget(self.hint)
        splitter.addWidget(top)
        splitter.addWidget(lower)
        splitter.setChildrenCollapsible(False)
        return splitter

    def set_loading(self) -> None:
        self._prepared = None
        self.state.set_state(StateModel('loading', LOADING))

    def set_no_project(self) -> None:
        self._prepared = None
        self.state.set_state(panel_state(None, has_project=False))

    def set_snapshot(self, snapshot: PeMetaSnapshot) -> None:
        self.set_prepared(prepare_meta(snapshot))

    def set_prepared(self, prepared: PreparedMeta) -> None:
        self._prepared = prepared
        self.facts.set_prepared(prepared.facts)
        self.api.set_prepared(prepared.api)
        self.filter.setEnabled(bool(prepared.api.total))
        self.notes.setText('\n'.join(prepared.notes))
        self.notes.setVisible(bool(prepared.notes))
        self.state.set_state(prepared.state, has_content=True)

    def _activated(self, key: str) -> None:
        row = self.api.table_model.view_row_of(key)
        change = self.api.table_model.row_at(row) if row >= 0 else None
        if change is not None:
            self.show_callers.emit(change.dll, change.name)

