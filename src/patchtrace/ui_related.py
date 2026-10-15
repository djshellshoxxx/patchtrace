"""Qt presentation of the Related evidence dock (FAB-integration-plan.md s8, slice FAB-6; table-only first release).

Responsibility: list the anchors the fabric holds for the selected function pair and route one to the panel that owns
it. What is said lives in the Qt-free `fabric.related`; this module moves it to widgets. Pages of anchors are read and
prepared by a worker on one task channel (a new selection supersedes the last, late results are dropped); the GUI
thread only swaps the prepared table. The dock never opens a window of its own.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QComboBox, QSplitter, QVBoxLayout, QWidget

from .fabric.contracts import KINDS, Anchor, AnchorQuery
from .fabric.limits import FabricError
from .fabric.panel import TIPS
from .fabric.ports import AnchorReader
from .fabric.related import (
    COLUMNS,
    DETAIL_NONE,
    KIND_TITLES,
    PAGE_ROWS,
    SPEC,
    TITLE,
    RelatedRow,
    anchor_ref,
    related_state,
    rows_of,
)
from .gui.anchors import AnchorRef, NavResult
from .gui.qt.docks import ControllerBase
from .gui.qt.labels import SafeTextView
from .gui.qt.state_view import StateView
from .gui.qt.table import VirtualTable
from .gui.registry import PanelContext
from .gui.state import StateModel
from .gui.table_spec import MAX_ROWS, PreparedTable, prepare_table
from .gui.text import sanitize_text
from .gui.tips import apply_tip, register_gui_tips, register_tips

CHANNEL = 'related.load'
PANEL_NAME = 'Related evidence panel'
TABLE_NAME = 'Related evidence table'
FILTER_NAME = 'Kind filter'
DETAIL_NAME = 'Related evidence detail'
ALL_KINDS = 'All kinds'
Subject = Callable[[Any, str], 'str | None']
ReaderFactory = Callable[[Any], 'AnchorReader | None']


@dataclass(frozen=True, slots=True)
class Loaded:
    """What a worker hands back: the prepared table, or the error that stopped it (a code and a short message)."""
    prepared: PreparedTable
    rows: tuple[RelatedRow, ...]
    error: tuple[str, str] | None = None


def fetch(reader: AnchorReader, project_id: str, subject: str, token: Any, report: Callable) -> Loaded:
    """Worker: read every page of the subject's anchors (500 rows each, canonical order) and prepare the table. More
    than `MAX_ROWS` anchors stop the read, and the table then says it is too large."""
    anchors: list[Anchor] = []
    total = 0
    try:
        while True:
            token.raise_if_cancelled()
            page = reader.find(project_id, AnchorQuery(subject=subject, offset=len(anchors), limit=PAGE_ROWS))
            total = page.total
            anchors.extend(page.items)
            report('reading', len(anchors), total)
            if not page.items or len(anchors) >= total or len(anchors) > MAX_ROWS:
                break
    except FabricError as exc:
        empty = prepare_table(SPEC, COLUMNS, ())
        return Loaded(empty, (), (exc.code, sanitize_text(exc.message, 200)))
    rows = rows_of(anchors)
    return Loaded(prepare_table(SPEC, COLUMNS, rows, token), rows)


def default_subject(port: Any, match_id: str) -> str | None:
    """The `pair:` key of a comparison row, when its functions have relative addresses (an RVA); else None."""
    from .fabric.ids import pair_key
    project = port.project()
    match = next((m for m in getattr(project, 'matches', ()) if m.id == match_id), None)
    if match is None:
        return None
    older_sha, newer_sha = port.artifact_paths()[2:]
    sides = []
    for functions in (match.older, match.newer):
        rvas = []
        for function in functions:
            try:
                if function.address_space != 'relative' or function.address is None:
                    return None
                rvas.append(int(function.address, 0))
            except ValueError:
                return None
        sides.append(rvas)
    try:
        return pair_key(older_sha, newer_sha, sides[0], sides[1])
    except FabricError:
        return None


def default_reader(port: Any) -> AnchorReader | None:
    from .enrichment.storage import EnrichmentStore
    from .fabric.store import EnrichmentAnchorStore
    service = getattr(port, 'service', None)
    return None if service is None else EnrichmentAnchorStore(EnrichmentStore(service.store))


class RelatedPanel(QWidget):
    """The widgets. It holds no state of the result: the controller feeds it."""

    kind_changed = Signal(str)

    def __init__(self, announcer: Any = None) -> None:
        super().__init__()
        self.setObjectName('related.panel')
        self.setAccessibleName(PANEL_NAME)
        self.state = StateView('related', TITLE, announcer, text_limit=400)
        self.table = VirtualTable(TABLE_NAME)
        self.kind = QComboBox()
        self.kind.setAccessibleName(FILTER_NAME)
        self.kind.view().setAccessibleName(f'{FILTER_NAME} list')
        self.kind.addItem(ALL_KINDS, '')
        for kind in KINDS:
            self.kind.addItem(KIND_TITLES[kind], kind)
        self.detail = SafeTextView(DETAIL_NAME, wrap=True)
        self.detail.setPlainText(DETAIL_NONE)
        apply_tip(self.table, 'related.table')
        apply_tip(self.kind, 'related.kind_filter')
        apply_tip(self.detail, 'related.detail')
        self.table.set_prepared(prepare_table(SPEC, COLUMNS, ()))
        self.kind.currentIndexChanged.connect(lambda _i: self.kind_changed.emit(self.kind.currentData() or ''))
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.kind)
        column.addWidget(self.table, 1)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(body)
        splitter.addWidget(self.detail)
        splitter.setChildrenCollapsible(False)
        self.state.set_content(splitter)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.state, 1)
        self.setFocusProxy(self.table)


class RelatedController(ControllerBase):
    """Owns the subject, the loaded rows and the one request in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, reader: ReaderFactory = default_reader,
                 subject_of: Subject = default_subject) -> None:
        register_gui_tips()
        register_tips(TIPS)
        panel = RelatedPanel(getattr(ctx.shell, 'announcer', None))
        super().__init__(panel)
        self.panel, self.ctx, self.port, self.tasks = panel, ctx, ctx.project, ctx.tasks
        self.reader_factory, self.subject_of = reader, subject_of
        self.key = None
        self.subject: str | None = None
        self.rows: tuple[RelatedRow, ...] = ()
        self.total = 0
        self.loading = False
        self.error: tuple[str, str] | None = None
        panel.kind_changed.connect(self._kind_changed)
        panel.table.activated_key.connect(self._activated)
        panel.table.detail_requested.connect(self._detail)
        panel.table.selectionModel().currentRowChanged.connect(lambda *_: self._current_changed())
        panel.state.refresh_requested.connect(self.reload)
        panel.state.retry_requested.connect(self.reload)
        panel.state.copy_requested.connect(lambda text: ctx.shell.copy_text(text))
        self._render()

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key: Any) -> None:
        self.tasks.cancel(CHANNEL)
        self.key, self.subject = key, None
        self._reset()
        self._render()

    def selection_changed(self, match_id: str | None) -> None:
        self.subject = None if match_id is None or self.key is None else self.subject_of(self.port, match_id)
        self.reload()

    def shutdown(self) -> None:
        self.tasks.cancel(CHANNEL)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        row = next((r for r in self.rows if r.anchor.key == anchor.key and r.kind == anchor.kind), None)
        if row is None:
            return NavResult.not_found(anchor.label or anchor.key, anchor.run_id)
        self.select_key(row.key)
        return NavResult.shown()

    # ---- loading -------------------------------------------------------------------------------------

    def _reset(self) -> None:
        self.rows, self.total, self.loading, self.error = (), 0, False, None
        self.panel.table.set_prepared(prepare_table(SPEC, COLUMNS, ()))
        self.panel.detail.setPlainText(DETAIL_NONE)

    def reload(self) -> None:
        self.tasks.cancel(CHANNEL)
        self._reset()
        project = self.port.project()
        reader = self.reader_factory(self.port) if self.subject and project is not None else None
        if reader is None or self.subject is None:
            return self._render()
        self.loading = True
        subject, project_id = self.subject, project.id
        self.tasks.submit(CHANNEL, lambda token, report: fetch(reader, project_id, subject, token, report),
                          self._loaded, self._failed)
        self._render()

    def _loaded(self, loaded: Loaded) -> None:
        self.loading, self.error = False, loaded.error
        self.rows, self.total = loaded.rows, loaded.prepared.total
        self.panel.table.set_prepared(loaded.prepared)
        self._render()

    def _failed(self, failure: Any) -> None:
        self.loading = False
        self.error = (failure.code, failure.exception_class)
        self._render()

    # ---- view ----------------------------------------------------------------------------------------

    def _render(self) -> None:
        table = self.panel.table
        state: StateModel = related_state(
            has_project=self.key is not None, subject=self.subject, loading=self.loading, error=self.error,
            total=self.total, too_large=table.too_large)
        self.panel.state.set_state(state, has_content=bool(self.rows))
        self.panel.kind.setEnabled(bool(self.rows))

    def _kind_changed(self, kind: str) -> None:
        self.panel.table.set_filter('', (lambda row: row.kind == kind) if kind else None)

    def select_key(self, key: str) -> None:
        table = self.panel.table
        view_row = table.table_model.view_row_of(key)
        if view_row >= 0:
            table.selectRow(view_row)
            table.setCurrentIndex(table.table_model.index(view_row, 0))
            self._detail(key)

    def _row(self, key: str) -> RelatedRow | None:
        model = self.panel.table.table_model
        view_row = model.view_row_of(key)
        return model.row_at(view_row) if view_row >= 0 else None

    def _current_changed(self) -> None:
        key = self.panel.table.current_key()
        row = self._row(key) if key else None
        self.panel.detail.setPlainText(row.detail if row else DETAIL_NONE)

    def _detail(self, key: str) -> None:
        row = self._row(key)
        if row is not None:
            self.panel.detail.setPlainText(row.detail)
            self.panel.detail.setFocus()

    def _activated(self, key: str) -> None:
        row = self._row(key)
        if row is None:
            return
        run_id = getattr(self.key, 'run_id', None)
        result = self.ctx.nav.navigate(anchor_ref(row.anchor, run_id).pinned(self.key))
        message = getattr(result, 'message', '')
        if getattr(result, 'status', 'shown') != 'shown' and message:
            self.ctx.announce(message)


