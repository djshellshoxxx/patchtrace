"""Qt presentation for the read-only Series panel (SPEC-09b section 6, GUI plan M3): one tab per series.json.

Responsibility: run :func:`patchtrace.nway.view_model.load_view` on a dedicated QThread and
render the resulting immutable rows. All domain logic lives in ``nway.view_model`` and
``nway.pair_access``; this module only moves a ``SeriesView`` to widgets and forwards intents.
Strings that come from series files or projects are always shown as plain text.
"""
from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, Qt, QThread, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .gui.qt.docks import ControllerBase
from .gui.qt.labels import PlainLabel
from .gui.registry import PanelContext
from .nway.contracts import NwayError
from .nway.pair_access import DiskPairReader, PairReader
from .nway.view_model import (
    ChainRow,
    HopView,
    LoadedSeries,
    SeriesView,
    ViewQuery,
    apply_query,
    chain_text,
    load_view,
)
from .tooltips import apply_tooltip, clean_value, template

CHAIN_COLUMNS = ('Chain', 'Hops', 'Highest hop', 'Sum', 'Status', 'Events', 'Stale')
HOP_COLUMNS = ('Hop', 'From', 'To', 'Category', 'Match types', 'Ratio', 'Score', 'Pair state')
SORTS = (('Highest hop', 'max-score', True), ('Sum of hops', 'sum-score', True), ('Hop count', 'hops', True),
         ('Name', 'name', False), ('Chain ID', 'chain-id', False))
SCORE_TEXT = {'unchanged': 'unchanged', 'no-ranking': 'n/a', 'pair-unavailable': 'n/a', 'stale-ranking': 'n/a',
              'not-ranked': 'not ranked'}
SCORE_REASON = {
    'scored': 'a stored attention score for this pairing',
    'unchanged': 'the function did not change in this pair, so it is not ranked',
    'no-ranking': 'this pair project has no stored default-profile ranking',
    'pair-unavailable': 'the pair project cannot be read right now',
    'stale-ranking': 'the stored ranking is older than the project',
    'not-ranked': 'the stored ranking has no entry for this pairing'}
REMEDY = 'Check that series.json is intact, or recreate it with `patchtrace series create` ' \
         '(add --replace-corrupt if it is damaged).'
OPENABLE_PAIR_STATES = frozenset({'ok', 'changed'})
_LIVE_THREADS: set[SeriesLoadThread] = set()  # a running QThread must never be garbage collected


def safe(text: object) -> str:
    """Display text from an untrusted source: control characters removed, length capped."""
    return clean_value(text)


class SeriesLoadThread(QThread):
    """Runs load_view off the GUI thread; cancellable; never writes anything."""
    loaded = Signal(object)
    failed = Signal(str)

    def __init__(self, path: Path, reader: PairReader):
        super().__init__()
        self.path, self.reader = Path(path), reader
        self.cancel = threading.Event()
        _LIVE_THREADS.add(self)
        self.finished.connect(self._release)

    def _release(self) -> None:
        _LIVE_THREADS.discard(self)
        self.deleteLater()

    def run(self) -> None:
        try:
            result = load_view(self.path, self.reader, self.cancel)
        except NwayError as exc:
            if exc.code != 'PT-NWAY-CANCEL' and not self.cancel.is_set():
                self.failed.emit(str(exc))
            return
        except Exception as exc:  # a reader bug must degrade to a message, never a crash
            if not self.cancel.is_set():
                self.failed.emit(f'PT-NWAY-STORAGE: unexpected {type(exc).__name__} while reading the series')
            return
        if not self.cancel.is_set():
            self.loaded.emit(result)


class ChainModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: tuple[ChainRow, ...] = ()

    def set_rows(self, rows: tuple[ChainRow, ...]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.rows)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(CHAIN_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return CHAIN_COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        row, column = self.rows[index.row()], index.column()
        return (safe(row.title), str(row.total_hops), '' if row.max_score is None else str(row.max_score),
                '' if row.sum_score is None else str(row.sum_score), row.status,
                ', '.join(sorted({e.kind for e in row.events})), 'STALE' if row.stale else '')[column]


class HopModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.hops: tuple[HopView, ...] = ()

    def set_hops(self, hops: tuple[HopView, ...]) -> None:
        self.beginResetModel()
        self.hops = hops
        self.endResetModel()

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.hops)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(HOP_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return HOP_COLUMNS[section]
        return None

    @staticmethod
    def score_text(hop: HopView) -> str:
        return str(hop.score) if hop.score is not None else SCORE_TEXT.get(hop.score_state, 'n/a')

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        hop, column = self.hops[index.row()], index.column()
        if role == Qt.ItemDataRole.ToolTipRole:
            if column == 6:
                return template('series.score_cell', state=hop.score_state,
                                reason=hop.reason or SCORE_REASON[hop.score_state])
            if column == 7:
                return template('series.pair_state', state=hop.pair_state, reason=hop.reason or 'readable')
            return None
        return (safe(hop.label), safe(hop.from_name), safe(hop.to_name), safe(hop.category),
                safe(', '.join(hop.match_types)), safe(hop.ratio_text or ''), self.score_text(hop),
                hop.pair_state)[column]


class SeriesTab(QWidget):
    """Read-only view of one series.json. Emits intents; owns no domain logic."""
    open_pair_requested = Signal(str, str)  # absolute pair project path, match id

    def __init__(self, series_path: Path, reader: PairReader | None = None, parent: QWidget | None = None):
        super().__init__(parent)
        self.series_path = Path(series_path).resolve()
        self.reader = reader or DiskPairReader()
        self.loaded: LoadedSeries | None = None
        self.view: SeriesView | None = None
        self.thread: SeriesLoadThread | None = None
        apply_tooltip(self, 'series.window')
        self._build()
        self.set_loading()
        self.reload()

    # ---- construction ------------------------------------------------------------------------
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.reload_button = QPushButton('Reload')
        self.cancel_button = QPushButton('Cancel load')
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText('Filter by function, address, label or chain ID')
        self.filter_text.setMaxLength(200)
        self.filter_status = QComboBox()
        self.filter_status.addItems(['All statuses', 'inferred', 'confirmed', 'contradicted'])
        self.filter_event = QComboBox()
        self.filter_event.addItems(['All events', 'added', 'removed', 'split', 'merged', 'ambiguous',
                                    'unmatched', 'reverted'])
        self.only_stale = QCheckBox('Only stale')
        self.only_scored = QCheckBox('Only scored')
        self.min_score = QSpinBox()
        self.min_score.setRange(0, 100)
        self.min_score.setPrefix('Min highest hop ')
        self.sort = QComboBox()
        self.sort.addItems([label for label, _, _ in SORTS])
        for widget in (self.reload_button, self.cancel_button, self.filter_text, self.filter_status,
                       self.filter_event, self.only_stale, self.only_scored, self.min_score, self.sort):
            bar.addWidget(widget)
        layout.addLayout(bar)
        self.banner = QLabel()
        self.banner.setTextFormat(Qt.TextFormat.PlainText)
        self.banner.setWordWrap(True)
        self.banner.hide()
        layout.addWidget(self.banner)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.message = QLabel()
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message.hide()
        layout.addWidget(self.message)
        self.chain_model, self.hop_model = ChainModel(self), HopModel(self)
        self.chain_table, self.hop_table = QTableView(), QTableView()
        for table, model in ((self.chain_table, self.chain_model), (self.hop_table, self.hop_model)):
            table.setModel(model)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.horizontalHeader().setStretchLastSection(True)
        buttons = QHBoxLayout()
        self.open_pair = QPushButton('Open pair at this function')
        self.copy_chain = QPushButton('Copy chain')
        buttons.addWidget(self.open_pair)
        buttons.addWidget(self.copy_chain)
        buttons.addStretch(1)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.addWidget(self.hop_table)
        detail_layout.addLayout(buttons)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.chain_table)
        self.splitter.addWidget(detail)
        layout.addWidget(self.splitter, 1)
        for widget, tip in ((self.reload_button, 'series.reload'), (self.cancel_button, 'series.cancel_load'),
                            (self.filter_text, 'series.filter_text'), (self.filter_status, 'series.filter_status'),
                            (self.filter_event, 'series.filter_event'), (self.only_stale, 'series.only_stale'),
                            (self.only_scored, 'series.only_scored'), (self.min_score, 'series.min_score'),
                            (self.sort, 'series.sort'), (self.banner, 'series.banner'),
                            (self.chain_table, 'series.chain_table'), (self.hop_table, 'series.hop_table'),
                            (self.open_pair, 'series.open_pair'), (self.copy_chain, 'series.copy_chain')):
            apply_tooltip(widget, tip)
        self.reload_button.clicked.connect(self.reload)
        self.cancel_button.clicked.connect(self.cancel_load)
        self.filter_text.textChanged.connect(self.requery)
        for combo in (self.filter_status, self.filter_event, self.sort):
            combo.currentIndexChanged.connect(self.requery)
        for box in (self.only_stale, self.only_scored):
            box.toggled.connect(self.requery)
        self.min_score.valueChanged.connect(self.requery)
        self.chain_table.selectionModel().selectionChanged.connect(self.chain_selected)
        self.hop_table.selectionModel().selectionChanged.connect(self.update_buttons)
        self.open_pair.clicked.connect(self.request_open_pair)
        self.copy_chain.clicked.connect(self.copy_selected_chain)

    # ---- loading -----------------------------------------------------------------------------
    def reload(self, *_) -> None:
        self._retire_thread()
        self.set_loading()
        self.thread = SeriesLoadThread(self.series_path, self.reader)
        self.thread.loaded.connect(self.on_loaded)
        self.thread.failed.connect(self.on_failed)
        self.thread.start()

    def cancel_load(self) -> None:
        self._retire_thread()
        if self.loaded is None:
            self.on_failed('PT-NWAY-CANCEL: loading was cancelled; use Reload to try again')
        else:
            self._show_view()

    def _retire_thread(self) -> None:
        thread, self.thread = self.thread, None
        if thread is not None:
            thread.cancel.set()
            try:
                thread.loaded.disconnect(self.on_loaded)
                thread.failed.disconnect(self.on_failed)
            except (RuntimeError, TypeError):
                pass

    def set_loading(self) -> None:
        self.progress.show()
        self.message.hide()
        self.cancel_button.setEnabled(True)
        self.chain_table.setEnabled(False)
        self.hop_table.setEnabled(False)

    def on_loaded(self, loaded: LoadedSeries) -> None:
        self.thread = None
        self.loaded = loaded
        self._show_view()

    def on_failed(self, message: str) -> None:
        self.thread = None
        self.loaded = LoadedSeries.failed(message)
        self._show_view()

    # ---- rendering ---------------------------------------------------------------------------
    def query(self) -> ViewQuery:
        _, key, descending = SORTS[self.sort.currentIndex()]
        status, event = self.filter_status.currentText(), self.filter_event.currentText()
        return ViewQuery(text=self.filter_text.text(),
                         status=frozenset() if self.filter_status.currentIndex() == 0 else frozenset({status}),
                         event=frozenset() if self.filter_event.currentIndex() == 0 else frozenset({event}),
                         only_stale=self.only_stale.isChecked(), only_scored=self.only_scored.isChecked(),
                         min_score=self.min_score.value(), sort=key, descending=descending)

    def requery(self, *_) -> None:
        if self.loaded is not None and self.thread is None:
            self._show_view()

    def _show_view(self) -> None:
        loaded = self.loaded
        assert loaded is not None
        self.view = view = apply_query(loaded, self.query())
        self.progress.hide()
        self.cancel_button.setEnabled(False)
        shown = view.state in {'ready', 'partial', 'stale'}
        self.splitter.setVisible(shown)
        self.chain_table.setEnabled(shown)
        self.hop_table.setEnabled(shown)
        notes = []
        if view.state == 'failed':
            self.message.setText(f'{safe(view.message)}\n{REMEDY}')
        elif view.state == 'empty':
            self.message.setText(view.message)
        self.message.setVisible(view.state in {'failed', 'empty'})
        if view.state == 'partial':
            notes.append(f'Warning: {safe(view.message)}')
        elif view.state == 'stale':
            notes.append(f'Warning: {safe(view.message)}. Re-run `patchtrace series create` to recompute.')
        if view.truncated:
            matched = view.total_chains - view.hidden_by_filter
            notes.append(f'Showing the first {len(view.rows)} of {matched} matching chains; refine the filter.')
        self.banner.setText('\n'.join(notes))
        self.banner.setVisible(bool(notes))
        selected = self._selected_chain_id()
        self.chain_model.set_rows(view.rows)
        if selected is not None:
            for i, row in enumerate(view.rows):
                if row.chain_id == selected:
                    self.chain_table.selectRow(i)
                    break
        self.chain_selected()

    def _selected_chain_id(self) -> str | None:
        row = self.selected_chain()
        return row.chain_id if row else None

    def selected_chain(self) -> ChainRow | None:
        rows = self.chain_table.selectionModel().selectedRows()
        return self.chain_model.rows[rows[0].row()] if rows else None

    def selected_hop(self) -> HopView | None:
        rows = self.hop_table.selectionModel().selectedRows()
        return self.hop_model.hops[rows[0].row()] if rows else None

    def chain_selected(self, *_) -> None:
        chain = self.selected_chain()
        self.hop_model.set_hops(chain.hops if chain else ())
        self.update_buttons()

    def update_buttons(self, *_) -> None:
        hop = self.selected_hop()
        self.open_pair.setEnabled(hop is not None and hop.pair_state in OPENABLE_PAIR_STATES
                                  and not hop.match_id.startswith('raw:'))
        self.copy_chain.setEnabled(self.selected_chain() is not None)

    # ---- intents -----------------------------------------------------------------------------
    def pair_path(self, hop: HopView) -> Path | None:
        if self.view is None:
            return None
        health = next((p for p in self.view.pairs if p.from_ordinal == hop.from_ordinal), None)
        root = self.series_path.parent
        target = (root / health.path).resolve() if health and health.path else None
        return target if target is not None and target.is_relative_to(root) else None

    def request_open_pair(self) -> None:
        hop = self.selected_hop()
        target = self.pair_path(hop) if hop else None
        if hop is not None and target is not None:
            self.open_pair_requested.emit(str(target), hop.match_id)

    def copy_selected_chain(self) -> None:
        chain = self.selected_chain()
        if chain is not None and self.view is not None:
            QGuiApplication.clipboard().setText(chain_text(chain, self.view.builds))

    # ---- teardown ----------------------------------------------------------------------------
    def shutdown(self) -> None:
        thread = self.thread
        self._retire_thread()
        if thread is not None:
            thread.wait(2000)  # on timeout the thread stays alive in _LIVE_THREADS until it finishes

    def closeEvent(self, event) -> None:
        self.shutdown()
        super().closeEvent(event)




def open_pair_in_main(port, pair_path: str, match_id: str) -> None:
    """Switch the main window to the pair project (its usual open path) and select the match."""
    from .service import ProjectService
    main, target = port.window, Path(pair_path)
    service = getattr(main, 'service', None)
    if service is None or Path(service.root).resolve() != target.resolve():
        if main._guard(lambda: main.set_service(ProjectService.open(target))) is None and (
                getattr(main, 'service', None) is None or Path(main.service.root).resolve() != target.resolve()):
            return
    if not match_id.startswith('raw:'):
        port.select_match(match_id)


class SeriesController(ControllerBase):
    """The Series dock: one closable tab per opened series.json, a single tab per file."""

    def __init__(self, ctx: PanelContext):
        root = QWidget()
        super().__init__(root)
        self.port = ctx.project
        self._choose = ctx.shell.choose_file
        self.tabs = QTabWidget()
        self.tabs.setObjectName('series.tabs')
        self.tabs.setTabsClosable(True)
        self.tabs.setDocumentMode(True)
        self.hint = PlainLabel('No series is open. Open a series.json to follow functions across builds.', wrap=True)
        self.open_button = QPushButton('Open series.json…')
        apply_tooltip(self.open_button, 'series.open_file')
        layout = QVBoxLayout(root)
        top = QHBoxLayout()
        top.addWidget(self.open_button)
        top.addWidget(self.hint, 1)
        layout.addLayout(top)
        layout.addWidget(self.tabs, 1)
        self.tabs.hide()
        self.open_button.clicked.connect(self.choose_and_open)
        self.tabs.tabCloseRequested.connect(self.close_tab)

    def focus_target(self) -> QWidget:
        return self.tabs.currentWidget() or self.open_button

    def choose_and_open(self) -> SeriesTab | None:
        path = self._choose('Open series.json', 'PatchTrace series (series.json);;JSON (*.json)')
        return None if path is None else self.open_series(path)

    def open_series(self, path: Path) -> SeriesTab:
        """Show the tab of `path`; one file never gets two tabs."""
        series_path = Path(path).resolve()
        tab = next((t for t in self._tabs() if t.series_path == series_path), None)
        if tab is None:
            tab = SeriesTab(series_path)
            tab.open_pair_requested.connect(self._open_pair)
            index = self.tabs.addTab(tab, safe(series_path.parent.name))
            self.tabs.setTabToolTip(index, safe(series_path))
            self.tabs.show()
            self.hint.hide()
        self.tabs.setCurrentWidget(tab)
        return tab

    def _tabs(self) -> list[SeriesTab]:
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def _open_pair(self, pair_path: str, match_id: str) -> None:
        open_pair_in_main(self.port, pair_path, match_id)

    def close_tab(self, index: int) -> None:
        tab = self.tabs.widget(index)
        self.tabs.removeTab(index)
        tab.shutdown()
        tab.deleteLater()
        if not self.tabs.count():
            self.tabs.hide()
            self.hint.show()

    def shutdown(self) -> None:
        for tab in self._tabs():
            tab.shutdown()
