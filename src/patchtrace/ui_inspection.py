"""Qt presentation for preliminary artifact inspection (SPEC-26 D, alpha; GUI plan M3).

Responsibility: run :func:`inspect_project_artifacts` on a dedicated QThread
(independent of the analysis job worker) and render its immutable result into
the Files dock. All domain logic lives in ``artifact_inspection``,
``pe_overview`` and ``raw_view``; this module only moves results to widgets.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QAbstractItemView, QSplitter, QTableView, QVBoxLayout, QWidget

from .artifact_inspection import ProjectInspection, inspect_project_artifacts
from .gui.qt.docks import ControllerBase
from .gui.qt.labels import PlainLabel
from .gui.registry import PanelContext
from .preflight import overview_rows
from .tooltips import apply_tooltip, template

# Never say "valid" or "fully trusted": revocation is not checked and catalog signatures are out of scope.
TRUST_LABELS = {
    'trusted_no_revocation_check': 'embedded signature chains to a trusted root (revocation NOT checked)',
    'unsigned': 'no embedded signature (catalog signing not checked)',
    'untrusted': 'signature present but not trusted',
    'invalid': 'signature present but digest/format invalid',
    'unknown': 'result unknown',
    'unavailable': 'not checked on this platform',
}
RECORDED_HEADERS = ('Recorded field', 'OLDER', 'NEWER')
PE_HEADERS = ('PE field', 'OLDER', 'NEWER', 'Status', 'Provenance')
RECORDED_TIP = 'Saved project artifact metadata; no executable content is run or parsed.'
EXPLANATION = (
    'Recorded values were saved when this project was created. The PE comparison re-verifies each '
    'project-owned artifact copy against its SHA-256 and parses headers with bounded read-only reads. Nothing is '
    'executed. Certificate presence is not signature validity, and COFF timestamps can be forged.')
IDLE_STATUS = 'File inspection not started.'
RUNNING_STATUS = 'File inspection running: verifying hashes and parsing PE headers…'


class InspectionThread(QThread):
    """Bounded read-only inspection of both artifacts; never mutates the project."""
    # Both signals carry the identity key so slots can be plain bound methods (queued onto the GUI thread).
    inspection_ready = Signal(object, object)
    inspection_failed = Signal(str, object)

    def __init__(self, project_id: str, artifacts, root: Path, parent=None, key=None):
        super().__init__(parent)
        self.key = key
        self.project_id = project_id
        self.artifacts = tuple(artifacts)
        self.root = Path(root)
        self.cancel = threading.Event()

    def run(self):
        try:
            result = inspect_project_artifacts(self.project_id, self.artifacts, self.root, self.cancel.is_set)
        except Exception as exc:  # noqa: BLE001 - only the class crosses the thread boundary (GUI plan 8.5)
            logging.getLogger(__name__).warning('File inspection failed', exc_info=True)
            self.inspection_failed.emit(type(exc).__name__, self.key)
            return
        if self.cancel.is_set():
            result.close()
            return
        self.inspection_ready.emit(result, self.key)


def side_summary(inspection: ProjectInspection) -> str:
    parts = []
    for side in ('older', 'newer'):
        info = inspection.sides[side]
        if info.overview is None:
            parts.append(f'{side.upper()}: unavailable ({info.error_code})')
            continue
        warnings = len(info.overview.warnings)
        trust = f', Authenticode {TRUST_LABELS.get(info.trust.status, info.trust.status)}' if info.trust else ''
        parts.append(f'{side.upper()}: PE inspection {info.overview.status}'
                     + (f', {warnings} parser warning(s)' if warnings else '') + trust)
    return ' · '.join(parts)


@dataclass(frozen=True, slots=True)
class TableRow:
    values: tuple[str, ...]
    tip: str
    bold: bool = False


def recorded_rows(project) -> tuple[TableRow, ...]:
    artifacts = {artifact.side: artifact for artifact in project.artifacts}
    return tuple(TableRow((row.field, row.older, row.newer), RECORDED_TIP)
                 for row in overview_rows(artifacts['older'], artifacts['newer']))


def pe_rows(inspection: ProjectInspection) -> tuple[TableRow, ...]:
    """Field/older/newer/status/provenance rows. Values are plain text."""
    rows = []
    if not inspection.comparisons:
        reasons = '; '.join(f'{s}: {i.error or i.error_code}' for s, i in inspection.sides.items()
                            if i.overview is None) or 'No comparable PE fields.'
        rows.append(TableRow(('PE comparison unavailable', reasons, 'unavailable', 'unavailable',
                              'Verified project artifacts; no comparable PE records'),
                             template('overview.pe_row', field='PE comparison unavailable',
                                      provenance='verified artifact inspection', reason=reasons)))
    for row in inspection.comparisons:
        rows.append(TableRow((row.field, row.older, row.newer, row.status, row.provenance),
                             template('overview.pe_row', field=row.field, provenance=row.provenance,
                                      reason=row.reason), row.status == 'changed'))
    trust = {side: inspection.sides[side].trust for side in ('older', 'newer')}
    if any(trust.values()):
        texts = [TRUST_LABELS.get(t.status, t.status) if t else 'not run' for t in trust.values()]
        status = 'unavailable' if not all(trust.values()) else (
            'unchanged' if trust['older'].status == trust['newer'].status else 'changed')
        detail = ' | '.join(f'{s}: {t.detail}' for s, t in trust.items() if t)
        rows.append(TableRow(('Authenticode (embedded, offline)', *texts, status,
                              'WinVerifyTrust, no revocation, no network'),
                             template('overview.pe_row', field='Authenticode trust status',
                                      provenance='WinVerifyTrust, embedded signatures only, no revocation',
                                      reason=detail or 'Authenticode probe did not run.')))
    return tuple(rows)


class RowsModel(QAbstractTableModel):
    """Read-only table of plain-text rows; a changed row is bold and every cell carries the row's tooltip."""

    def __init__(self, headers: tuple[str, ...], parent=None):
        super().__init__(parent)
        self.headers = headers
        self.rows: tuple[TableRow, ...] = ()

    def set_rows(self, rows: tuple[TableRow, ...]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.rows)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.headers)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return row.values[index.column()]
        if role == Qt.ItemDataRole.ToolTipRole:
            return row.tip
        if role == Qt.ItemDataRole.FontRole and row.bold:
            font = QFont()
            font.setBold(True)
            return font
        return None


def rows_view(model: RowsModel, widths_em: tuple[int, ...], tip_id: str, name: str) -> QTableView:
    view = QTableView()
    view.setAccessibleName(name)
    view.setModel(model)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.verticalHeader().hide()  # row headers are exposed to UI Automation as accessibles
    view.horizontalHeader().setStretchLastSection(True)
    em = view.fontMetrics().horizontalAdvance('M')
    for column, width in enumerate(widths_em):
        view.setColumnWidth(column, width * em)
    apply_tooltip(view, tip_id)
    return view


class FilesController(ControllerBase):
    """The Files dock: recorded fields and the parsed PE comparison of the project's two artifacts. The inspection
    itself stays with the main window (the raw view shares it); this renders its state and asks for a start."""

    def __init__(self, ctx: PanelContext):
        root = QWidget()
        super().__init__(root)
        self.port = ctx.project
        self.window = self.port.window
        self.recorded, self.pe = RowsModel(RECORDED_HEADERS), RowsModel(PE_HEADERS)
        self.recorded_view = rows_view(self.recorded, (18, 24), 'overview.table', 'Recorded artifact fields')
        self.pe_view = rows_view(self.pe, (24, 22, 22, 10), 'overview.pe_table', 'PE comparison fields')
        self.status = PlainLabel(IDLE_STATUS, wrap=True, limit=1000)
        explanation = PlainLabel(EXPLANATION, wrap=True, limit=1000)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.addWidget(self.status)
        detail_layout.addWidget(self.pe_view, 1)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.recorded_view)
        splitter.addWidget(detail)
        splitter.setStretchFactor(1, 1)
        layout = QVBoxLayout(root)
        layout.addWidget(explanation)
        layout.addWidget(splitter, 1)
        self.window.inspection_status.connect(self._inspection_status)

    def focus_target(self) -> QWidget:
        return self.pe_view

    def project_changed(self, key: object) -> None:
        self.refresh()

    def refresh(self) -> None:
        """Show the recorded fields now; use the current inspection, or start one."""
        project = self.port.project()
        self.recorded.set_rows(recorded_rows(project) if project else ())
        inspection = self.window._current_inspection() if project else None
        self.pe.set_rows(())
        if inspection is not None:
            self._inspection_status('File inspection complete · ' + side_summary(inspection))
        elif project:
            self.status.setText(RUNNING_STATUS)
            self.window.start_inspection()
        else:
            self.status.setText(IDLE_STATUS)

    def _inspection_status(self, text: str) -> None:
        self.status.setText(text)
        inspection = self.window._current_inspection()
        if inspection is not None:
            self.pe.set_rows(pe_rows(inspection))
