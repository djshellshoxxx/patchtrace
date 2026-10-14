"""Qt presentation for preliminary artifact inspection (SPEC-26 D, alpha).

Responsibility: run :func:`inspect_project_artifacts` on a dedicated QThread
(independent of the analysis job worker) and render its immutable result into
the File overview dialog. All domain logic lives in ``artifact_inspection``,
``pe_overview`` and ``raw_view``; this module only moves results to widgets.
"""
from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QAbstractItemView, QTableWidget, QTableWidgetItem

from .artifact_inspection import ProjectInspection, inspect_project_artifacts
from .tooltips import template

# Never say "valid" or "fully trusted": revocation is not checked and catalog signatures are out of scope.
TRUST_LABELS = {
    'trusted_no_revocation_check': 'embedded signature chains to a trusted root (revocation NOT checked)',
    'unsigned': 'no embedded signature (catalog signing not checked)',
    'untrusted': 'signature present but not trusted',
    'invalid': 'signature present but digest/format invalid',
    'unknown': 'result unknown',
    'unavailable': 'not checked on this platform',
}


class InspectionThread(QThread):
    """Bounded read-only inspection of both artifacts; never mutates the project."""
    inspection_ready = Signal(object)
    inspection_failed = Signal(str)

    def __init__(self, project_id: str, artifacts, root: Path, parent=None):
        super().__init__(parent)
        self.project_id = project_id
        self.artifacts = tuple(artifacts)
        self.root = Path(root)
        self.cancel = threading.Event()

    def run(self):
        try:
            result = inspect_project_artifacts(self.project_id, self.artifacts, self.root, self.cancel.is_set)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user as text
            self.inspection_failed.emit(f'{type(exc).__name__}: {exc}')
            return
        if self.cancel.is_set():
            result.close()
            return
        self.inspection_ready.emit(result)


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


def fill_pe_table(table: QTableWidget, inspection: ProjectInspection) -> None:
    """Populate field/older/newer/status/provenance rows. Values are plain text items."""
    rows = inspection.comparisons
    table.clear()
    table.setColumnCount(5)
    table.setHorizontalHeaderLabels(['PE field', 'OLDER', 'NEWER', 'Status', 'Provenance'])
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    if not rows:
        table.setRowCount(1)
        reasons = '; '.join(f'{s}: {i.error or i.error_code}' for s, i in inspection.sides.items()
                            if i.overview is None) or 'No comparable PE fields.'
        values = ('PE comparison unavailable', reasons, 'unavailable', 'unavailable',
                  'Verified project artifacts; no comparable PE records')
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(template('overview.pe_row', field='PE comparison unavailable',
                                     provenance='verified artifact inspection',
                                     reason=reasons))
            table.setItem(0, column, item)
        return
    table.setRowCount(len(rows))
    for index, row in enumerate(rows):
        values = (row.field, row.older, row.newer, row.status, row.provenance)
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setToolTip(template('overview.pe_row', field=row.field, provenance=row.provenance,
                                     reason=row.reason))
            if row.status == 'changed':
                font = QFont(item.font())
                font.setBold(True)
                item.setFont(font)
            table.setItem(index, column, item)
    trust = {side: inspection.sides[side].trust for side in ('older', 'newer')}
    if any(trust.values()):
        index = table.rowCount()
        table.setRowCount(index + 1)
        texts = [TRUST_LABELS.get(t.status, t.status) if t else 'not run' for t in trust.values()]
        status = 'unavailable' if not all(trust.values()) else (
            'unchanged' if trust['older'].status == trust['newer'].status else 'changed')
        values = ('Authenticode (embedded, offline)', *texts, status, 'WinVerifyTrust, no revocation, no network')
        detail = ' | '.join(f'{s}: {t.detail}' for s, t in trust.items() if t)
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(template('overview.pe_row', field='Authenticode trust status',
                                     provenance='WinVerifyTrust, embedded signatures only, no revocation',
                                     reason=detail or 'Authenticode probe did not run.'))
            table.setItem(index, column, item)
    table.resizeColumnsToContents()
