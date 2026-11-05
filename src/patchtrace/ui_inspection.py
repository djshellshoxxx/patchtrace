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

from PySide6.QtCore import QAbstractItemModel, QAbstractTableModel, QModelIndex, Qt, QThread, Signal
from PySide6.QtGui import QFont, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QPlainTextEdit,
    QSplitter,
    QTableView,
    QTabWidget,
    QTreeView,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from .artifact_bytes import ArtifactBytesError
from .artifact_inspection import ProjectInspection, inspect_project_artifacts
from .gui.qt.docks import ControllerBase
from .gui.qt.labels import PlainLabel
from .gui.registry import PanelContext
from .gui.tips import register_tips
from .pe_overview import signing_view as sv
from .pe_overview.compare import compare_metadata
from .pe_overview.metadata import PeMetadata, inspect_metadata
from .preflight import overview_rows
from .tooltips import TooltipEntry, apply_tooltip, template

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


def copy_to_clipboard(text: str) -> None:
    clipboard = QGuiApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text)


class CopyTableView(QTableView):
    """A table whose Ctrl+C copies the selected rows as tab-separated plain text."""

    def selected_tsv(self) -> str:
        model = self.model()
        rows = sorted({index.row() for index in self.selectionModel().selectedRows()})
        return sv.tsv(model.rows[row].values for row in rows)

    def keyPressEvent(self, event) -> None:  # noqa: N802 (Qt name)
        if event.matches(QKeySequence.StandardKey.Copy):
            copy_to_clipboard(self.selected_tsv())
            event.accept()
            return
        super().keyPressEvent(event)


def rows_view(model: RowsModel, widths_em: tuple[int, ...], tip_id: str, name: str,
              view_class: type[QTableView] = QTableView) -> QTableView:
    view = view_class()
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


SIGNING_TIPS = {  # registered: each is applied to a control (tests/test_tooltips.py)
    'pe.version.fileversion': TooltipEntry(
        'Version, manifest and signing facts of the older and the newer file, side by side.',
        'Spot a changed build, a changed privilege request or a lost signature before reading any code.',
        'Read-only; nothing is executed. A changed row is a lead, never a verdict.',
        'Version and manifest resources and the signature container of the verified artifact copies.',
        'Needs an open project whose files are PE images.'),
    'pe.manifest.execlevel': TooltipEntry(
        'What the embedded manifest of each file declares, such as the requested execution level.',
        'A build that asks for more privilege than before is worth a look.',
        'Read-only text; the manifest is parsed without DTDs or entities and is never run.',
        'The RT_MANIFEST resource only; sidecar .manifest files are not read.',
        'Needs a file with an embedded manifest.'),
    'pe.sig.digest': TooltipEntry(
        'Whether the file bytes match the digest that the signature container claims.',
        'A mismatch means the file changed after it was signed, or the container is not about this file.',
        'Read-only. A match is not trust: nobody has checked who made the signature.',
        'The file digest recomputed from the verified artifact copy, without the checksum and the signature areas.',
        'Needs an embedded signature.'),
}
# Per-node tips of the tree. Spec ids pe.sig.chain and pe.sig.timestamp belong in tooltips.py (frozen for this slice, so
# they are not registry entries yet; the registry test demands that every registered id sits on a control).
NODE_TIPS = {
    'Certificate chain': TooltipEntry(
        'Whether the signer certificate chains to a trusted root.',
        'Trust is a decision of the operating system, not of the file.',
        'Not evaluated on this platform; no network request is made.',
        'Windows reports it; this platform reads the structure only.',
        'Chain trust is evaluated on Windows only.'),
    'Claimed signing time (not verified)': TooltipEntry(
        'The signing time that the signature container claims.',
        'It may be wrong or forged unless the timestamp signature and chain are checked, which they are not here.',
        'Shown as a claim only, never as a file date.',
        'The timestamp or countersignature attribute inside the signature container.',
        'Needs a timestamped signature.'),
    'Digest vs file': SIGNING_TIPS['pe.sig.digest'],
}
_LIVE_THREADS: set[QThread] = set()  # a running QThread must never be garbage collected


class SigningTreeModel(QAbstractItemModel):
    """Read-only tree of signature, signer and certificate nodes; children are indexed only when a view asks."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.roots: tuple[sv.TreeNode, ...] = ()
        self._where: dict[int, tuple[sv.TreeNode | None, int]] = {}  # id(node) -> (parent, row); keeps nodes alive

    def set_nodes(self, roots: tuple[sv.TreeNode, ...]) -> None:
        self.beginResetModel()
        self.roots = roots
        self._where = {}
        todo = [(node, None, row) for row, node in enumerate(roots)]
        while todo:
            node, parent, row = todo.pop()
            self._where[id(node)] = (parent, row)
            todo.extend((child, node, i) for i, child in enumerate(node.children))
        self.endResetModel()

    def _children(self, parent: QModelIndex) -> tuple[sv.TreeNode, ...]:
        return parent.internalPointer().children if parent.isValid() else self.roots

    def index(self, row, column, parent=QModelIndex()):  # noqa: B008 (Qt signature)
        children = self._children(parent)
        if column < 0 or column >= len(sv.TREE_HEADERS) or row < 0 or row >= len(children):
            return QModelIndex()
        return self.createIndex(row, column, children[row])

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        owner, _row = self._where[id(index.internalPointer())]
        if owner is None:
            return QModelIndex()
        return self.createIndex(self._where[id(owner)][1], 0, owner)

    def rowCount(self, parent=QModelIndex()):  # noqa: B008 (Qt signature)
        return 0 if parent.isValid() and parent.column() > 0 else len(self._children(parent))

    def columnCount(self, parent=QModelIndex()):  # noqa: B008 (Qt signature)
        return len(sv.TREE_HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return sv.TREE_HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        node = index.internalPointer()
        if role == Qt.ItemDataRole.DisplayRole:
            return (node.label, node.value)[index.column()]
        if role == Qt.ItemDataRole.ToolTipRole and node.label in NODE_TIPS:
            return NODE_TIPS[node.label].render()
        return None

    def _path(self, index: QModelIndex) -> tuple[int, ...]:
        rows = []
        while index.isValid():
            rows.append(index.row())
            index = index.parent()
        return tuple(reversed(rows))

    def selected_text(self, indexes) -> str:
        """Label and value of each selected node, in tree order."""
        nodes = sorted(((self._path(i), i.internalPointer()) for i in indexes if i.column() == 0),
                       key=lambda pair: pair[0])
        return sv.tsv((node.label, node.value) for _path, node in nodes)


class CopyTreeView(QTreeView):
    """Ctrl+C copies the selected nodes as tab-separated plain text."""

    def keyPressEvent(self, event) -> None:  # noqa: N802 (Qt name)
        if event.matches(QKeySequence.StandardKey.Copy):
            copy_to_clipboard(self.model().selected_text(self.selectionModel().selectedIndexes()))
            event.accept()
            return
        super().keyPressEvent(event)


class MetadataThread(QThread):
    """Reads version, manifest and signature facts of both verified readers off the GUI thread; read-only."""
    metadata_ready = Signal(object, object)   # ({side: PeMetadata | None}, key)
    metadata_failed = Signal(str, object)     # (error code, key)

    def __init__(self, inspection: ProjectInspection, key=None):
        super().__init__()
        self.inspection, self.key = inspection, key
        self.cancel = threading.Event()
        _LIVE_THREADS.add(self)
        self.finished.connect(self._release)

    def _release(self) -> None:
        _LIVE_THREADS.discard(self)
        self.deleteLater()

    def run(self) -> None:
        found: dict[str, PeMetadata | None] = {}
        try:
            for side in sv.SIDES:
                overview = self.inspection.sides[side].overview
                reader = self.inspection.reader(side)
                usable = overview is not None and reader is not None and overview.status != 'not_pe'
                found[side] = inspect_metadata(reader, overview, self.cancel.is_set) if usable else None
        except ArtifactBytesError as exc:
            code = exc.code
        except Exception as exc:  # noqa: BLE001 - only the class crosses the thread boundary (GUI plan 8.5)
            logging.getLogger(__name__).warning('Version and signing read failed', exc_info=True)
            code = type(exc).__name__
        else:
            code = None
        if self.cancel.is_set():
            return
        if code is None:
            self.metadata_ready.emit(found, self.key)
        else:
            self.metadata_failed.emit(code, self.key)


class SigningTab(QWidget):
    """The "Version and signing" tab: comparison table, manifest text and signature tree. Plain text only."""

    def __init__(self, parent=None):
        super().__init__(parent)
        register_tips(SIGNING_TIPS)
        self.setObjectName('pe.version.tab')
        self.status = PlainLabel(sv.LOADING, wrap=True, limit=1000)
        self.note = PlainLabel(sv.BLOCKED, wrap=True, limit=1000)
        self.note.setToolTip(NODE_TIPS['Certificate chain'].render())
        self.note.setVisible(sv.blocked_note() is not None)
        self.model = RowsModel(sv.HEADERS)
        self.table = rows_view(self.model, (24, 22, 22, 10), 'pe.version.fileversion', 'Version and signing comparison',
                               CopyTableView)
        self.table.setObjectName('pe.version.table')
        self.manifest = QPlainTextEdit()
        self.manifest.setObjectName('pe.manifest.view')
        self.manifest.setAccessibleName('Manifest declarations')
        self.manifest.setReadOnly(True)
        apply_tooltip(self.manifest, 'pe.manifest.execlevel')
        self.tree_model = SigningTreeModel()
        self.tree = CopyTreeView()
        self.tree.setObjectName('pe.signature.tree')
        self.tree.setAccessibleName('Signature, signer and certificate details')
        self.tree.setModel(self.tree_model)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setUniformRowHeights(True)
        apply_tooltip(self.tree, 'pe.sig.digest')
        splitter = QSplitter(Qt.Orientation.Vertical)
        for widget in (self.table, self.manifest, self.tree):
            splitter.addWidget(widget)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        for widget in (self.status, self.note):
            layout.addWidget(widget)
        layout.addWidget(splitter, 1)
        self.setTabOrder(self.table, self.manifest)
        self.setTabOrder(self.manifest, self.tree)
        self.setFocusProxy(self.table)

    def set_loading(self) -> None:
        self.status.setText(sv.LOADING)
        self._show((), '', ())

    def set_error(self, code: str) -> None:
        self.status.setText(sv.error_text(code))
        self._show((), '', ())

    def set_result(self, metas: dict[str, PeMetadata | None],
                   trust: dict[str, str | None] | None = None) -> None:
        trust = trust or {}
        comparison = compare_metadata(metas.get('older'), metas.get('newer'),
                                      trust=(trust.get('older'), trust.get('newer')))
        rows = tuple(TableRow((r.field, r.older, r.newer, r.status, r.provenance),
                              template('overview.pe_row', field=r.field, provenance=r.provenance, reason=r.reason),
                              r.status == 'changed') for r in comparison)
        self.status.setText('' if sv.has_version(metas) else sv.EMPTY)
        self._show(rows, sv.manifest_text(metas), sv.signature_tree(metas, trust))

    def _show(self, rows: tuple[TableRow, ...], manifest: str, tree: tuple[sv.TreeNode, ...]) -> None:
        self.model.set_rows(rows)
        self.manifest.setPlainText(manifest)
        self.tree_model.set_nodes(tree)
        self.tree.expandToDepth(0)


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
        self.signing = SigningTab()
        self._signing_for: ProjectInspection | None = None
        self._signing_thread: MetadataThread | None = None
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName('File overview sections')
        self.tabs.addTab(splitter, 'Files')
        self.tabs.addTab(self.signing, sv.TITLE)
        layout = QVBoxLayout(root)
        layout.addWidget(explanation)
        layout.addWidget(self.tabs, 1)
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
        if inspection is None:
            self._stop_signing()
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
            self._start_signing(inspection)

    def _start_signing(self, inspection: ProjectInspection) -> None:
        if inspection is self._signing_for:
            return
        self._stop_signing()
        self._signing_for = inspection
        self.signing.set_loading()
        thread = MetadataThread(inspection, inspection)
        thread.metadata_ready.connect(self._signing_ready)
        thread.metadata_failed.connect(self._signing_failed)
        self._signing_thread = thread
        thread.start()

    def _stop_signing(self, wait: bool = False) -> None:
        thread, self._signing_thread, self._signing_for = self._signing_thread, None, None
        if thread is not None and isValid(thread):  # a finished thread has already deleted itself
            thread.cancel.set()
            if wait:
                thread.wait(5000)  # on timeout the thread stays alive in _LIVE_THREADS until it finishes

    def _signing_ready(self, metas, key) -> None:
        if key is self._signing_for:
            trust = {side: (info.trust.status if info.trust else None) for side, info in key.sides.items()}
            self.signing.set_result(metas, trust)

    def _signing_failed(self, code: str, key) -> None:
        if key is self._signing_for:
            self.signing.set_error(code)

    def shutdown(self) -> None:
        self._stop_signing(wait=True)
