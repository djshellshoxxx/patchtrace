"""Qt desktop. Workers produce values; project mutations stay on the GUI thread."""
from __future__ import annotations

import html
import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QKeySequence, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .alignment import alignment_strategy, diff_hunks
from .backend import BackendConfig, diagnose, quarantine_failed_run, run_comparison
from .evidence import build_context, resolve_evidence
from .interpretation import interpret, system_prompt
from .offline_bundle import inspect_offline_bundle, install_offline_bundle
from .providers import ProviderConfig
from .reports import export_project
from .runtime_discovery import discover_local_runtimes
from .service import ProjectService

REVIEWS = ['unreviewed', 'accepted', 'rejected', 'needs-review']
CATEGORIES = ['modified', 'added', 'removed', 'ambiguous', 'split', 'merged', 'unmatched', 'unchanged']
MAX_VIEW_CHARS = 200_000
DARK_STYLE = """
QWidget { background: #161b22; color: #d9e1ec; font-size: 12px; }
QMainWindow, QDialog { background: #10151c; }
QToolBar { border: none; background: #1d2530; spacing: 7px; padding: 6px; }
QPushButton, QComboBox, QSpinBox { background: #253040; border: 1px solid #3b4a5c;
 padding: 5px 8px; border-radius: 4px; min-height: 21px; }
QPushButton:hover { border-color: #53c6d6; }
QPushButton:disabled { color: #6c7684; }
QLineEdit, QPlainTextEdit, QTextEdit, QListWidget { background: #10151c;
 border: 1px solid #303b49; border-radius: 3px; padding: 4px; }
QListWidget::item { padding: 7px 3px; }
QListWidget::item:selected { background: #21424c; color: #f1fcff; }
QLabel#brand { font-size: 20px; font-weight: 600; color: #8be2e9; }
QLabel#muted { color: #97a7ba; }
QLabel#warning { color: #ffc875; }
QSplitter::handle { background: #283241; }
QTabBar::tab { background: #202a36; padding: 6px 12px; }
QTabBar::tab:selected { color: #8be2e9; }
QProgressBar { border: 1px solid #303b49; text-align: center; }
QProgressBar::chunk { background: #3c9ea9; }
QMenu { border: 1px solid #394959; }
"""


class PlainLabel(QLabel):
    """Imported names and messages are always text, never Qt rich text."""
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setTextFormat(Qt.TextFormat.PlainText)


class ArtifactPathEdit(QLineEdit):
    """A dropped file populates exactly the explicitly labelled side."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile() and Path(urls[0].toLocalFile()).is_file():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile():
            self.setText(urls[0].toLocalFile())
            event.acceptProposedAction()


def plain_tip(text):
    """Tooltips auto-detect rich text (Qt::mightBeRichText); escape untrusted text so it renders literally."""
    return '<p style="white-space:pre-wrap">' + html.escape(text).replace('\n', '<br>') + '</p>'


def plain_view(text='', parent=None):
    view = QPlainTextEdit(parent)
    view.setReadOnly(True)
    view.setPlainText(text)
    view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    return view


def dialog_buttons(dialog, accepted='OK'):
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.button(QDialogButtonBox.StandardButton.Ok).setText(accepted)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    return buttons


def text_dialog(parent, title, text):
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(800, 560)
    layout = QVBoxLayout(dialog)
    layout.addWidget(plain_view(text))
    close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    close.rejected.connect(dialog.reject)
    layout.addWidget(close)
    dialog.exec()


class Worker(QThread):
    """One retained thread per window; cooperative cancel never mutates the service."""
    result_ready = Signal(object)
    failed = Signal(str)
    event_ready = Signal(object)

    def __init__(self, task: Callable, parent=None):
        super().__init__(parent)
        self.cancel = threading.Event()
        self.task = task

    def run(self):
        try:
            self.result_ready.emit(self.task(self.cancel, self.event_ready.emit))
        except Exception as exc:
            self.failed.emit(str(exc) or type(exc).__name__)


class NewProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('New comparison · explicit older / newer')
        self.resize(680, 300)
        layout = QVBoxLayout(self)
        label = PlainLabel('Select the older artifact on the left and the newer artifact on the right.\n'
                       'Only static analysis is performed. Originals are preserved.')
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QFormLayout()
        self.name = QLineEdit('Patch comparison')
        self.older = ArtifactPathEdit()
        self.newer = ArtifactPathEdit()
        self.root = QLineEdit()
        form.addRow('Project name', self.name)
        for title, edit, directory in [('Older PE x64', self.older, False),
                                       ('Newer PE x64', self.newer, False),
                                       ('New project directory', self.root, True)]:
            row = QWidget()
            horizontal = QHBoxLayout(row)
            horizontal.setContentsMargins(0, 0, 0, 0)
            horizontal.addWidget(edit)
            choose = QPushButton('Browse…')
            choose.clicked.connect(lambda checked=False, e=edit, d=directory: self.browse(e, d))
            horizontal.addWidget(choose)
            form.addRow(title, row)
        layout.addLayout(form)
        swap = QPushButton('Swap older and newer')
        swap.clicked.connect(self.swap)
        layout.addWidget(swap)
        self.error = PlainLabel()
        self.error.setObjectName('warning')
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        layout.addWidget(dialog_buttons(self, 'Create project'))

    def browse(self, edit, directory):
        if directory:
            parent = QFileDialog.getExistingDirectory(self, 'Choose parent directory')
            if parent:
                edit.setText(str(Path(parent) / 'patchtrace-project'))
        else:
            value, _ = QFileDialog.getOpenFileName(self, 'Select PE AMD64 artifact', '', 'PE files (*.exe *.dll *.sys);;All files (*)')
            if value:
                edit.setText(value)

    def swap(self):
        old = self.older.text()
        self.older.setText(self.newer.text())
        self.newer.setText(old)

    def accept(self):
        if not self.name.text().strip() or not self.root.text().strip():
            self.error.setText('Enter a project name and a new project directory.')
            return
        if not all(Path(edit.text()).is_file() for edit in [self.older, self.newer]):
            self.error.setText('Choose two existing binary files. PE format and architecture are validated on creation.')
            return
        root = Path(self.root.text())
        if root.exists() and any(root.iterdir()):
            self.error.setText('The project directory must be absent or empty.')
            return
        super().accept()


class SetupDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Backend and desktop setup')
        self.resize(720, 470)
        layout = QVBoxLayout(self)
        intro = PlainLabel('Comparison needs Ghidriff, Ghidra and Java. You can use existing tools or import a prebuilt offline backend ZIP.\n'
                       'Import does not download or execute software; Diagnose dependencies is a separate explicit action.')
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.python = QLineEdit(settings.value('backend/python', ''))
        self.ghidra = QLineEdit(settings.value('backend/ghidra', ''))
        self.java_home = QLineEdit(settings.value('backend/java_home', ''))
        for name, edit, directory in [('External Python executable', self.python, False),
                                       ('Ghidra installation directory', self.ghidra, True),
                                       ('Private Java installation directory (optional)', self.java_home, True)]:
            row = QWidget()
            horizontal = QHBoxLayout(row)
            horizontal.setContentsMargins(0, 0, 0, 0)
            horizontal.addWidget(edit)
            button = QPushButton('Browse…')
            button.clicked.connect(lambda checked=False, e=edit, d=directory: self.browse(e, d))
            horizontal.addWidget(button)
            form.addRow(name, row)
        self.allow_symbol_downloads = QCheckBox('Allow Ghidriff symbol-server lookups (may access the Internet)')
        self.allow_symbol_downloads.setChecked(settings.value('backend/allow_symbol_downloads', False, type=bool))
        form.addRow(self.allow_symbol_downloads)
        self.timeout = QSpinBox()
        self.timeout.setRange(10, 86400)
        self.timeout.setValue(int(settings.value('backend/timeout', 3600)))
        form.addRow('Comparison timeout (seconds)', self.timeout)
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 28)
        self.font_size.setValue(int(settings.value('desktop/font_size', 11)))
        form.addRow('Code font size (points)', self.font_size)
        self.context_budget = QSpinBox()
        self.context_budget.setRange(512, 200000)
        self.context_budget.setValue(int(settings.value('provider/context_budget', 24000)))
        form.addRow('Interpretation context budget (characters)', self.context_budget)
        self.sync = QCheckBox('Synchronize code scrolling')
        self.sync.setChecked(settings.value('desktop/sync', True, type=bool))
        form.addRow(self.sync)
        layout.addLayout(form)
        self.diagnostics = plain_view('Configure paths, then diagnose dependencies.')
        layout.addWidget(self.diagnostics)
        self.find = QPushButton('Find existing installations')
        self.find.clicked.connect(self.discover_existing)
        layout.addWidget(self.find)
        self.bundle_sha = QLineEdit()
        self.bundle_sha.setPlaceholderText('Optional trusted ZIP SHA-256 (64 lowercase hex)')
        form.addRow('Trusted offline ZIP checksum', self.bundle_sha)
        self.install = QPushButton('Install offline backend ZIP…')
        self.install.clicked.connect(self.import_offline_bundle)
        layout.addWidget(self.install)
        self.cancel_install = QPushButton('Cancel offline installation')
        self.cancel_install.setEnabled(False)
        self.cancel_install.clicked.connect(self.cancel_offline_install)
        layout.addWidget(self.cancel_install)
        self.check = QPushButton('Diagnose dependencies')
        self.check.clicked.connect(self.check_dependencies)
        layout.addWidget(self.check)
        layout.addWidget(dialog_buttons(self, 'Save setup'))
        self.worker = None
        self._pending_plan = None
        self.discover_existing()

    def discover_existing(self):
        """Suggest known local installations without executing or installing tools."""
        found = discover_local_runtimes()
        notes = ['Local discovery only: nothing downloaded or executed.']
        for label, edit, paths in (
            ('External Python', self.python, found.python_executables),
            ('Ghidra', self.ghidra, found.ghidra_roots),
        ):
            if edit.text().strip():
                notes.append(f'{label}: retaining configured path')
            elif len(paths) == 1:
                edit.setText(str(paths[0]))
                notes.append(f'{label}: detected {paths[0]}')
            elif paths:
                notes.append(f'{label}: multiple installations found; choose one using Browse:')
                notes.extend(str(path) for path in paths[:8])
            else:
                notes.append(f'{label}: not found; use Browse after installing')
        notes.append('Detected paths require Diagnose dependencies and a real comparison to verify.')
        self.diagnostics.setPlainText('\n'.join(notes))

    def browse(self, edit, directory):
        if directory:
            value = QFileDialog.getExistingDirectory(self, 'Select extracted installation directory')
        else:
            value, _ = QFileDialog.getOpenFileName(self, 'External Python executable')
        if value:
            edit.setText(value)

    def config(self):
        return BackendConfig(python_executable=self.python.text().strip(), ghidra_dir=self.ghidra.text().strip(),
                             timeout_seconds=self.timeout.value(),
                             allow_symbol_downloads=self.allow_symbol_downloads.isChecked(),
                             java_home=self.java_home.text().strip())

    def check_dependencies(self):
        if self.worker and self.worker.isRunning():
            return
        config = self.config()
        self.check.setEnabled(False)
        self.diagnostics.setPlainText('Checking external dependencies…')
        self.worker = Worker(lambda cancel, event: diagnose(config), self)
        self.worker.result_ready.connect(lambda result: self.diagnostics.setPlainText('\n'.join(result)))
        self.worker.failed.connect(self.diagnostics.setPlainText)
        self.worker.finished.connect(self._finish_diagnosis)
        self.worker.start()

    def _finish_diagnosis(self):
        self.worker = None
        self.check.setEnabled(True)

    def _offline_busy(self, active):
        self.install.setEnabled(not active)
        self.find.setEnabled(not active)
        self.check.setEnabled(not active)
        self.cancel_install.setEnabled(active)
        for edit in (self.python, self.ghidra, self.java_home):
            edit.setReadOnly(active)

    def cancel_offline_install(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel.set()
            self.cancel_install.setEnabled(False)
            self.diagnostics.setPlainText('Cancelling offline operation after current chunk…')

    def import_offline_bundle(self):
        """Explicit local selection, background verification, then user confirmation."""
        if self.worker and self.worker.isRunning():
            return
        chosen, _ = QFileDialog.getOpenFileName(
            self, 'Choose a previously prepared offline backend ZIP', '', 'ZIP archives (*.zip)')
        if not chosen:
            return
        self._pending_plan = None
        digest = self.bundle_sha.text().strip() or None
        self._offline_busy(True)
        self.diagnostics.setPlainText('Verifying local offline bundle integrity…')
        self.worker = Worker(
            lambda cancel, event: inspect_offline_bundle(Path(chosen), expected_sha256=digest, cancel=cancel),
            self)
        self.worker.result_ready.connect(lambda plan: setattr(self, '_pending_plan', plan))
        self.worker.failed.connect(self.diagnostics.setPlainText)
        self.worker.finished.connect(self._finish_offline_inspection)
        self.worker.start()

    def _finish_offline_inspection(self):
        self.worker = None
        self._offline_busy(False)
        plan = self._pending_plan
        self._pending_plan = None
        if plan is None:
            return
        box = QMessageBox(
            QMessageBox.Icon.Question, 'Install verified offline backend?',
            f'Bundle: {plan.archive.name}\nRuntime: {plan.runtime_id}\n'
            f'Files: {plan.file_count:,}; uncompressed: {plan.total_bytes:,} bytes\n'
            f'Archive SHA-256: {plan.sha256}\n\n'
            'The file hashes match its own manifest. This does NOT prove publisher authenticity. '
            'Verify the archive checksum against a trusted source and review the included '
            'LICENSES/NOTICE.txt before relying on this software.\n\n'
            'Continue with private per-user installation?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, self)
        # Archive name and runtime ID come from an untrusted file; never interpret them as rich text.
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        answer = box.exec()
        if answer != QMessageBox.StandardButton.Yes:
            self.diagnostics.setPlainText('Offline bundle checked; installation not authorized.')
            return
        local = os.environ.get('LOCALAPPDATA')
        if not local:
            self.diagnostics.setPlainText('PT-OFFLINE: LOCALAPPDATA is unavailable; Windows per-user install required')
            return
        target = Path(local) / 'PatchTrace' / 'runtimes'
        self._offline_busy(True)
        self.diagnostics.setPlainText('Installing verified backend into private user directory…')
        self.worker = Worker(
            lambda cancel, event: install_offline_bundle(
                plan, target, cancel=cancel, event=lambda message: event(message)), self)
        self.worker.event_ready.connect(lambda message: self.diagnostics.setPlainText(str(message)))
        self.worker.result_ready.connect(self._offline_installed)
        self.worker.failed.connect(self.diagnostics.setPlainText)
        self.worker.finished.connect(self._finish_offline_install)
        self.worker.start()

    def _offline_installed(self, installed):
        self.python.setText(str(installed.python_executable))
        self.ghidra.setText(str(installed.ghidra_dir))
        self.java_home.setText(str(installed.java_home))
        self.diagnostics.setPlainText(
            f'Offline backend installed at {installed.root}.\n'
            'Use Diagnose dependencies, then Save setup. A native comparison must still '
            'verify compatibility. No system-wide settings were changed.')

    def _finish_offline_install(self):
        self.worker = None
        self._offline_busy(False)

    def reject(self):
        if self.worker and self.worker.isRunning():
            self.diagnostics.appendPlainText('Wait for dependency diagnosis to finish before closing setup.')
            return
        super().reject()

    def accept(self):
        if self.worker and self.worker.isRunning():
            return
        super().accept()


class ContextDialog(QDialog):
    """Nothing is transmitted until this dialog returns Accepted."""
    def __init__(self, context, settings, parent=None):
        super().__init__(parent)
        self.context = context
        self.setWindowTitle('Preview exact interpretation context')
        self.resize(900, 720)
        layout = QVBoxLayout(self)
        info = PlainLabel(f'{len(context.match_ids)} matches · {len(context.evidence)} evidence records · '
                      f'about {context.token_estimate:,} tokens\nDigest: {context.digest}\n'
                      'Context is sent only after you select Send context. Model output is an unverified hypothesis.')
        info.setWordWrap(True)
        layout.addWidget(info)
        tabs = QTabWidget()
        tabs.addTab(plain_view(context.payload), 'Exact context')
        tabs.addTab(plain_view(system_prompt()), 'Exact system prompt')
        tabs.addTab(plain_view('\n'.join(context.omitted) or 'No omitted records.'), 'Omitted / unavailable')
        layout.addWidget(tabs, 1)
        form = QFormLayout()
        self.kind = QComboBox()
        self.kind.addItems(['ollama', 'openai'])
        self.kind.setCurrentText(settings.value('provider/kind', 'ollama'))
        self.endpoint = QLineEdit(settings.value('provider/endpoint', 'http://127.0.0.1:11434'))
        self.model = QLineEdit(settings.value('provider/model', ''))
        self.key = QLineEdit()
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setPlaceholderText('Session only; never saved')
        form.addRow('Provider', self.kind)
        form.addRow('Endpoint', self.endpoint)
        form.addRow('Model', self.model)
        form.addRow('API key', self.key)
        self.kind.currentTextChanged.connect(self.provider_changed)
        layout.addLayout(form)
        self.error = PlainLabel()
        self.error.setObjectName('warning')
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        layout.addWidget(dialog_buttons(self, 'Send context'))

    def provider_changed(self, kind):
        self.endpoint.setText('http://127.0.0.1:11434' if kind == 'ollama' else 'https://api.openai.com/v1')

    def config(self):
        return ProviderConfig(kind=self.kind.currentText(), endpoint=self.endpoint.text().strip(),
                              model=self.model.text().strip(), api_key=self.key.text())

    def accept(self):
        if not self.model.text().strip():
            self.error.setText('Enter a model name before sending context.')
            return
        try:
            self.config()
        except Exception as exc:
            self.error.setText(str(exc))
            return
        super().accept()


class CorrectMatchDialog(QDialog):
    def __init__(self, project, match, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Correct function relationship')
        self.resize(820, 560)
        layout = QVBoxLayout(self)
        label = PlainLabel('Choose exact existing records for each side. Corrections retain provenance and invalidate findings.')
        label.setWordWrap(True)
        layout.addWidget(label)
        panes = QHBoxLayout()
        self.sides = {}
        for side in ['older', 'newer']:
            box = QVBoxLayout()
            box.addWidget(PlainLabel(side.title()))
            listing = QListWidget()
            self.sides[side] = listing
            selected = {f.id for f in getattr(match, side)}
            records = {f.id: f for m in project.matches for f in getattr(m, side)}
            for record in records.values():
                item = QListWidgetItem(f'{record.name} · {record.address or "address unavailable"} · {record.id[:8]}')
                item.setData(Qt.ItemDataRole.UserRole, record.id)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Checked if record.id in selected else Qt.CheckState.Unchecked)
                listing.addItem(item)
            box.addWidget(listing)
            panes.addLayout(box)
        layout.addLayout(panes)
        form = QFormLayout()
        self.category = QComboBox()
        self.category.addItems(CATEGORIES)
        self.category.setCurrentText(match.category)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText('Required analyst reason')
        form.addRow('Relationship', self.category)
        form.addRow('Reason', self.reason)
        layout.addLayout(form)
        self.error = PlainLabel()
        self.error.setObjectName('warning')
        layout.addWidget(self.error)
        layout.addWidget(dialog_buttons(self, 'Save correction'))

    def selected(self, side):
        listing = self.sides[side]
        return [listing.item(i).data(Qt.ItemDataRole.UserRole) for i in range(listing.count())
                if listing.item(i).checkState() == Qt.CheckState.Checked]

    def accept(self):
        old, new = self.selected('older'), self.selected('newer')
        category = self.category.currentText()
        if not self.reason.text().strip() or not (old or new):
            self.error.setText('Choose at least one function and enter a reason.')
            return
        if (category == 'added' and (old or not new)) or (category == 'removed' and (new or not old)):
            self.error.setText('Added requires only newer records; removed requires only older records.')
            return
        super().accept()


class ExportDialog(QDialog):
    def __init__(self, project, root, selected_ids, parent=None):
        super().__init__(parent)
        self.project = project
        self.root = root
        self.selected_ids = selected_ids
        self.enrichment = None
        self.setWindowTitle('Export report · review exact preview')
        self.resize(880, 700)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.format = QComboBox()
        self.format.addItems(['md', 'html', 'json'])
        self.destination = QLineEdit(str(root / 'exports' / 'report.md'))
        self.format.currentTextChanged.connect(self.change_format)
        row = QWidget()
        horizontal = QHBoxLayout(row)
        horizontal.setContentsMargins(0, 0, 0, 0)
        horizontal.addWidget(self.destination)
        browse = QPushButton('Browse…')
        browse.clicked.connect(self.browse)
        horizontal.addWidget(browse)
        form.addRow('Format', self.format)
        form.addRow('Destination', row)
        self.code = QCheckBox('Include function code')
        self.notes = QCheckBox('Include analyst notes')
        self.notes.setChecked(True)
        self.selection = QCheckBox(f'Only selected findings ({len(selected_ids)})')
        self.selection.setEnabled(bool(selected_ids))
        form.addRow(self.code)
        form.addRow(self.notes)
        form.addRow(self.selection)
        layout.addLayout(form)
        policy = PlainLabel('Absolute source paths are redacted. Raw provider responses are excluded.\n'
                        'Review the preview, then write the report to the chosen destination.')
        policy.setWordWrap(True)
        layout.addWidget(policy)
        self.preview = plain_view()
        layout.addWidget(self.preview, 1)
        self.error = PlainLabel()
        self.error.setObjectName('warning')
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.buttons = dialog_buttons(self, 'Write report')
        layout.addWidget(self.buttons)
        for control in [self.code, self.notes, self.selection]:
            control.toggled.connect(self.refresh_preview)
        self.format.currentTextChanged.connect(self.refresh_preview)
        self.refresh_preview()

    def change_format(self, value):
        if not self.destination.text().strip():
            return
        self.destination.setText(str(Path(self.destination.text()).with_suffix('.' + value)))

    def browse(self):
        value, _ = QFileDialog.getSaveFileName(self, 'Write report', self.destination.text())
        if value:
            self.destination.setText(value)

    def options(self):
        return dict(include_code=self.code.isChecked(), include_notes=self.notes.isChecked(),
                    finding_ids=self.selected_ids if self.selection.isChecked() else None,
                    enrichment=self.enrichment)

    def refresh_preview(self, *_):
        try:
            with tempfile.TemporaryDirectory(prefix='patchtrace-preview-') as directory:
                output = Path(directory) / ('preview.' + self.format.currentText())
                export_project(self.project, self.format.currentText(), output, **self.options())
                self.preview.setPlainText(output.read_text(encoding='utf-8'))
            self.error.clear()
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        except Exception as exc:
            self.error.setText(str(exc))
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)

    def accept(self):
        if not self.destination.text().strip():
            self.error.setText('Choose an export destination.')
            return
        super().accept()


class MainWindow(QMainWindow):
    def __init__(self, service=None, settings=None):
        super().__init__()
        self.settings = settings or QSettings('PatchTrace', 'PatchTrace')
        self.service = service
        self.worker = None
        self._updating = False
        # Derived enrichment for the current run, keyed by match ID; never part of the project snapshot.
        self._ranking = {}
        self._signal_sets = {}
        self._ranking_note = ''
        self._ranking_result = None
        self._syncing = False
        self._close_requested = False
        self._job_started = 0.0
        self._hunks = []
        self._hunk_index = -1
        self._function_offsets = {}
        self._finding = None
        self._context = None
        self._evidence = {}
        self.setWindowTitle('PatchTrace · Compare binaries. Trace fixes.')
        self.resize(1440, 900)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(DARK_STYLE)
        self._build_actions()
        self._build_workspace()
        self.restore_preferences()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._elapsed)
        self.refresh()

    def _action(self, title, callback, shortcut=None):
        action = QAction(title, self)
        action.triggered.connect(callback)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        return action

    def _build_actions(self):
        self.new_action = self._action('New', self.new_project, 'Ctrl+N')
        self.open_action = self._action('Open', self.open_project, 'Ctrl+O')
        self.sample_action = self._action('Sample', self.open_sample)
        self.import_action = self._action('Import JSON', self.import_diff)
        self.run_action = self._action('Run comparison', self.run_analysis, 'F5')
        self.cancel_action = self._action('Cancel job', self.cancel_job, 'Escape')
        self.interpret_action = self._action('Interpret selection', self.preview_interpretation, 'Ctrl+I')
        self.export_action = self._action('Export', self.export_report, 'Ctrl+E')
        self.setup_action = self._action('Setup', self.setup)
        self.swap_action = self._action('Swap orientation', self.swap_orientation)
        self.save_action = self._action('Save', self.save_project, 'Ctrl+S')
        self.backup_action = self._action('Back up project…', self.backup_project)
        self.undo_match_action = self._action('Undo latest match correction', self.undo_match_correction)
        self.help_action = self._action('Workflow and dependencies', self.show_help, 'F1')
        self.rank_action = self._action('Rank changes', self.rank_changes, 'Ctrl+R')
        toolbar = QToolBar('Project and analysis', self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        for action in [self.new_action, self.open_action, self.sample_action, self.import_action,
                       self.run_action, self.rank_action, self.cancel_action, self.interpret_action, self.export_action,
                       self.setup_action]:
            toolbar.addAction(action)
        file_menu = self.menuBar().addMenu('Project')
        for action in [self.new_action, self.open_action, self.sample_action, self.save_action,
                       self.import_action, self.export_action, self.swap_action]:
            file_menu.addAction(action)
        file_menu.addAction(self.backup_action)
        file_menu.addAction(self.undo_match_action)
        self.recent_menu = file_menu.addMenu('Recent projects')
        self.refresh_recent()
        analysis = self.menuBar().addMenu('Analysis')
        for action in [self.run_action, self.rank_action, self.cancel_action, self.interpret_action, self.setup_action]:
            analysis.addAction(action)
        self.menuBar().addMenu('Help').addAction(self.help_action)

    def _build_workspace(self):
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 8, 10, 8)
        heading = QHBoxLayout()
        brand = PlainLabel('PATCHTRACE')
        brand.setObjectName('brand')
        heading.addWidget(brand)
        self.project_label = PlainLabel('Open a project or load the synthetic sample to begin.')
        self.project_label.setObjectName('muted')
        heading.addWidget(self.project_label, 1)
        layout.addLayout(heading)
        self.vertical = QSplitter(Qt.Orientation.Vertical)
        self.workspace = QSplitter(Qt.Orientation.Horizontal)
        self.vertical.addWidget(self.workspace)
        self._build_navigator()
        self._build_code()
        self._build_findings()
        diagnostics = QWidget()
        diag_layout = QVBoxLayout(diagnostics)
        diag_layout.setContentsMargins(0, 0, 0, 0)
        status = QHBoxLayout()
        self.job_label = PlainLabel('Ready · static analysis only')
        self.job_label.setWordWrap(True)
        status.addWidget(self.job_label, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setMaximumWidth(250)
        self.progress.setVisible(False)
        status.addWidget(self.progress)
        diag_layout.addLayout(status)
        self.logs = plain_view('No analysis has been started. Configure dependencies in Setup or import a Ghidriff JSON.')
        self.logs.document().setMaximumBlockCount(2000)
        diag_layout.addWidget(self.logs)
        self.vertical.addWidget(diagnostics)
        self.vertical.setSizes([700, 120])
        self.workspace.setSizes([260, 830, 330])
        layout.addWidget(self.vertical, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage('Offline comparison and review work without an AI provider.')

    def _build_navigator(self):
        pane = QWidget()
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.addWidget(PlainLabel('FUNCTION MATCHES'))
        self.search = QLineEdit()
        self.search.setPlaceholderText('Search names or addresses…')
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName('Search function names and addresses')
        layout.addWidget(self.search)
        self.category_filter = QComboBox()
        self.category_filter.addItems(['All categories', *CATEGORIES])
        self.category_filter.setAccessibleName('Match category filter')
        layout.addWidget(self.category_filter)
        self.review_filter = QComboBox()
        self.review_filter.addItems(['All review states', *REVIEWS])
        self.review_filter.setAccessibleName('Match review status filter')
        layout.addWidget(self.review_filter)
        self.order = QComboBox()
        self.order.addItems(['Project order', 'Attention score (research priority)'])
        self.order.setAccessibleName('Match ordering')
        self.order.setToolTip('Attention scores prioritize research; they do not establish exploitability.')
        self.order.currentIndexChanged.connect(self.filter_matches)
        layout.addWidget(self.order)
        self.manual_filter = QCheckBox('Manual corrections only')
        self.finding_match_filter = QCheckBox('Matches with findings only')
        self.manual_filter.toggled.connect(self.filter_matches)
        self.finding_match_filter.toggled.connect(self.filter_matches)
        layout.addWidget(self.manual_filter)
        layout.addWidget(self.finding_match_filter)
        self.match_count = PlainLabel('No project')
        self.match_count.setObjectName('muted')
        layout.addWidget(self.match_count)
        self.navigator = QListWidget()
        self.navigator.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.navigator.setAccessibleName('Function matches; select multiple for interpretation')
        self.navigator.currentItemChanged.connect(self.select_match)
        self.navigator.itemSelectionChanged.connect(self.update_controls)
        layout.addWidget(self.navigator, 1)
        layout.addWidget(PlainLabel('CHANGE SIGNALS'))
        self.signal_list = QListWidget()
        self.signal_list.setAccessibleName('Deterministic change signals for the selected match; activate to show source')
        self.signal_list.setMaximumHeight(130)
        self.signal_list.itemActivated.connect(self.jump_signal)
        self.signal_list.currentItemChanged.connect(lambda current, _previous: self.jump_signal(current))
        layout.addWidget(self.signal_list)
        self.match_review = QComboBox()
        self.match_review.addItems(REVIEWS)
        self.match_review.setAccessibleName('Selected match review status')
        self.match_review.currentTextChanged.connect(self.review_match)
        layout.addWidget(self.match_review)
        self.correct_button = QPushButton('Correct match…')
        self.correct_button.clicked.connect(self.correct_match)
        layout.addWidget(self.correct_button)
        for control in [self.search, self.category_filter, self.review_filter]:
            if isinstance(control, QLineEdit):
                control.textChanged.connect(self.filter_matches)
            else:
                control.currentTextChanged.connect(self.filter_matches)
        self.workspace.addWidget(pane)

    def _build_code(self):
        pane = QWidget()
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(4, 0, 4, 0)
        row = QHBoxLayout()
        self.mode = QComboBox()
        self.mode.addItems(['Decompiled code', 'Assembly', 'Metadata'])
        self.mode.currentTextChanged.connect(self.render_match)
        row.addWidget(self.mode)
        self.sync_scroll = QCheckBox('Sync scroll')
        self.sync_scroll.setChecked(True)
        row.addWidget(self.sync_scroll)
        row.addStretch()
        self.previous_diff = QPushButton('Previous diff')
        self.previous_diff.setToolTip('Previous changed hunk · Alt+Up')
        self.previous_diff.clicked.connect(lambda: self.navigate_hunk(-1))
        row.addWidget(self.previous_diff)
        self.next_diff = QPushButton('Next diff')
        self.next_diff.setToolTip('Next changed hunk · Alt+Down')
        self.next_diff.clicked.connect(lambda: self.navigate_hunk(1))
        row.addWidget(self.next_diff)
        self.addAction(self._action('Next difference', lambda: self.navigate_hunk(1), 'Alt+Down'))
        self.addAction(self._action('Previous difference', lambda: self.navigate_hunk(-1), 'Alt+Up'))
        layout.addLayout(row)
        self.match_label = PlainLabel('Select a function match to inspect changes.')
        self.match_label.setWordWrap(True)
        layout.addWidget(self.match_label)
        self.code_split = QSplitter(Qt.Orientation.Horizontal)
        self.views = {}
        self.side_labels = {}
        for side in ['older', 'newer']:
            side_widget = QWidget()
            side_layout = QVBoxLayout(side_widget)
            side_layout.setContentsMargins(0, 0, 0, 0)
            header = QHBoxLayout()
            label = PlainLabel(side.upper())
            label.setWordWrap(True)
            self.side_labels[side] = label
            header.addWidget(label, 1)
            copy = QPushButton('Copy')
            copy.clicked.connect(lambda checked=False, s=side: self.copy_code(s))
            header.addWidget(copy)
            side_layout.addLayout(header)
            view = plain_view('No project open.')
            view.setAccessibleName(f'{side.title()} artifact code')
            self.views[side] = view
            view.verticalScrollBar().valueChanged.connect(lambda value, s=side: self.scroll_other(s, value))
            side_layout.addWidget(view, 1)
            self.code_split.addWidget(side_widget)
        layout.addWidget(self.code_split, 1)
        self.hunk_list = QComboBox()
        self.hunk_list.setAccessibleName('Changed hunks')
        self.hunk_list.currentIndexChanged.connect(self.select_hunk)
        layout.addWidget(self.hunk_list)
        self.workspace.addWidget(pane)

    def _build_findings(self):
        pane = QWidget()
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(6, 0, 0, 0)
        layout.addWidget(PlainLabel('FINDINGS & ANALYST REVIEW'))
        self.finding_search = QLineEdit()
        self.finding_search.setPlaceholderText('Search findings…')
        self.finding_search.setClearButtonEnabled(True)
        self.finding_search.textChanged.connect(self.refresh_findings)
        layout.addWidget(self.finding_search)
        finding_filters = QHBoxLayout()
        self.finding_review_filter = QComboBox()
        self.finding_review_filter.addItems(['All reviews', *REVIEWS])
        self.finding_stale_filter = QComboBox()
        self.finding_stale_filter.addItems(['Current & stale', 'Current only', 'Stale only'])
        for control in [self.finding_review_filter, self.finding_stale_filter]:
            control.currentIndexChanged.connect(self.refresh_findings)
            finding_filters.addWidget(control)
        layout.addLayout(finding_filters)
        self.findings_list = QListWidget()
        self.findings_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.findings_list.setWordWrap(True)
        self.findings_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.findings_list.setMinimumHeight(90)
        self.findings_list.setMaximumHeight(160)
        self.findings_list.currentItemChanged.connect(self.select_finding)
        layout.addWidget(self.findings_list)
        self.finding_detail = plain_view('Optional interpretations appear here. Review matches and annotate without AI.')
        self.finding_detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.finding_detail.setMinimumHeight(180)
        layout.addWidget(self.finding_detail, 2)
        layout.addWidget(PlainLabel('EVIDENCE · select to navigate'))
        self.evidence_list = QListWidget()
        self.evidence_list.setMinimumHeight(90)
        self.evidence_list.setMaximumHeight(140)
        self.evidence_list.currentItemChanged.connect(self.jump_evidence)
        layout.addWidget(self.evidence_list)
        self.bookmark_button = QPushButton('Bookmark selected evidence')
        self.bookmark_button.clicked.connect(self.bookmark_evidence)
        layout.addWidget(self.bookmark_button)
        self.finding_review = QComboBox()
        self.finding_review.addItems(REVIEWS)
        layout.addWidget(PlainLabel('Finding review status'))
        layout.addWidget(self.finding_review)
        self.conclusion = QPlainTextEdit()
        self.conclusion.setPlaceholderText('Analyst conclusion (separate from model content)')
        self.conclusion.setMaximumHeight(85)
        layout.addWidget(self.conclusion)
        self.review_button = QPushButton('Save finding review')
        self.review_button.clicked.connect(self.review_finding)
        layout.addWidget(self.review_button)
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText('Add an analyst note to selected finding or match…')
        self.notes.setMaximumHeight(80)
        self.note_target = QComboBox()
        self.note_target.addItems(['Note on selected match', 'Note on selected finding'])
        self.note_target.currentIndexChanged.connect(self.update_controls)
        layout.addWidget(self.note_target)
        layout.addWidget(self.notes)
        self.note_button = QPushButton('Save note')
        self.note_button.clicked.connect(self.save_note)
        layout.addWidget(self.note_button)
        self.raw_button = QPushButton('Inspect interpretation responses…')
        self.raw_button.clicked.connect(self.inspect_responses)
        layout.addWidget(self.raw_button)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(pane)
        scroll.setMinimumWidth(250)
        self.workspace.addWidget(scroll)

    @property
    def project(self):
        return self.service.project if self.service else None

    def current_match(self):
        item = self.navigator.currentItem()
        match_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        return next((m for m in self.project.matches if m.id == match_id), None) if self.project else None

    def _guard(self, callback):
        try:
            return callback()
        except Exception as exc:
            self.show_error(str(exc))
            return None

    def show_error(self, message):
        self.job_label.setText('Error · ' + message)
        self.logs.appendPlainText('ERROR: ' + message)
        self.statusBar().showMessage(message)
        box = QMessageBox(QMessageBox.Icon.Critical, 'PatchTrace · action failed', message, parent=self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    def set_service(self, service):
        previous = self.service
        self.service = service
        if previous and previous is not service:
            previous.close()
        self.refresh()
        self.settings.setValue('recent/project', str(service.root))
        recent = self.settings.value('recent/projects', [], type=list)
        recent = [str(service.root), *[path for path in recent if path != str(service.root)]]
        self.settings.setValue('recent/projects', recent[:8])
        self.refresh_recent()

    def refresh_recent(self):
        self.recent_menu.clear()
        for path in self.settings.value('recent/projects', [], type=list):
            action = self._action(str(path), lambda checked=False, p=path: self.open_recent(p))
            self.recent_menu.addAction(action)
        self.recent_menu.setEnabled(bool(self.recent_menu.actions()))

    def open_recent(self, path):
        if not self.worker:
            self._guard(lambda: self.set_service(ProjectService.open(Path(path))))

    def backup_project(self):
        if not self.service:
            return
        parent = QFileDialog.getExistingDirectory(self, 'Choose parent directory for a new project backup')
        if parent:
            destination = Path(parent) / f'patchtrace-backup-{time.strftime("%Y%m%d-%H%M%S")}'
            result = self._guard(lambda: self.service.backup(destination))
            if result is not None:
                self.logs.appendPlainText(f'Backup: {result}')
                self.statusBar().showMessage(f'Backup created: {result}')

    def undo_match_correction(self):
        if not self.service:
            return
        annotation = next((a for a in reversed(self.project.annotations)
                           if a.kind == 'match-override' and not a.stale), None)
        if annotation:
            self._guard(lambda: self.service.restore_match_override(annotation.id))
            self.refresh()

    def new_project(self):
        dialog = NewProjectDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        # SQLite connections remain in their owner thread. Creation closes before GUI-thread adoption.
        args = (Path(dialog.older.text()), Path(dialog.newer.text()), dialog.name.text().strip(), Path(dialog.root.text()))
        def create(cancel, event):
            service = ProjectService.create(*args)
            root = service.root
            service.close()
            return root
        def adopt(root):
            if self.worker and self.worker.cancel.is_set():
                self.job_label.setText('Cancelled · created project retained without opening')
                self.logs.appendPlainText(f'Project creation finished before cancellation. Retained directory: {root}')
                return
            self.set_service(ProjectService.open(root))
        self.start_job('Creating project', create, adopt)

    def open_project(self):
        path = QFileDialog.getExistingDirectory(self, 'Open PatchTrace project', self.settings.value('recent/project', ''))
        if path:
            self._guard(lambda: self.set_service(ProjectService.open(Path(path))))

    def open_sample(self):
        parent = QFileDialog.getExistingDirectory(self, 'Choose directory for a new synthetic sample project')
        if not parent:
            return
        root = Path(parent) / f'patchtrace-sample-{time.strftime("%Y%m%d-%H%M%S")}'
        self._guard(lambda: self.set_service(ProjectService.sample(root)))

    def save_project(self):
        if self.service:
            self._guard(self.service.save)
            self.statusBar().showMessage('Project saved')

    def refresh(self):
        self._updating = True
        project = self.project
        if project:
            suffix = ' · SYNTHETIC SAMPLE' if project.sample else ''
            self.project_label.setText(f'{project.name}{suffix} · revision {project.revision}')
            self.setWindowTitle(f'{project.name} · PatchTrace')
            for side in ['older', 'newer']:
                artifact = next(a for a in project.artifacts if a.side == side)
                self.side_labels[side].setText(f'{side.upper()} · {artifact.name}\nSHA-256 {artifact.sha256[:16]}…')
                self.side_labels[side].setToolTip(plain_tip(f'{artifact.name}\nSHA-256 {artifact.sha256}\n{artifact.size:,} bytes'))
        else:
            self.project_label.setText('Open a project or load the synthetic sample to begin.')
        self._load_enrichment()
        self.filter_matches()
        self.refresh_findings()
        self._updating = False
        self.render_match()
        self.update_controls()

    def filter_matches(self, *_):
        previous = self.navigator.currentItem()
        selected_id = previous.data(Qt.ItemDataRole.UserRole) if previous else None
        selected_ids = {item.data(Qt.ItemDataRole.UserRole) for item in self.navigator.selectedItems()}
        self.navigator.blockSignals(True)
        self.navigator.clear()
        query = self.search.text().lower().strip()
        total = len(self.project.matches) if self.project else 0
        findings_matches = {mid for run in self.project.interpretations for finding in run.findings
                            for mid in finding.match_ids} if self.project else set()
        matches = list(self.project.matches) if self.project else []
        if self.order.currentIndex() == 1 and self._ranking:
            # Unranked matches (other runs) keep project order after ranked ones.
            matches.sort(key=lambda m: self._ranking[m.id].rank if m.id in self._ranking else 10**9)
        for match in matches:
            if self.manual_filter.isChecked() and not match.manual:
                continue
            if self.finding_match_filter.isChecked() and match.id not in findings_matches:
                continue
            if self.category_filter.currentIndex() and match.category != self.category_filter.currentText():
                continue
            if self.review_filter.currentIndex() and match.review != self.review_filter.currentText():
                continue
            funcs = match.older + match.newer
            if query and not any(query in (f.name + ' ' + (f.address or '')).lower() for f in funcs):
                continue
            old = ', '.join(f.name for f in match.older) or '—'
            new = ', '.join(f.name for f in match.newer) or '—'
            entry = self._ranking.get(match.id)
            score = f'[{entry.score:>3}] ' if entry and entry.evidence != 'unavailable' else (
                '[ — ] ' if entry else '')
            item = QListWidgetItem(f'{score}{old} → {new}\n{match.category} · {match.review}')
            item.setData(Qt.ItemDataRole.UserRole, match.id)
            tip = f'Run {match.run_id}\nMatch quality: {match.quality} (not vulnerability confidence)'
            if entry:
                tip += (f'\nAttention {entry.score}/100 (raw {entry.raw}/80, rank {entry.rank}, '
                        f'{len(entry.groups)} edit group(s), evidence {entry.evidence})')
            item.setToolTip(plain_tip(tip))
            self.navigator.addItem(item)
            if match.id == selected_id:
                self.navigator.setCurrentItem(item)
            item.setSelected(match.id in selected_ids)
        if self.navigator.currentRow() < 0 and self.navigator.count():
            first_modified = next((index for index in range(self.navigator.count())
                                   if self.navigator.item(index).text().split('\n')[-1].startswith('modified')), 0)
            self.navigator.setCurrentRow(first_modified)
        self.navigator.blockSignals(False)
        self.match_count.setText(f'{self.navigator.count()} / {total} matches')
        self.render_match()
        self.update_controls()

    def select_match(self, *_):
        if not self._updating:
            self.note_target.setCurrentIndex(0)
            self.render_match()
            self.update_controls()

    def render_match(self, *_):
        match = self.current_match()
        self._render_signals(match)
        self._function_offsets = {}
        self._hunks = []
        self._hunk_index = -1
        self.hunk_list.blockSignals(True)
        self.hunk_list.clear()
        if not match:
            for view in self.views.values():
                view.setPlainText('No matching function selected.')
            self.match_label.setText('Select a function match to inspect changes.')
            self.hunk_list.blockSignals(False)
            self.update_controls()
            return
        self.match_label.setText(f'{match.category.title()} · quality: {match.quality} · '
                                 f'{"manual correction · " if match.manual else ""}run {match.run_id[:8]}')
        self.match_review.blockSignals(True)
        self.match_review.setCurrentText(match.review)
        self.match_review.blockSignals(False)
        texts = {}
        for side in ['older', 'newer']:
            chunks = []
            line_offset = 0
            for function in getattr(match, side):
                header = f'// {function.name} · {function.address or "address unavailable"}\n'
                if self.mode.currentIndex() == 0:
                    body = function.code or '[Decompiled code unavailable for this function]'
                elif self.mode.currentIndex() == 1:
                    body = function.assembly or '[Assembly unavailable from this analysis backend]'
                else:
                    body = json.dumps(function.model_dump(mode='json', exclude={'code', 'assembly'}), indent=2)
                self._function_offsets[function.id] = (side, line_offset + 1)
                chunk = header + body.rstrip('\n')
                chunks.append(chunk)
                line_offset += len(chunk.splitlines()) + 1
            texts[side] = '\n\n'.join(chunks) or f'[No {side} function in this relationship]'
            if len(texts[side]) > MAX_VIEW_CHARS:
                texts[side] = texts[side][:MAX_VIEW_CHARS] + '\n[View truncated at 200,000 characters; provenance copy uses full records.]'
        # Alignment preserves original line numbers for evidence navigation through a row map.
        old_lines = texts['older'].splitlines()
        new_lines = texts['newer'].splitlines()
        strategy = alignment_strategy(texts['older'], texts['newer'])
        self.match_label.setToolTip(strategy)
        if strategy != 'exact SequenceMatcher':
            self.match_label.setText(self.match_label.text() + ' · ' + strategy)
        self._line_maps = {'older': {}, 'newer': {}}
        aligned = {'older': [], 'newer': []}
        for hunk in diff_hunks(texts['older'], texts['newer'], match.id):
            operation = hunk.operation
            a, b, c, d = hunk.old_start, hunk.old_end, hunk.new_start, hunk.new_end
            start = len(aligned['older'])
            count = max(b - a, d - c)
            for offset in range(count):
                for side, lines, begin, end in [('older', old_lines, a, b), ('newer', new_lines, c, d)]:
                    if begin + offset < end:
                        self._line_maps[side][begin + offset] = start + offset
                        aligned[side].append(lines[begin + offset])
                    else:
                        aligned[side].append('')
            if operation != 'equal':
                self._hunks.append((start, max(1, count), operation))
                self.hunk_list.addItem(f'{operation.title()} · older lines {a + 1}–{b} / newer {c + 1}–{d}', len(self._hunks) - 1)
        for side in ['older', 'newer']:
            self.views[side].setPlainText('\n'.join(aligned[side]))
            self._highlight_hunks(self.views[side])
        self.hunk_list.blockSignals(False)
        if self._hunks:
            self.select_hunk(0)
        if not self._finding:
            self.show_match_annotations()
        self.update_controls()

    def _highlight_hunks(self, view):
        selections = []
        for start, length, operation in self._hunks:
            selection = QTextEdit.ExtraSelection()
            selection.cursor = QTextCursor(view.document().findBlockByNumber(start))
            end = view.document().findBlockByNumber(start + length - 1)
            selection.cursor.setPosition(end.position() + end.length() - 1, QTextCursor.MoveMode.KeepAnchor)
            selection.format.setBackground(QColor('#263a43' if operation == 'replace' else '#33392b'))
            selection.format.setProperty(QTextCharFormat.Property.FullWidthSelection, True)
            selections.append(selection)
        view.setExtraSelections(selections)

    def navigate_hunk(self, step):
        if self._hunks:
            self.hunk_list.setCurrentIndex((max(0, self._hunk_index) + step) % len(self._hunks))

    def select_hunk(self, index):
        if not 0 <= index < len(self._hunks):
            return
        self._hunk_index = index
        start = self._hunks[index][0]
        for view in self.views.values():
            cursor = QTextCursor(view.document().findBlockByNumber(start))
            view.setTextCursor(cursor)
            view.centerCursor()

    def scroll_other(self, side, value):
        if self.sync_scroll.isChecked() and not self._syncing:
            self._syncing = True
            self.views['newer' if side == 'older' else 'older'].verticalScrollBar().setValue(value)
            self._syncing = False

    def copy_code(self, side):
        match = self.current_match()
        if not match:
            return
        artifact = next(a for a in self.project.artifacts if a.side == side)
        text = f'PatchTrace project {self.project.id} / revision {self.project.revision}\n'
        text += f'{side}: {artifact.name}\nSHA-256: {artifact.sha256}\nRun: {match.run_id}\nMatch: {match.id}\n\n'
        for function in getattr(match, side):
            text += f'Function: {function.name} / {function.id} / {function.address or "unavailable"}\n'
            text += (function.code if self.mode.currentIndex() == 0 else function.assembly
                     if self.mode.currentIndex() == 1 else json.dumps(function.metadata, indent=2)) or '[Unavailable]'
            text += '\n\n'
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage('Copied code with artifact, hash, run and function provenance.')

    def review_match(self, status):
        match = self.current_match()
        if match and not self._updating and not self.worker:
            self._guard(lambda: self.service.review_match(match.id, status))
            self.filter_matches()

    def correct_match(self):
        match = self.current_match()
        if not match:
            return
        dialog = CorrectMatchDialog(self.project, match, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._guard(lambda: self.service.correct_match(match.id, dialog.selected('older'), dialog.selected('newer'),
                                                           dialog.category.currentText(), dialog.reason.text().strip()))
            self.refresh()

    def swap_orientation(self):
        if not self.service:
            return
        answer = QMessageBox.question(self, 'Swap orientation',
                                      'Reverse older and newer? Existing interpretation contexts and findings will become stale.')
        if answer == QMessageBox.StandardButton.Yes:
            self._guard(self.service.swap_orientation)
            self.refresh()

    def refresh_findings(self, *_):
        current_id = self._finding.id if self._finding else None
        selected_ids = {item.data(Qt.ItemDataRole.UserRole) for item in self.findings_list.selectedItems()}
        self.findings_list.blockSignals(True)
        self.findings_list.clear()
        for run in self.project.interpretations if self.project else []:
            for finding in run.findings:
                if self.finding_search.text().lower().strip() not in (finding.summary + ' ' + finding.fix_purpose).lower():
                    continue
                if self.finding_review_filter.currentIndex() and finding.review != self.finding_review_filter.currentText():
                    continue
                if self.finding_stale_filter.currentIndex() == 1 and finding.stale:
                    continue
                if self.finding_stale_filter.currentIndex() == 2 and not finding.stale:
                    continue
                item = QListWidgetItem(f'{"STALE · " if finding.stale else ""}{finding.summary}\n'
                                       f'{finding.category} · {finding.review}')
                item.setData(Qt.ItemDataRole.UserRole, finding.id)
                item.setToolTip(plain_tip(finding.summary))
                self.findings_list.addItem(item)
                if finding.id == current_id:
                    self.findings_list.setCurrentItem(item)
                item.setSelected(finding.id in selected_ids)
        self.findings_list.blockSignals(False)
        self.select_finding()

    def select_finding(self, *_):
        self._finding = None
        self._context = None
        self._evidence = {}
        item = self.findings_list.currentItem()
        finding_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        for run in self.project.interpretations if self.project else []:
            for finding in run.findings:
                if finding.id == finding_id:
                    self._finding = finding
                    self._context = run.context
        self.evidence_list.clear()
        self.conclusion.clear()
        if not self._finding:
            self.show_match_annotations()
            self.update_controls()
            return
        finding = self._finding
        self.note_target.setCurrentIndex(1)
        hypothesis = finding.hypothesis
        detail = ('STALE: retained context no longer describes the current project.\n\n' if finding.stale else '')
        detail += f'{finding.summary}\n\nFix purpose: {finding.fix_purpose}\nCategory: {finding.category}\n'
        detail += f'Confidence: {hypothesis.confidence} (model assessment, not validation)\n\n{hypothesis.explanation}'
        for title, values in [('Preconditions', hypothesis.preconditions), ('Unknowns', hypothesis.unknowns),
                              ('Proposed verification', hypothesis.verification)]:
            detail += '\n\n' + title + ':\n' + ('\n'.join('• ' + value for value in values) or 'None supplied')
        for number, alternative in enumerate(finding.alternatives, 1):
            detail += f'\n\nAlternative {number} ({alternative.confidence}): {alternative.explanation}'
            for title, values in [('Preconditions', alternative.preconditions), ('Unknowns', alternative.unknowns),
                                  ('Proposed verification', alternative.verification)]:
                detail += '\n' + title + ': ' + ('; '.join(values) or 'None supplied')
        if finding.cwe:
            detail += f'\n\nProposed CWE: {finding.cwe}\nRationale: {finding.cwe_rationale or "not supplied"}'
        notes = [a for a in self.project.annotations if a.target_id == finding.id]
        if notes:
            detail += '\n\nAnalyst annotations:\n' + '\n'.join(f'{a.kind}{" [stale]" if a.stale else ""}: {a.text}' for a in notes)
        self.finding_detail.setPlainText(detail)
        self.finding_review.setCurrentText(finding.review)
        self.conclusion.setPlainText(finding.analyst_conclusion)
        self._evidence = {e.id: e for e in self._context.evidence}
        groups = [('Support', hypothesis.supporting), ('Counterevidence', hypothesis.contradicting)]
        for number, alternative in enumerate(finding.alternatives, 1):
            groups.extend([(f'Alternative {number} support', alternative.supporting),
                           (f'Alternative {number} counterevidence', alternative.contradicting)])
        for label, ids in groups:
            for evidence_id in ids:
                evidence = self._evidence.get(evidence_id)
                text = (f'{label} · {evidence.side} lines {evidence.start_line}–{evidence.end_line}\n{evidence.id[:12]}'
                        if evidence else f'{label} · unavailable evidence {evidence_id}')
                item = QListWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, evidence_id)
                self.evidence_list.addItem(item)
        self.update_controls()

    def show_match_annotations(self):
        match = self.current_match()
        if not match:
            self.finding_detail.setPlainText('Select a finding or function match to review analyst annotations.')
            return
        notes = [a for a in self.project.annotations if a.target_id == match.id]
        text = f'Match {match.id}\nCategory: {match.category}\nReview: {match.review}\n'
        if match.reason:
            text += f'\nAnalyst correction reason: {match.reason}\n'
        text += '\nAnalyst annotations:\n' + ('\n\n'.join(
            f'{a.kind}{" [stale]" if a.stale else ""}: {a.text}' for a in notes) or 'No annotations yet.')
        self.finding_detail.setPlainText(text)

    def _render_signals(self, match):
        self.signal_list.blockSignals(True)
        self.signal_list.clear()
        signal_set = self._signal_sets.get(match.id) if match else None
        if not match:
            pass
        elif signal_set is None:
            self.signal_list.addItem(self._ranking_note or 'Not ranked yet. Use Rank changes (Ctrl+R).')
        else:
            for signal in signal_set.signals:
                first = signal.locations[0]
                item = QListWidgetItem(f'{signal.detector} · {signal.confidence} · {first.side} '
                                       f'lines {first.start_line}-{first.end_line}')
                item.setData(Qt.ItemDataRole.UserRole, signal.signal_id)
                item.setToolTip(plain_tip(signal.rationale + ('\nLimitations: ' + ', '.join(signal.limitations)
                                                               if signal.limitations else '')))
                self.signal_list.addItem(item)
            unavailable = [o.detector for o in signal_set.outcomes if o.status == 'unavailable']
            if not signal_set.signals:
                self.signal_list.addItem('No change signals (evidence complete).' if not unavailable else
                                         'No change signals; evidence unavailable for: ' + ', '.join(unavailable))
            elif unavailable:
                self.signal_list.addItem('Unavailable detectors: ' + ', '.join(unavailable))
        self.signal_list.blockSignals(False)

    def jump_signal(self, current=None, *_):
        if current is None or self.current_match() is None:
            return
        signal_set = self._signal_sets.get(self.current_match().id)
        signal = next((s for s in (signal_set.signals if signal_set else ())
                       if s.signal_id == current.data(Qt.ItemDataRole.UserRole)), None)
        if signal is None:
            return
        location = signal.locations[0]
        if location.function_id not in self._function_offsets:
            return
        if self.mode.currentIndex() != 0:
            self.mode.setCurrentIndex(0)
        side, offset = self._function_offsets[location.function_id]
        start = self._line_maps[side].get(offset + location.start_line - 1)
        end = self._line_maps[side].get(offset + location.end_line - 1)
        if start is None or end is None:
            return
        view = self.views[side]
        cursor = QTextCursor(view.document().findBlockByNumber(start))
        block = view.document().findBlockByNumber(end)
        cursor.setPosition(block.position() + block.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        view.setTextCursor(cursor)
        view.centerCursor()

    def _load_enrichment(self):
        """Show the stored ranking only when it was computed from the current run and pairings."""
        from .enrichment import pipeline
        from .enrichment.contracts import EnrichmentError
        from .enrichment.storage import EnrichmentStore
        self._ranking, self._signal_sets, self._ranking_note = {}, {}, ''
        self._ranking_result = None
        if not self.service:
            return
        try:
            ranking, sets, note = pipeline.load_default(EnrichmentStore(self.service.store), self.project)
        except EnrichmentError as exc:
            self._ranking_note = f'Stored ranking unreadable: {exc}'
            return
        self._ranking_note = note
        if ranking is not None:
            self._ranking_result = ranking
            self._ranking = {e.match_id: e for e in ranking.entries}
            self._signal_sets = {s.match_id: s for s in sets}

    def _enrichment_export(self):
        """The exact default-profile ranking shown in the navigator, for preview and report alike."""
        if self._ranking_result is None:
            return None
        return {'ranking': self._ranking_result.model_dump(mode='json'), 'stale': False}

    def rank_changes(self):
        if not self.service or self.worker:
            return
        from .enrichment import pipeline
        snapshot = self.project.model_copy(deep=True)

        def task(cancel, event):
            return pipeline.run(snapshot, pipeline.PipelineOptions(), cancel,
                                lambda message: event(type('Event', (), {'message': message, 'stage': 'rank'})()))

        def complete(result):
            from .enrichment.storage import EnrichmentStore
            written = pipeline.publish(EnrichmentStore(self.service.store), self.project, result)
            stale = any(e.stale for e in written)
            self._load_enrichment()
            if stale:
                self._ranking_note = 'Project changed while ranking; result stored as stale. Rank again.'
            else:
                self.order.setCurrentIndex(1)
            self.logs.appendPlainText(f'Ranking {result.status.status}: ' + ', '.join(
                f'{s.stage} {s.status}' for s in result.status.stages))
            self.filter_matches()

        self.start_job('Ranking changes', task, complete)

    def jump_evidence(self, current=None, *_):
        if not current:
            return
        evidence = self._evidence.get(current.data(Qt.ItemDataRole.UserRole))
        if not evidence:
            return
        if self._finding.stale or self._context.stale or self._context.revision != self.project.revision:
            text_dialog(self, 'Stale evidence · immutable original context', evidence.text)
            return
        verified = self._guard(lambda: resolve_evidence(self.project, evidence.id))
        if verified is None:
            return
        evidence = verified
        match = next((m for m in self.project.matches if m.run_id == evidence.run_id
                      and any(f.id == evidence.function_id and f.artifact_id == evidence.artifact_id
                              for f in getattr(m, evidence.side))), None)
        if not match:
            self.show_error('Evidence does not resolve to the current run. Inspect the retained context instead.')
            return
        self.search.clear()
        self.category_filter.setCurrentIndex(0)
        self.review_filter.setCurrentIndex(0)
        self.manual_filter.setChecked(False)
        self.finding_match_filter.setChecked(False)
        for index in range(self.navigator.count()):
            item = self.navigator.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == match.id:
                self.navigator.setCurrentItem(item)
                break
        self.mode.setCurrentIndex(0)
        self.render_match()
        side, offset = self._function_offsets[evidence.function_id]
        start = self._line_maps[side].get(offset + evidence.start_line - 1)
        end = self._line_maps[side].get(offset + evidence.end_line - 1)
        if start is None or end is None:
            text_dialog(self, 'Evidence beyond displayed code · retained context', evidence.text)
            return
        view = self.views[side]
        cursor = QTextCursor(view.document().findBlockByNumber(start))
        block = view.document().findBlockByNumber(end)
        cursor.setPosition(block.position() + block.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        view.setTextCursor(cursor)
        view.centerCursor()
        view.setFocus()
        self.update_controls()

    def bookmark_evidence(self):
        item = self.evidence_list.currentItem()
        if item:
            evidence_id = item.data(Qt.ItemDataRole.UserRole)
            self._guard(lambda: self.service.annotate(evidence_id, 'Evidence bookmarked by analyst', kind='bookmark'))
            self.statusBar().showMessage('Evidence bookmark saved.')

    def review_finding(self):
        if self._finding:
            self._guard(lambda: self.service.review_finding(self._finding.id, self.finding_review.currentText(),
                                                            self.conclusion.toPlainText()))
            self.refresh_findings()

    def save_note(self):
        target = self._finding if self.note_target.currentIndex() == 1 else self.current_match()
        text = self.notes.toPlainText().strip()
        if target and text:
            self._guard(lambda: self.service.annotate(target.id, text, kind='note'))
            self.notes.clear()
            self.refresh_findings()
            self.statusBar().showMessage('Analyst note saved.')

    def inspect_responses(self):
        records = []
        for run in self.project.interpretations if self.project else []:
            records.append(f'Run {run.id} · {run.status} · {run.provider}/{run.model}\n'
                           f'Error: {run.error or "none"}\nContext digest: {run.context.digest}\n\n{run.raw_response}')
        text_dialog(self, 'Retained interpretation responses · plain text', '\n\n'.join(records) or 'No interpretation attempts.')

    def backend_config(self):
        return BackendConfig(python_executable=str(self.settings.value('backend/python', '')),
                             ghidra_dir=str(self.settings.value('backend/ghidra', '')),
                             timeout_seconds=int(self.settings.value('backend/timeout', 3600)),
                             allow_symbol_downloads=self.settings.value('backend/allow_symbol_downloads', False,
                                                                         type=bool),
                             java_home=str(self.settings.value('backend/java_home', '')))

    def run_analysis(self):
        if not self.project:
            return
        config = self.backend_config()
        if not str(config.python_executable) or not str(config.ghidra_dir):
            self.setup()
            config = self.backend_config()
        if not str(config.python_executable) or not str(config.ghidra_dir):
            self.show_error('Configure the external Python executable and Ghidra directory in Setup.')
            return
        snapshot, root, service = self.project.model_copy(deep=True), self.service.root, self.service
        def compare(cancel, event):
            raw_path, run = run_comparison(config, snapshot, root, cancel, event)
            prepared = None
            if run.status == 'completed':
                try:
                    if cancel.is_set():
                        raise ValueError('PT-CANCEL: cancelled before normalization')
                    prepared = service.prepare_analysis(raw_path, run)
                    if cancel.is_set():
                        service.discard_import(prepared)
                        prepared = None
                        raise ValueError('PT-CANCEL: cancelled during normalization')
                except Exception as exc:
                    run = quarantine_failed_run(root, run, str(exc))
                    if cancel.is_set():
                        run = run.model_copy(update={'status': 'cancelled'})
            return raw_path, run, prepared
        self.start_job('Comparing artifacts', compare, self.complete_analysis)

    def complete_analysis(self, result):
        raw_path, run = result[:2]
        prepared = result[2] if len(result) > 2 else None
        if self.worker and self.worker.cancel.is_set() and run.status == 'completed':
            if prepared is not None:
                self.service.discard_import(prepared)
            run = quarantine_failed_run(self.service.root, run, 'PT-CANCEL: cancelled before result commit')
            run = run.model_copy(update={'status': 'cancelled'})
        if run.status == 'completed':
            if prepared is not None:
                self.service.apply_import(prepared)
            else:
                self.service.apply_analysis(raw_path, run)
            self.refresh()
        elif run.status == 'identical':
            self.service.record_terminal_run(run)
            self.refresh()
            self.logs.appendPlainText('Identical SHA-256 hashes · analysis skipped')
        else:
            self.service.record_terminal_run(run)
            message = run.error or f'Comparison {run.status}; previous results preserved.'
            if run.status == 'cancelled':
                self.job_label.setText('Cancelled · previous results preserved')
                self.logs.appendPlainText(message)
            else:
                self.show_error(message)

    def import_diff(self):
        if not self.project:
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import Ghidriff JSON for current artifact pair', '', 'JSON (*.json)')
        if not path:
            return
        # Service prepare_import performs bounded parsing/normalization without touching its aggregate.
        service = self.service
        def commit(prepared):
            if self.worker and self.worker.cancel.is_set():
                service.discard_import(prepared)
                self.job_label.setText('Cancelled · import not applied')
                return
            service.apply_import(prepared)
            self.refresh()
        self.start_job('Importing Ghidriff JSON', lambda cancel, event: service.prepare_import(Path(path)), commit)

    def preview_interpretation(self):
        if not self.project or self.worker:
            return
        match_ids = [item.data(Qt.ItemDataRole.UserRole) for item in self.navigator.selectedItems()]
        if not match_ids:
            return
        budget = int(self.settings.value('provider/context_budget', 24000))
        context = self._guard(lambda: build_context(self.project, match_ids, max_chars=budget))
        if context is None:
            return
        dialog = ContextDialog(context, self.settings, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        config = dialog.config()
        # Persist non-secret preferences only; credentials live solely in the worker closure.
        self.settings.setValue('provider/kind', dialog.kind.currentText())
        self.settings.setValue('provider/endpoint', dialog.endpoint.text().strip())
        self.settings.setValue('provider/model', dialog.model.text().strip())
        self.start_job('Interpreting explicit context', lambda cancel, event: interpret(context, config, cancel),
                       self.complete_interpretation)

    def complete_interpretation(self, run):
        if self.worker and self.worker.cancel.is_set() and run.status == 'completed':
            run = run.model_copy(update={'status': 'cancelled', 'findings': [],
                                         'error': 'PT-CANCEL: cancelled before interpretation commit'})
        self.service.add_interpretation(run)
        self.refresh()
        if run.status == 'failed':
            self.show_error(run.error or 'Interpretation failed. Inspect the retained raw response; no findings were promoted.')
        elif run.status == 'cancelled':
            self.job_label.setText('Interpretation cancelled')
        elif run.findings:
            self.findings_list.setCurrentRow(self.findings_list.count() - len(run.findings))

    def start_job(self, title, task, complete):
        if self.worker:
            return
        self._job_title = title
        self._job_started = time.monotonic()
        self.job_label.setText(title + '…')
        self.logs.appendPlainText(title)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        worker = Worker(task, self)
        self.worker = worker
        worker.event_ready.connect(self.job_event)
        worker.result_ready.connect(lambda result: self._guard(lambda: complete(result)))
        worker.failed.connect(self.show_error)
        worker.finished.connect(self.job_finished)
        self.timer.start(1000)
        self.update_controls()
        worker.start()

    def job_event(self, event):
        message = getattr(event, 'message', str(event))
        stage = getattr(event, 'stage', '')
        self.logs.appendPlainText((stage + ' · ' if stage else '') + message)
        value = getattr(event, 'progress', None)
        if value is not None:
            self.progress.setRange(0, 100)
            self.progress.setValue(int(value * 100))

    def _elapsed(self):
        if self.worker:
            state = 'Cancelling' if self.worker.cancel.is_set() else self._job_title
            self.job_label.setText(f'{state} · {int(time.monotonic() - self._job_started)} seconds')

    def cancel_job(self):
        if self.worker:
            self.worker.cancel.set()
            self.cancel_action.setEnabled(False)
            self.job_label.setText('Cancelling · waiting for worker cleanup')

    def job_finished(self):
        worker = self.worker
        self.worker = None
        self.timer.stop()
        self.progress.setVisible(False)
        if not self.job_label.text().startswith(('Error', 'Cancelled', 'Interpretation cancelled')):
            self.job_label.setText(f'Finished · {int(time.monotonic() - self._job_started)} seconds')
        if worker:
            worker.deleteLater()
        self.update_controls()
        if self._close_requested:
            self.close()

    def update_controls(self):
        if not hasattr(self, 'navigator') or not hasattr(self, 'raw_button'):
            return
        idle = self.worker is None
        project = bool(self.service)
        match = self.current_match()
        for action in [self.new_action, self.open_action, self.sample_action, self.setup_action]:
            action.setEnabled(idle)
        for action in [self.run_action, self.import_action, self.export_action, self.save_action, self.swap_action,
                       self.backup_action]:
            action.setEnabled(project and idle)
        self.recent_menu.setEnabled(idle and bool(self.recent_menu.actions()))
        self.undo_match_action.setEnabled(project and idle and any(
            a.kind == 'match-override' and not a.stale for a in self.project.annotations))
        self.interpret_action.setEnabled(project and idle and bool(self.navigator.selectedItems()))
        self.rank_action.setEnabled(project and idle and any(r.status == "completed" and r.raw_sha256
                                                              for r in self.project.runs))
        self.cancel_action.setEnabled(not idle and not self.worker.cancel.is_set())
        self.correct_button.setEnabled(bool(match) and idle)
        self.match_review.setEnabled(bool(match) and idle)
        self.previous_diff.setEnabled(bool(self._hunks))
        self.next_diff.setEnabled(bool(self._hunks))
        self.hunk_list.setEnabled(bool(self._hunks))
        self.finding_review.setEnabled(bool(self._finding) and idle)
        self.conclusion.setEnabled(bool(self._finding) and idle)
        self.review_button.setEnabled(bool(self._finding) and idle)
        note_target = self._finding if self.note_target.currentIndex() == 1 else match
        self.note_button.setEnabled(bool(note_target) and idle)
        self.note_target.setEnabled(project and idle)
        self.notes.setEnabled(project and idle)
        self.bookmark_button.setEnabled(bool(self.evidence_list.currentItem()) and idle)
        self.raw_button.setEnabled(project and bool(self.project.interpretations))

    def setup(self):
        dialog = SetupDialog(self.settings, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.settings.setValue('backend/python', dialog.python.text().strip())
        self.settings.setValue('backend/ghidra', dialog.ghidra.text().strip())
        self.settings.setValue('backend/java_home', dialog.java_home.text().strip())
        self.settings.setValue('backend/timeout', dialog.timeout.value())
        self.settings.setValue('backend/allow_symbol_downloads', dialog.allow_symbol_downloads.isChecked())
        self.settings.setValue('desktop/font_size', dialog.font_size.value())
        self.settings.setValue('provider/context_budget', dialog.context_budget.value())
        self.settings.setValue('desktop/sync', dialog.sync.isChecked())
        self.apply_font(dialog.font_size.value())
        self.sync_scroll.setChecked(dialog.sync.isChecked())
        self.statusBar().showMessage('Setup saved. Run comparison to analyze the selected pair.')

    def export_report(self):
        if not self.project:
            return
        selected = [item.data(Qt.ItemDataRole.UserRole) for item in self.findings_list.selectedItems()]
        dialog = ExportDialog(self.project, self.service.root, selected, self)
        dialog.enrichment = self._enrichment_export()
        dialog.refresh_preview()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            output = Path(dialog.destination.text())
            result = self._guard(lambda: export_project(self.project, dialog.format.currentText(), output,
                                                       **dialog.options()))
            if result is not None:
                self.statusBar().showMessage(f'Report written: {output}')
                self.logs.appendPlainText(f'Export: {output}')

    def show_help(self):
        text_dialog(self, 'PatchTrace workflow and dependency setup',
                    '1. Create a project with explicit older and newer PE AMD64 artifacts, or open the synthetic sample.\n'
                    '2. Import a Ghidriff JSON, or configure external dependencies and run comparison.\n'
                    '3. Search and filter function matches. Inspect decompiled code, assembly and metadata.\n'
                    '4. Review matches, correct relationships, and save analyst notes.\n'
                    '5. Optionally select matches and Interpret. Review exact context before Send.\n'
                    '6. Follow evidence, assess alternatives and unknowns, save an independent analyst conclusion.\n'
                    '7. Export a report after reviewing its exact preview. Code is excluded by default.\n\n'
                    'Dependency setup\n'
                    'Use an external Python environment with the supported Ghidriff version installed. Select its\n'
                    'python executable and the unpacked Ghidra installation in Setup. Ghidra requires a compatible\n'
                    'Java installation. Diagnose reports dependency failures without running either target artifact.\n'
                    'Ghidriff and Ghidra are not bundled and no dependency is downloaded automatically.\n\n'
                    'Interpretation is optional. Ollama must use a loopback endpoint; OpenAI-compatible providers\n'
                    'require HTTPS. API keys remain in memory for the current request and are never saved.\n'
                    'Model assessments, match quality and review status do not establish vulnerability validity.\n'
                    'Stale findings retain their original context and cannot navigate into a different analysis run.')

    def apply_font(self, size):
        font = QFont('Consolas', size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        for view in self.views.values():
            view.setFont(font)
            view.setStyleSheet(f'QPlainTextEdit {{ font-size: {size}pt; }}')
        self.logs.setFont(font)
        self.logs.setStyleSheet(f'QPlainTextEdit {{ font-size: {size}pt; }}')

    def restore_preferences(self):
        geometry = self.settings.value('desktop/geometry')
        if geometry:
            self.restoreGeometry(geometry)
        screen = QApplication.screenAt(self.frameGeometry().center()) or QApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            self.setMinimumSize(min(960, available.width()), min(640, available.height()))
            self.resize(min(self.width(), available.width()), min(self.height(), available.height()))
            if not available.contains(self.frameGeometry()):
                x = max(available.left(), min(self.x(), available.right() - self.width() + 1))
                y = max(available.top(), min(self.y(), available.bottom() - self.height() + 1))
                self.move(x, y)
        for name, splitter in [('workspace', self.workspace), ('vertical', self.vertical), ('code', self.code_split)]:
            state = self.settings.value('desktop/' + name)
            if state:
                splitter.restoreState(state)
            splitter.setChildrenCollapsible(False)
        self.apply_font(int(self.settings.value('desktop/font_size', 11)))
        self.sync_scroll.setChecked(self.settings.value('desktop/sync', True, type=bool))

    def closeEvent(self, event):
        if self.worker:
            self._close_requested = True
            self.cancel_job()
            event.ignore()
            return
        self.settings.setValue('desktop/geometry', self.saveGeometry())
        for name, splitter in [('workspace', self.workspace), ('vertical', self.vertical), ('code', self.code_split)]:
            self.settings.setValue('desktop/' + name, splitter.saveState())
        self.settings.setValue('desktop/sync', self.sync_scroll.isChecked())
        self.settings.sync()
        if self.service:
            self.service.close()
            self.service = None
        super().closeEvent(event)
