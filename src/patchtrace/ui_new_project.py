"""Explicit create/retry choices and generation-bound background project adoption."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event

from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .project_retry import CreationCancelled
from .service import ProjectService
from .tooltips import apply_tooltip, apply_tooltips


class NewProjectDialog(QDialog):
    RETRY_REQUESTED = 2

    def __init__(self, parent=None):
        from .ui import ArtifactPathEdit, PlainLabel, dialog_buttons

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
        for title, edit, directory, browse_tip in [
                ('Older PE x64', self.older, False, 'new_project.older_browse'),
                ('Newer PE x64', self.newer, False, 'new_project.newer_browse'),
                ('New project directory', self.root, True, 'new_project.root_browse')]:
            row = QWidget()
            horizontal = QHBoxLayout(row)
            horizontal.setContentsMargins(0, 0, 0, 0)
            horizontal.addWidget(edit)
            choose = QPushButton('Browse…')
            apply_tooltip(choose, browse_tip)
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
        apply_tooltips(self, {'name': 'new_project.name', 'older': 'new_project.older',
                              'newer': 'new_project.newer', 'root': 'new_project.root'})
        apply_tooltip(swap, 'new_project.swap')
        layout.addWidget(dialog_buttons(self, 'Create project', 'new_project'))
        self.retry_button = QPushButton('Check and retry incomplete creation')
        apply_tooltip(self.retry_button, 'new_project.retry')
        self.retry_button.clicked.connect(self.retry)
        layout.addWidget(self.retry_button)

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
        try:
            occupied = root.exists() and (not root.is_dir() or any(root.iterdir()))
        except OSError:
            occupied = True
        if occupied:
            self.error.setText('The project directory must be absent or empty.')
            return
        super().accept()

    def retry(self):
        if not self.name.text().strip() or not self.root.text().strip():
            self.error.setText('Enter a project name and the incomplete project directory.')
            return
        if not all(Path(edit.text()).is_file() for edit in [self.older, self.newer]):
            self.error.setText('Choose the same two input files for this incomplete creation.')
            return
        root = Path(self.root.text())
        try:
            occupied = root.is_dir() and any(root.iterdir())
        except OSError:
            occupied = False
        if not occupied:
            self.error.setText('Retry requires an existing incomplete directory. Use Create for an absent or empty folder.')
            return
        self.done(self.RETRY_REQUESTED)


@dataclass(frozen=True)
class CreationOutcome:
    root: Path | None
    cancel: Event


def start_project_creation(window, dialog_type=NewProjectDialog):
    if window.worker is not None:
        return
    dialog = dialog_type(window)
    choice = dialog.exec()
    if choice not in (QDialog.DialogCode.Accepted, NewProjectDialog.RETRY_REQUESTED):
        return
    retry = choice == NewProjectDialog.RETRY_REQUESTED
    args = (Path(dialog.older.text()), Path(dialog.newer.text()), dialog.name.text().strip(), Path(dialog.root.text()))
    origin_service, origin_key = window.service, window.panels.port.key()

    def create(cancel, event):
        try:
            service = (ProjectService.retry_create(*args, cancel=cancel) if retry
                       else ProjectService.create(*args))
            with service:
                return CreationOutcome(service.root, cancel)
        except CreationCancelled:
            return CreationOutcome(None, cancel)

    def adopt(outcome):
        current = window.service is origin_service and window.panels.port.key() == origin_key
        if outcome.root is None:
            if current:
                window.job_label.setText('Cancelled · project creation stopped')
            return
        if outcome.cancel.is_set() or not current:
            prefix = 'Cancelled' if outcome.cancel.is_set() else 'Note'
            window.job_label.setText(prefix + ' · created project retained without opening')
            window.logs.appendPlainText(f'Created project retained without opening: {outcome.root}')
            return
        window.set_service(ProjectService.open(outcome.root))

    window.start_job('Checking and retrying incomplete creation' if retry else 'Creating project', create, adopt)
