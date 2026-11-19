"""Cancellation-aware creation and context-bound GUI adoption over the current core."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event

from PySide6.QtWidgets import QDialog, QPushButton

from .input_readers import InputReadError
from .persistence import creation_directory_available
from .service import ProjectService
from .tooltips import apply_tooltip

RETRY_INCOMPLETE = 2


@dataclass(frozen=True)
class CreationOutcome:
    root: Path | None
    cancel: Event


def add_retry_action(dialog, layout):
    dialog.retry_button = QPushButton('Retry incomplete project', dialog)
    dialog.retry_button.setObjectName('new_project.retry')
    apply_tooltip(dialog.retry_button, 'new_project.retry')
    dialog.retry_button.clicked.connect(lambda: accept_creation(dialog, retry=True))
    layout.addWidget(dialog.retry_button)


def accept_creation(dialog, *, retry=False):
    if not dialog.name.text().strip() or not dialog.root.text().strip():
        dialog.error.setText('Enter a project name and a project directory.')
        return
    if not all(Path(edit.text()).is_file() for edit in (dialog.older, dialog.newer)):
        dialog.error.setText('Choose two existing binary files. PE format and architecture are validated on creation.')
        return
    if not retry and not creation_directory_available(Path(dialog.root.text())):
        dialog.error.setText('The project directory must be absent or empty. Use Retry incomplete project for verified leftovers.')
        return
    if retry:
        dialog.done(RETRY_INCOMPLETE)
    else:
        QDialog.accept(dialog)


def start_project_creation(window, dialog_type):
    if window.worker is not None or window._close_requested:
        return
    dialog = dialog_type(window)
    choice = dialog.exec()
    if choice not in (QDialog.DialogCode.Accepted, RETRY_INCOMPLETE):
        return
    if window.worker is not None or window._close_requested:
        return
    args = (Path(dialog.older.text()), Path(dialog.newer.text()), dialog.name.text().strip(),
            Path(dialog.root.text()))
    origin_service, origin_key = window.service, window.panels.port.key()
    creator = ProjectService.retry_create if choice == RETRY_INCOMPLETE else ProjectService.create

    def create(cancel, event):
        def checkpoint(_count):
            if cancel.is_set():
                raise InputReadError('cancelled')

        try:
            service = creator(*args, checkpoint=checkpoint)
        except InputReadError as exc:
            if exc.reason == 'cancelled':
                return CreationOutcome(None, cancel)
            raise
        # SQLite remains on its creator thread. Closing is observable; a failed
        # close must not manufacture a successful GUI adoption receipt.
        with service:
            return CreationOutcome(service.root, cancel)

    def adopt(outcome):
        current = window.service is origin_service and window.panels.port.key() == origin_key
        if outcome.root is None:
            if current and not window._close_requested:
                window.job_label.setText('Cancelled · project creation stopped')
            return
        if outcome.cancel.is_set() or not current or window._close_requested:
            prefix = 'Cancelled' if outcome.cancel.is_set() else 'Note'
            window.job_label.setText(prefix + ' · created project retained without opening')
            window.logs.appendPlainText(f'Created project retained without opening: {outcome.root}')
            return
        window.set_service(ProjectService.open(outcome.root))

    window.start_job('Retrying incomplete project' if choice == RETRY_INCOMPLETE else 'Creating project', create, adopt)
