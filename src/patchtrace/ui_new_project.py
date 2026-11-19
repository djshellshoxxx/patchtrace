"""Cancellation-aware creation and context-bound GUI adoption over the current core."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event

from PySide6.QtWidgets import QDialog

from .input_readers import InputReadError
from .service import ProjectService


@dataclass(frozen=True)
class CreationOutcome:
    root: Path | None
    cancel: Event


def start_project_creation(window, dialog_type):
    if window.worker is not None or window._close_requested:
        return
    dialog = dialog_type(window)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    if window.worker is not None or window._close_requested:
        return
    args = (Path(dialog.older.text()), Path(dialog.newer.text()), dialog.name.text().strip(),
            Path(dialog.root.text()))
    origin_service, origin_key = window.service, window.panels.port.key()

    def create(cancel, event):
        def checkpoint(_count):
            if cancel.is_set():
                raise InputReadError('cancelled')

        try:
            service = ProjectService.create(*args, checkpoint=checkpoint)
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

    window.start_job('Creating project', create, adopt)
