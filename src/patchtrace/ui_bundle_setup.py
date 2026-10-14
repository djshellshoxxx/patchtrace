"""Setup dialog row for the bundled analysis runtime (BUNDLE plan section 8). No new window.

The dialog owns one ``BundleSetup``. Discovery results arrive from the dialog's existing background
worker; the full hash verification runs in its own ``Worker`` and never touches the GUI thread or the
dialog's saved settings.
"""
from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QWidget
from shiboken6 import isValid

from .backend_bundle import verify_bundle
from .runtime_discovery import EXTRACT_AGAIN, BundleStatus, bundle_work_dir
from .tooltips import apply_tooltips

OK_TEXT = 'Bundled runtime: ok (fast check)'
FOUND_NOTE = 'Bundled analysis runtime found next to PatchTrace ({id}). Run Diagnose dependencies to verify it.'
UNUSABLE_NOTE = 'A bundled analysis runtime was found next to PatchTrace but is unusable ({code}).'
_THREADS: set = set()  # unparented running workers: a destroyed dialog must not abort a QThread


def problem_text(code: str) -> str:
    return f'Bundled runtime problem: {code} - {EXTRACT_AGAIN}'


class BundleSetup:
    def __init__(self, dialog, layout) -> None:
        self.dialog = dialog
        self.state: BundleStatus | None = None
        self._thread = None
        self.status = QLineEdit()
        self.status.setReadOnly(True)
        self.status.setAccessibleName('Bundled runtime status')
        self.verify_button = QPushButton('Verify bundle files')
        self.verify_button.setAccessibleName('Verify bundle files')
        self.verify_button.clicked.connect(self.verify)
        self.cancel_button = QPushButton('Cancel verification')
        self.cancel_button.setAccessibleName('Cancel bundle verification')
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)
        self.row = QWidget()
        horizontal = QHBoxLayout(self.row)
        horizontal.setContentsMargins(0, 0, 0, 0)
        for widget in (self.status, self.verify_button, self.cancel_button):
            horizontal.addWidget(widget)
        self.row.setVisible(False)
        layout.addWidget(self.row)
        apply_tooltips(self, {'status': 'setup.backend.bundle', 'verify_button': 'setup.backend.verify',
                              'cancel_button': 'setup.backend.verify_cancel'})

    def discovered(self, state: BundleStatus | None) -> str | None:
        """Show the fast-check outcome; pre-fill empty runtime fields when it is usable. Returns a note."""
        self.state = state
        self.row.setVisible(state is not None)
        self.refresh()
        if state is None:
            return None
        if not state.ok or state.ref is None:
            self.status.setText(problem_text(state.code))
            return UNUSABLE_NOTE.format(code=state.code)
        self.status.setText(OK_TEXT)
        for edit, path in ((self.dialog.python, state.ref.python), (self.dialog.ghidra, state.ref.ghidra),
                           (self.dialog.java_home, state.ref.java_home)):
            if not edit.text().strip():
                edit.setText(str(path))
        return FOUND_NOTE.format(id=state.runtime_id)

    def refresh(self) -> None:
        """Enable Verify only for a usable bundle while nothing else (or this verification) is running."""
        usable = self.state is not None and self.state.ok and self.state.ref is not None
        idle = not self.dialog._busy_kind
        self.verify_button.setEnabled(usable and idle)
        self.cancel_button.setEnabled(self._thread is not None)

    def verify(self) -> None:
        if self._thread is not None or self.dialog._busy_kind or self.state is None or not self.state.ok:
            return
        from .ui import Worker, _release_thread
        ref, work = self.state.ref, bundle_work_dir()
        thread = Worker(lambda cancel, event: verify_bundle(ref, mode='full', cancel=cancel, event=event,
                                                            work_dir=work))
        _THREADS.add(thread)
        thread.event_ready.connect(self.dialog.diagnostics.setPlainText)
        thread.result_ready.connect(self._done)
        thread.failed.connect(self._failed)
        thread.finished.connect(self._finished)
        thread.finished.connect(lambda t=thread: _release_thread(_THREADS, t))
        self.dialog.finished.connect(lambda _code=0, t=thread: t.cancel.set())
        self._thread = thread
        self.dialog._busy_kind = 'bundle'
        self.dialog.check.setEnabled(False)
        self.dialog.install.setEnabled(False)
        self.dialog.diagnostics.setPlainText('Verifying bundle files...')
        self.refresh()
        thread.start()

    def cancel(self) -> None:
        if self._thread is not None:
            self._thread.cancel.set()
            self.cancel_button.setEnabled(False)
            self.dialog.diagnostics.setPlainText('Cancelling bundle verification after the current chunk...')

    def _done(self, report) -> None:
        if not isValid(self.dialog):
            return
        if report.ok:
            self.dialog.diagnostics.setPlainText(
                f'Bundled runtime {self.state.runtime_id}: full verification ok '
                f'({report.checked:,} files, {report.bytes:,} bytes). Integrity only; not publisher authenticity.')
            return
        self.status.setText(problem_text(report.problems[0].code))
        self.dialog.diagnostics.setPlainText('\n'.join([problem_text(report.problems[0].code)]
                                                       + [str(p) for p in report.problems]))

    def _failed(self, message: str) -> None:
        if not isValid(self.dialog):
            return
        cancelled = 'PT-CANCEL' in message
        self.dialog.diagnostics.setPlainText('Bundle verification cancelled. Settings are unchanged.'
                                             if cancelled else f'Bundle verification failed: {message}')

    def _finished(self) -> None:
        self._thread = None
        if not isValid(self.dialog):
            return
        self.dialog._busy_kind = None
        self.dialog.check.setEnabled(True)
        self.dialog.install.setEnabled(True)
        self.dialog.find.setEnabled(self.dialog._discovery is None)
        self.refresh()
