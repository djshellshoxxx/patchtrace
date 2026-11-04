"""RB-05 (automated part): one analyst journey through the REAL MainWindow and panel host.

EVIDENCE CLASS: automated OFFSCREEN evidence with a FAKE backend. The comparison backend (``patchtrace.ui.run_comparison``)
is replaced by a stub that returns a recorded-shape Ghidriff JSON (tests/fixtures/journey/ghidriff.recorded.json).
This is NOT native Windows acceptance and NOT live evidence: no Ghidra, Ghidriff, network or real Microsoft binary
is involved, and no target is ever executed (the PE files are the synthetic ``patchtrace.sample.synthetic_pe``).

Journey: no project (empty states) -> New project dialog -> offline KB investigation (import, search, product,
preview, cancel once, preview, create) -> adopted project -> failed then successful comparison through the fake
runner -> Unified and Evidence panels -> keyboard export to tmp_path -> report asserts. Waits use qtbot.waitUntil.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from functools import partial
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k3_support import BASELINE, FixedClock, write_pair
from PySide6.QtCore import QSettings
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog
from qt_support import join_gui_threads  # noqa: F401  (autouse fixture: no worker thread may survive)

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.models import AnalysisRun, uid
from patchtrace.sample import synthetic_pe
from patchtrace.ui import ExportDialog, MainWindow, NewProjectDialog

FIXTURE = Path(__file__).parent / 'fixtures' / 'journey' / 'ghidriff.recorded.json'
ABSOLUTE = re.compile(r'(?<![\w:/<])/(?:home|tmp|Users|var|root|mnt)/|(?i:\b[a-z]:[\\/])')
TIMEOUT = 15000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key(window, sequence):
    """Real shortcut delivery to the window (the keyboard path), not a direct action.trigger()."""
    window.activateWindow()
    QTest.qWaitForWindowActive(window, 5000)
    QTest.keySequence(window, sequence)


def idle(window):
    return window.worker is None


@pytest.fixture
def journey(qtbot, tmp_path, monkeypatch):
    # The KB workspace clock is fixed so advisory coverage never goes stale; everything stays under tmp_path.
    monkeypatch.setattr(wiring, 'build_service', partial(wiring.build_service, clock=FixedClock()))
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    window = MainWindow(None, settings, tmp_path / 'profiles')
    qtbot.addWidget(window)
    window.show()
    qtbot.waitExposed(window)
    window.activateWindow()
    qtbot.waitUntil(window.isActiveWindow, timeout=TIMEOUT)
    yield window
    if window.worker:
        window.cancel_job()
        qtbot.waitUntil(lambda: window.worker is None, timeout=TIMEOUT)
    window.close()
    if window.service:
        window.service.close()
        window.service = None


def unified_state(window):
    controller = window.panels.controller('unified')  # None until the lazy panel is built
    return controller.panel.model.vm.state if controller is not None else None


def evidence_kind(window):
    controller = window.panels.controller('evidence')
    return controller.panel.state_view.kind if controller is not None else None


def test_analyst_journey_offscreen_fake_backend(journey, qtbot, tmp_path, monkeypatch):
    window = journey
    old_bytes, new_bytes = synthetic_pe(0), synthetic_pe(1)
    old_sha, new_sha = sha(old_bytes), sha(new_bytes)
    fixture = json.loads(FIXTURE.read_text(encoding='utf-8'))
    assert fixture['old_meta']['Executable SHA256'] == old_sha and fixture['new_meta']['Executable SHA256'] == new_sha

    # 0. No project: every panel says so in words; none of them shows a zero-result state.
    assert window.service is None
    key(window, 'Ctrl+Shift+U')
    key(window, 'Ctrl+Shift+E')
    assert window.panels.is_shown('unified') and window.panels.is_shown('evidence')
    qtbot.waitUntil(lambda: unified_state(window) == 'U0', timeout=TIMEOUT)
    assert evidence_kind(window) == 'no-project'
    assert 'Open a project' in window.panels.controller('evidence').panel.state_view.status_label().full_text()

    # 1. New project from two synthetic PE files through the real wizard (dialog accepted programmatically).
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    (inputs / 'older.dll').write_bytes(old_bytes)
    (inputs / 'newer.dll').write_bytes(new_bytes)

    def fill_and_accept(dialog_self):
        dialog_self.older.setText(str(inputs / 'older.dll'))
        dialog_self.newer.setText(str(inputs / 'newer.dll'))
        dialog_self.root.setText(str(tmp_path / 'project-a'))
        dialog_self.accept()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(NewProjectDialog, 'exec', fill_and_accept)
    key(window, 'Ctrl+N')
    qtbot.waitUntil(lambda: idle(window) and window.service is not None, timeout=TIMEOUT)
    assert window.service.root == (tmp_path / 'project-a')
    assert {a.sha256 for a in window.project.artifacts} == {old_sha, new_sha}
    assert window.project.matches == []  # a project with no analysis: empty, not "no findings"
    qtbot.waitUntil(lambda: unified_state(window) == 'U1', timeout=TIMEOUT)
    assert 'No unified result yet' in window.panels.controller('unified').panel.status.full_text()

    # 2. Offline KB investigation through the menu action: import, search (unknown first), product, preview.
    created = {}
    original_factory = window.panels.investigation_dialog

    def factory():
        dialog = original_factory()
        created['dialog'] = dialog
        return dialog

    monkeypatch.setattr(window, 'investigation_dialog', factory)
    monkeypatch.setattr(InvestigationDialog, 'exec', lambda self: self.show() or 0)
    window.kb_investigation_action.trigger()
    dialog = created['dialog']
    assert dialog.isVisible()

    def settled():
        qtbot.waitUntil(lambda: dialog._pending is None, timeout=TIMEOUT)

    dialog.fields['workspace'].setText(str(tmp_path / 'kb-workspace'))
    dialog.fields['source'].setText(str(h.fixture_path(BASELINE)))
    dialog.buttons['import'].click()
    settled()
    assert 'imported' in dialog.status.full_text()
    dialog.fields['lead'].setText('KB0000000')  # unknown identifier: a not-found state, distinct from a result
    dialog.buttons['search'].click()
    settled()
    unknown_status = dialog.status.full_text()
    assert dialog.scope.count() == 1 and not dialog.buttons['preview'].isEnabled()
    dialog.fields['lead'].setText('CVE-2099-20001')
    dialog.buttons['search'].click()
    settled()
    assert dialog.scope.count() > 1 and dialog.status.full_text() != unknown_status
    dialog.scope.setCurrentIndex(next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i)))
    settled()
    kb_old, kb_new = write_pair(tmp_path / 'kb-inputs')
    destination = tmp_path / 'project-b'
    for name, value in (('older', kb_old), ('newer', kb_new), ('destination', destination)):
        dialog.fields[name].setText(str(value))

    # 3. Cancellation exercised once: cancel an in-flight preview; its result must be dropped.
    dialog.buttons['preview'].click()
    assert dialog.buttons['cancel'].isEnabled()
    dialog.buttons['cancel'].click()
    assert dialog._pending is None and not dialog.buttons['create'].isEnabled()
    assert dialog.status.full_text().startswith('Cancelled')
    assert not destination.exists()
    QTest.qWait(0)  # let any queued late result be delivered and dropped (generation check)
    assert dialog._preview is None and not dialog.buttons['create'].isEnabled()

    # 4. Preview again, read the hashes, create; the main window adopts the NEW project only.
    dialog.buttons['preview'].click()
    settled()
    assert dialog._preview is not None, dialog.status.full_text()
    shown = dialog.details.toPlainText()
    assert f'Older SHA-256: {old_sha}' in shown and f'Newer SHA-256: {new_sha}' in shown
    project_a_bytes = (tmp_path / 'project-a' / 'project.sqlite3').read_bytes()
    assert dialog.buttons['create'].isEnabled()
    dialog.buttons['create'].click()
    qtbot.waitUntil(lambda: window.service is not None and window.service.root == destination.resolve(),
                    timeout=TIMEOUT)
    qtbot.waitUntil(lambda: idle(window), timeout=TIMEOUT)
    assert (tmp_path / 'project-a' / 'project.sqlite3').read_bytes() == project_a_bytes
    assert {a.sha256 for a in window.project.artifacts} == {old_sha, new_sha}

    # 5. Comparison through the FAKE backend runner. First a failed run: an error, distinct from zero matches.
    window.settings.setValue('backend/python', 'fake-python-not-executed')
    window.settings.setValue('backend/ghidra', 'fake-ghidra-not-installed')
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    calls = []

    def stub_runner(failing, config, project, root, cancel, event):
        calls.append(failing)
        run_id = uid()
        raw = Path(root) / 'runs' / run_id / 'raw' / 'ghidriff.json'
        raw.parent.mkdir(parents=True)
        if failing:
            return raw, AnalysisRun(id=run_id, status='failed', error='PT-BACKEND: fake backend unavailable')
        shutil.copyfile(FIXTURE, raw)
        return raw, AnalysisRun(id=run_id, status='completed', backend='journey-fake', backend_version='0',
                                raw_path=raw.relative_to(root).as_posix(), raw_sha256=sha(raw.read_bytes()))

    monkeypatch.setattr('patchtrace.ui.run_comparison', partial(stub_runner, True))
    key(window, 'F5')
    qtbot.waitUntil(lambda: bool(calls) and idle(window), timeout=TIMEOUT)
    assert errors and 'PT-BACKEND' in errors[0]
    assert window.project.runs[-1].status == 'failed' and window.project.matches == []

    monkeypatch.setattr('patchtrace.ui.run_comparison', partial(stub_runner, False))
    key(window, 'F5')
    qtbot.waitUntil(lambda: bool(window.project.matches) and idle(window), timeout=TIMEOUT)
    assert len(errors) == 1 and window.project.runs[-1].status == 'completed'
    assert {m.category for m in window.project.matches} >= {'added', 'removed', 'modified'}
    match = next(m for m in window.project.matches if m.category == 'modified' and m.newer[0].name == 'read_item')
    window.service.annotate(match.id, r'Reviewed against C:\Users\analyst\src\old.c and /home/analyst/src/old.c')
    window.refresh()

    # 6. Unified and Evidence panels over the new run: idle/empty-with-words, never a zero-result state.
    assert window.panels.is_shown('evidence') and window.panels.is_shown('unified')
    qtbot.waitUntil(lambda: evidence_kind(window) != 'no-project', timeout=TIMEOUT)
    kinds = {evidence_kind(window)}
    assert 'ready' not in kinds and window.panels.controller('evidence').panel.state_view.status_label().full_text()
    qtbot.waitUntil(lambda: unified_state(window) == 'U1', timeout=TIMEOUT)
    assert window.panels.controller('unified').panel.model.rowCount() == 0  # no result is not a zero-row result
    assert unified_state(window) not in {'U3', 'U4'}

    # 7. Export through the service-owned route (Ctrl+E -> ExportDialog -> ProjectService.export_report).
    report = tmp_path / 'out' / 'report.md'

    def write_report(dialog_self):
        dialog_self.destination.setText(str(report))
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(ExportDialog, 'exec', write_report)
    key(window, 'Ctrl+E')
    qtbot.waitUntil(report.is_file, timeout=TIMEOUT)
    text = report.read_text(encoding='utf-8').replace('\\', '')  # the md renderer backslash-escapes punctuation
    assert old_sha in text and new_sha in text
    assert '[PATH REDACTED]' in text  # the analyst note carried absolute paths
    assert not ABSOLUTE.search(text)
    for private in (str(tmp_path), str(tmp_path.as_posix()), 'analyst/src', 'analyst\\src'):
        assert private not in text
    assert str(report) in window.statusBar().currentMessage()
