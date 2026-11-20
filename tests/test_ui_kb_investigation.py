"""Offline dialog journeys and late-result handling; no target execution or live providers."""
from __future__ import annotations

import threading
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import kbc_helpers as h
import pytest
import pytestqt.exceptions
from kbc_k3_support import BASELINE, FixedClock, write_pair
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLineEdit, QPushButton

from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.kbcorrelation.investigation_service import InvestigationResult, execute_request
from patchtrace.service import ProjectService


def settled(qtbot, dialog):
    try:
        qtbot.waitUntil(lambda: dialog._pending is None, timeout=10000)
    except pytestqt.exceptions.TimeoutError as exc:
        # The native Windows Qt gate has timed out here on real project creation.
        # Never emit GUI status, file paths or source/advisory strings to CI.
        operation = getattr(dialog._pending, 'operation', None)
        operations = {'import', 'search', 'browse_products', 'current_inputs', 'plan_sources',
                      'sync_sources', 'plan_metadata', 'refresh_metadata', 'candidate_pairs',
                      'candidate_preview', 'preview', 'create'}
        operation = operation if isinstance(operation, str) and operation in operations else 'unknown'
        try:
            worker_busy = dialog.tasks.busy(dialog._channel)
        except Exception:
            worker_busy = 'unknown'  # Diagnostics must not mask the original timeout.
        raise AssertionError(
            f'Investigation dialog did not settle: operation={operation}, worker_busy={worker_busy}, '
            f'preview={dialog._preview is not None}, closed={dialog._closed}, generation={dialog._generation}, '
            f'cancel_create={dialog._cancel_create}, close_after_create={dialog._close_after_create}'
        ) from exc


@pytest.mark.parametrize('lead', ['CVE-2099-20001', 'KB5099001'])
def test_real_offline_dialog_journey_creates_and_opens_only_new_project(qtbot, tmp_path, lead):
    opened = []
    parent_project = ProjectService.sample(tmp_path / 'parent')
    original = (parent_project.root / 'project.sqlite3').read_bytes()
    execute = partial(execute_request, service_factory=lambda path: wiring.build_service(path, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', current_project=parent_project.root,
                                 execute=execute, on_created=opened.append)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['source'].setText(str(h.fixture_path(BASELINE)))
        dialog.buttons['import'].click()
        settled(qtbot, dialog)
        dialog.fields['lead'].setText(lead)
        dialog.buttons['search'].click()
        settled(qtbot, dialog)
        assert dialog.scope.currentData() is None
        assert not dialog.buttons['preview'].isEnabled()
        index = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(index)
        settled(qtbot, dialog)
        old, new = write_pair(tmp_path / 'inputs')
        for key, value in (('older', old), ('newer', new), ('destination', tmp_path / 'new-project')):
            dialog.fields[key].setText(str(value))
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is not None, dialog.status.text()
        assert 'Older SHA-256:' in dialog.details.toPlainText()
        assert dialog.buttons['create'].isEnabled()
        dialog.buttons['create'].click()
        settled(qtbot, dialog)
        assert opened == [(tmp_path / 'new-project').resolve()]
        assert (parent_project.root / 'project.sqlite3').read_bytes() == original
        service = ProjectService.open(opened[0])
        service.close()
    finally:
        parent_project.close()
        dialog.reject()


def test_close_drops_late_search_result_and_keeps_plain_text(qtbot, tmp_path):
    gate, started = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)
    def execute(request, token):
        started.set()
        gate.wait(5)
        return InvestigationResult('search', '<b>untrusted</b>', {'investigation_id': 'late', 'scopes': []})
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', tasks=runner, execute=execute)
    qtbot.addWidget(dialog)
    dialog.fields['lead'].setText('CVE-2099-20001')
    dialog.buttons['search'].click()
    qtbot.waitUntil(started.is_set)
    dialog.reject()
    gate.set()
    qtbot.waitUntil(lambda: not runner.busy())
    assert dialog._investigation_id is None
    assert dialog.status.textFormat() == Qt.TextFormat.PlainText
    runner.shutdown()


def seeded(qtbot, tmp_path, execute, **options):
    dialog = InvestigationDialog(workspace=tmp_path / 'ws', execute=execute, **options)
    qtbot.addWidget(dialog)
    dialog._investigation_id = 'inv'
    dialog.scope.blockSignals(True)
    dialog.scope.addItem('Product amd64', 'scope')
    dialog.scope.setCurrentIndex(1)
    dialog.scope.blockSignals(False)
    for key, value in (('older', 'old.sys'), ('newer', 'new.sys'), ('destination', tmp_path / 'new-project')):
        dialog.fields[key].setText(str(value))
    dialog._enable()
    dialog.buttons['preview'].click()
    settled(qtbot, dialog)
    return dialog


def preview_result():
    return InvestigationResult('preview', '<b>literal text</b>',
                               {'pair': {'pair_id': 'pair', 'older_sha256': 'a' * 64, 'newer_sha256': 'b' * 64},
                                'investigation_revision': 4})


def test_any_edited_input_or_confirmation_invalidates_preview(qtbot, tmp_path):
    dialog = seeded(qtbot, tmp_path, lambda request, token: preview_result())
    assert dialog.buttons['create'].isEnabled()
    assert '<b>literal text</b>' in dialog.details.toPlainText()
    dialog.same_component.setChecked(True)
    assert not dialog.buttons['create'].isEnabled()
    dialog.buttons['preview'].click()
    settled(qtbot, dialog)
    dialog.fields['newer'].setText('other.sys')
    assert not dialog.buttons['create'].isEnabled()
    dialog.reject()


def test_cancel_during_create_retains_result_and_does_not_adopt(qtbot, tmp_path):
    gate, started, opened, notices, requests = threading.Event(), threading.Event(), [], [], []
    def execute(request, token):
        requests.append(request)
        if request.operation == 'preview':
            return preview_result()
        started.set()
        gate.wait(5)
        return InvestigationResult('create', 'done', project_path=Path(request.destination))
    dialog = seeded(qtbot, tmp_path, execute, on_created=opened.append, notice=notices.append)
    dialog.buttons['create'].click()
    qtbot.waitUntil(started.is_set)
    dialog.reject()
    assert not dialog._closed
    gate.set()
    settled(qtbot, dialog)
    assert opened == []
    assert notices and str(tmp_path / 'new-project') in notices[0]
    assert requests[-1].expected_pair_id == 'pair' and requests[-1].expected_revision == 4
    assert dialog._closed


def test_every_interactive_control_has_accessible_name_and_tooltip(qtbot, tmp_path):
    dialog = InvestigationDialog(workspace=tmp_path)
    qtbot.addWidget(dialog)
    for widget in [*dialog.findChildren(QLineEdit), *dialog.findChildren(QPushButton), dialog.scope,
                   dialog.same_component]:
        assert widget.accessibleName()
        assert widget.toolTip()
    dialog.reject()


def test_partial_attach_is_reported_as_retained_and_never_adopted(qtbot, tmp_path):
    opened, notices = [], []
    def execute(request, token):
        if request.operation == 'preview':
            return preview_result()
        return InvestigationResult('create', 'Advisory context is pending; use repair.',
                                   project_path=Path(request.destination), success=False,
                                   error_code='PT-KBC-PARTIAL')
    dialog = seeded(qtbot, tmp_path, execute, on_created=opened.append, notice=notices.append)
    dialog.buttons['create'].click()
    settled(qtbot, dialog)
    assert opened == []
    assert 'context is pending' in dialog.status.text()
    assert notices and 'retained without opening' in notices[0]
    dialog.reject()


@pytest.mark.parametrize('unexpected', [False, True])
def test_close_during_failed_create_closes_after_completion(qtbot, tmp_path, unexpected):
    gate, started, opened, notices = threading.Event(), threading.Event(), [], []
    def execute(request, token):
        if request.operation == 'preview':
            return preview_result()
        started.set()
        gate.wait(5)
        if unexpected:
            raise RuntimeError('synthetic worker failure')
        return InvestigationResult('create', 'The local project could not be created.',
                                   success=False, error_code='PT-KBC-STORAGE')
    dialog = seeded(qtbot, tmp_path, execute, on_created=opened.append, notice=notices.append)
    dialog.buttons['create'].click()
    qtbot.waitUntil(started.is_set)
    dialog.reject()
    gate.set()
    settled(qtbot, dialog)
    assert dialog._closed
    assert opened == []
    assert notices and ('PT-GUI-TASK' in notices[0] if unexpected else 'PT-KBC-STORAGE' in notices[0])


def test_empty_workspace_does_not_fall_back_to_an_undisplayed_default(qtbot, tmp_path):
    requests = []
    dialog = InvestigationDialog(workspace=tmp_path, execute=lambda request, token: requests.append(request))
    qtbot.addWidget(dialog)
    dialog.fields['workspace'].clear()
    dialog.fields['lead'].setText('CVE-2099-20001')
    dialog.buttons['search'].click()
    assert requests == []
    assert 'Choose an advisory workspace' in dialog.status.text()
    dialog.reject()


@pytest.mark.parametrize('changed_selection', [False, True])
def test_host_retains_created_path_on_open_failure_or_changed_selection(qtbot, tmp_path, monkeypatch,
                                                                      changed_selection):
    from PySide6.QtCore import QSettings

    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest
    from patchtrace.ui import MainWindow

    window = MainWindow(settings=QSettings(str(tmp_path / 'host.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    candidate = ProjectService.sample(tmp_path / 'candidate')
    destination = candidate.root
    candidate.close()
    if changed_selection:
        current = ProjectService.sample(tmp_path / 'current')
        window.set_service(current)
    else:
        current = previous
        original = window.refresh

        def fail_incoming_render():
            original()
            if window.service is not previous:
                raise RuntimeError('synthetic incoming rendering failure')

        monkeypatch.setattr(window, 'refresh', fail_incoming_render)
    request = InvestigationRequest('create', tmp_path / 'ws', destination=destination)
    dialog._loaded(dialog._generation, request, InvestigationResult('create', 'created', project_path=destination))
    assert window.service is current
    assert current.store.load().id == current.project.id
    assert str(destination) in window.logs.toPlainText()
    with ProjectService.open(destination):
        pass  # failed adoption never leaves the retained project locked
    dialog.reject()
    window.close()


def test_real_host_adopts_created_project_on_gui_thread(qtbot, tmp_path):
    from PySide6.QtCore import QSettings

    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest
    from patchtrace.ui import MainWindow

    window = MainWindow(settings=QSettings(str(tmp_path / 'success.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    candidate = ProjectService.sample(tmp_path / 'candidate')
    destination, project_id = candidate.root, candidate.project.id
    candidate.close()
    request = InvestigationRequest('create', tmp_path / 'workspace', destination=destination)
    dialog._loaded(dialog._generation, request, InvestigationResult('create', 'created', project_path=destination))
    assert window.service.project.id == project_id
    assert window.settings.value('recent/project') == str(destination)
    assert dialog._closed
    with pytest.raises(ValueError, match='closed'):
        previous.store._check_open()
    window.close()


def test_settled_timeout_preserves_original_failure_and_bounded_worker_state():
    class TimeoutBot:
        def waitUntil(self, _predicate, *, timeout):
            assert timeout == 10000
            raise pytestqt.exceptions.TimeoutError('synthetic timeout')

    class Tasks:
        def busy(self, channel=None):
            assert channel == 'investigation-test'
            return True

    dialog = SimpleNamespace(
        _pending=SimpleNamespace(operation='create'), tasks=Tasks(), _channel='investigation-test',
        _closed=False, _preview=None, _generation=7, _cancel_create=False, _close_after_create=False,
        status=SimpleNamespace(text=lambda: 'PRIVATE PATH AND SOURCE SHOULD NOT LEAK'),
    )
    with pytest.raises(AssertionError) as raised:
        settled(TimeoutBot(), dialog)
    message = str(raised.value)
    assert isinstance(raised.value.__cause__, pytestqt.exceptions.TimeoutError)
    assert 'operation=create' in message
    assert 'worker_busy=True' in message
    assert 'generation=7' in message
    assert 'closed=False' in message
    assert 'PRIVATE PATH' not in message
    assert 'investigation-test' not in message


def test_settled_timeout_distinguishes_idle_worker_from_pending_gui_delivery():
    class TimeoutBot:
        def waitUntil(self, _predicate, *, timeout):
            assert timeout == 10000
            raise pytestqt.exceptions.TimeoutError('synthetic timeout')

    dialog = SimpleNamespace(
        _pending=SimpleNamespace(operation='create'),
        tasks=SimpleNamespace(busy=lambda channel: False), _channel='test',
        _closed=False, _preview=object(), _generation=9,
        _cancel_create=True, _close_after_create=True,
    )
    with pytest.raises(AssertionError, match='worker_busy=False') as raised:
        settled(TimeoutBot(), dialog)
    message = str(raised.value)
    assert 'preview=True' in message
    assert 'cancel_create=True' in message
    assert 'close_after_create=True' in message


def test_settled_success_keeps_existing_timeout_budget():
    class ReadyBot:
        def waitUntil(self, predicate, *, timeout):
            assert timeout == 10000
            assert predicate()

    settled(ReadyBot(), SimpleNamespace(_pending=None))


def test_settled_timeout_handles_unhashable_pending_operation():
    class TimeoutBot:
        def waitUntil(self, _predicate, *, timeout):
            assert timeout == 10000
            raise pytestqt.exceptions.TimeoutError('synthetic timeout')

    dialog = SimpleNamespace(
        _pending=SimpleNamespace(operation=['PRIVATE SOURCE']),
        tasks=SimpleNamespace(busy=lambda channel: True), _channel='test',
        _closed=False, _preview=None, _generation=3, _cancel_create=False,
        _close_after_create=False,
    )
    with pytest.raises(AssertionError, match='operation=unknown') as raised:
        settled(TimeoutBot(), dialog)
    assert isinstance(raised.value.__cause__, pytestqt.exceptions.TimeoutError)
    assert 'PRIVATE SOURCE' not in str(raised.value)
