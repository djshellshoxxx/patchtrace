"""Real offline create cancellation, before mutation and after a committed project.

Only thread scheduling is controlled. Advisory parsing, PE inspection, workspace
transitions, project creation and TaskRunner result delivery use production code.
"""
from __future__ import annotations

import threading
from dataclasses import replace

import kbc_helpers as h
import pytest
from kbc_k3_support import BASELINE, FixedClock, write_pair

from patchtrace.kbcorrelation import service as kb_service
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.kbcorrelation.investigation_service import execute_request
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.service import ProjectService


def _settled(qtbot, dialog):
    qtbot.waitUntil(lambda: dialog._pending is None, timeout=10000)


def _ready(qtbot, dialog, tmp_path):
    dialog.fields['source'].setText(str(h.fixture_path(BASELINE)))
    dialog.buttons['import'].click()
    _settled(qtbot, dialog)
    dialog.fields['lead'].setText('CVE-2099-20001')
    dialog.buttons['search'].click()
    _settled(qtbot, dialog)
    scope = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
    dialog.scope.setCurrentIndex(scope)
    _settled(qtbot, dialog)
    older, newer = write_pair(tmp_path / 'inputs')
    for key, value in (('older', older), ('newer', newer), ('destination', tmp_path / 'new-project')):
        dialog.fields[key].setText(str(value))
    dialog.buttons['preview'].click()
    _settled(qtbot, dialog)
    assert dialog._preview is not None, dialog.status.full_text()


@pytest.mark.parametrize('stage', ['queued', 'second-inspection', 'precommit', 'committed'])
@pytest.mark.parametrize('action', ['cancel', 'close'])
def test_create_cancel_reaches_worker_and_retains_committed_path(qtbot, tmp_path, monkeypatch, stage, action):
    entered, release, creating = threading.Event(), threading.Event(), threading.Event()
    opened, notices, outcomes, inspections = [], [], [], []

    def pause():
        entered.set()
        if not release.wait(10):
            raise RuntimeError('test did not release the create worker')

    local_plan = kb_service.local_plan

    def plan(pair):
        result = local_plan(pair)
        if creating.is_set() and stage == 'precommit':
            pause()
        return result

    monkeypatch.setattr(kb_service, 'local_plan', plan)

    def factory(path):
        service = wiring.build_service(path, clock=FixedClock())
        inspect = service.env.inspect

        def inspected(binary):
            result = inspect(binary)
            if creating.is_set():
                inspections.append(binary)
                if stage == 'second-inspection' and len(inspections) == 2:
                    pause()
            return result

        return wiring.KbService(service.root, replace(service.env, inspect=inspected))

    def execute(request, token):
        if request.operation == 'create':
            creating.set()
            if stage == 'queued':
                pause()
        outcome = execute_request(request, token, service_factory=factory)
        if request.operation == 'create':
            outcomes.append(outcome)
            if stage == 'committed':
                pause()
        return outcome

    parent = ProjectService.sample(tmp_path / 'parent')
    parent_database = parent.root / 'project.sqlite3'
    original = parent_database.read_bytes()
    workspace, destination = tmp_path / 'workspace', tmp_path / 'new-project'
    dialog = InvestigationDialog(workspace=workspace, current_project=parent.root, execute=execute,
                                 on_created=opened.append, notice=notices.append)
    qtbot.addWidget(dialog)
    try:
        _ready(qtbot, dialog, tmp_path)
        investigation = dialog._investigation_id
        with WorkspaceStore(workspace, create=False) as store:
            revision = store.current_revision(investigation).revision
        dialog.buttons['create'].click()
        qtbot.waitUntil(entered.is_set, timeout=10000)
        dialog.buttons[action].click()
        assert dialog._pending is not None  # Await acknowledgement; do not discard the create outcome.
        release.set()
        _settled(qtbot, dialog)
        assert opened == []
        assert dialog._closed is (action == 'close')
        assert parent_database.read_bytes() == original
        assert len(outcomes) == 1
        if stage == 'committed':
            assert outcomes[0].success, outcomes[0].text
            assert (destination / 'project.sqlite3').is_file()
            assert notices and str(destination.resolve()) in notices[0]
            assert 'retained without opening' in notices[0]
            reopened = ProjectService.open(destination)
            reopened.close()
        else:
            assert not outcomes[0].success, 'cancelled precommit create still committed a project'
            assert outcomes[0].error_code == 'PT-KBC-CANCEL'
            assert not destination.exists()
            with WorkspaceStore(workspace, create=False) as store:
                assert store.current_revision(investigation).revision == revision
            assert 'PT-KBC-CANCEL' in dialog.status.full_text()
    finally:
        release.set()
        _settled(qtbot, dialog)
        dialog.reject()
        parent.close()
