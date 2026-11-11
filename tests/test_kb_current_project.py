"""Current project inputs are an explicit offline starting point, never CVE evidence."""
from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QSettings

from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def test_host_exposes_explicit_current_input_action(qtbot, tmp_path):
    window = MainWindow(settings=QSettings(str(tmp_path / 'current.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    try:
        assert dialog.buttons['use_current'].isEnabled()
        assert window.service is previous
        dialog.buttons['use_current'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog._input_origin is not None
        dialog.fields['older'].setText(dialog.fields['older'].text() + '.edited')
        assert dialog._input_origin is None and dialog._preview is None
    finally:
        dialog.reject()
        window.close()


def test_real_current_project_journey_requires_scope_confirmation_and_exact_preview(qtbot, tmp_path):
    from functools import partial

    import kbc_helpers as h
    from kbc_k3_support import BASELINE, FixedClock

    from patchtrace.kbcorrelation import wiring
    from patchtrace.kbcorrelation.investigation_service import execute_request

    window = MainWindow(settings=QSettings(str(tmp_path / 'journey.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    before = (previous.root / 'project.sqlite3').read_bytes()
    expected = {a.side: a.sha256 for a in previous.project.artifacts}
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    dialog._execute = partial(execute_request, service_factory=lambda root: wiring.build_service(root, clock=FixedClock()))
    dialog.fields['workspace'].setText(str(tmp_path / 'workspace'))
    try:
        dialog.buttons['use_current'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog._input_origin is not None, dialog.status.text()
        assert 'preview only' in dialog.details.toPlainText()
        assert previous.project.id in dialog.details.toPlainText()
        assert not dialog.buttons['create'].isEnabled()
        assert not dialog.same_component.isChecked()
        assert window.service is previous
        assert not (tmp_path / 'workspace').exists()  # verification needs no workspace/database
        dialog.fields['source'].setText(str(h.fixture_path(BASELINE)))
        dialog.buttons['import'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.fields['lead'].setText('CVE-2099-20001')
        dialog.buttons['search'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog.scope.currentData() is None
        index = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(index)
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.fields['destination'].setText(str(tmp_path / 'new-comparison'))
        dialog.buttons['preview'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog._preview is None  # hash-named copies need explicit same-component consent
        dialog.same_component.setChecked(True)
        dialog.buttons['preview'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog._preview is not None, dialog.status.text()
        preview = dialog._preview[1].data
        assert preview['pair']['older_sha256'] == expected['older']
        assert preview['pair']['newer_sha256'] == expected['newer']
        assert preview['input_origin']['project_id'] == previous.project.id
        assert 'preview only' in dialog.details.toPlainText()
        assert window.service is previous
        assert (previous.root / 'project.sqlite3').read_bytes() == before
        dialog.buttons['create'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog._closed
        assert window.service is not previous
        assert window.service.root == (tmp_path / 'new-comparison').resolve()
        assert (previous.root / 'project.sqlite3').read_bytes() == before
        assert {a.side: a.sha256 for a in window.service.project.artifacts} == expected
    finally:
        dialog.reject()
        window.close()


def captured(service):
    from patchtrace.kbcorrelation.investigation_service import CurrentProjectInputs

    artifacts = {a.side: a for a in service.project.artifacts}
    return CurrentProjectInputs(service.project.id, service.project.revision, service.root,
                                artifacts['older'].model_dump_json(), artifacts['newer'].model_dump_json())


def test_snapshot_decoder_refuses_duplicate_artifact_keys(tmp_path):
    import threading
    from dataclasses import replace

    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request

    previous = ProjectService.sample(tmp_path / 'previous')
    try:
        snapshot = captured(previous)
        snapshot = replace(snapshot, older_json=snapshot.older_json.replace('{', '{"side":"older",', 1))
        result = execute_request(InvestigationRequest('current_inputs', tmp_path / 'ws', current_inputs=snapshot),
                                 threading.Event())
        assert not result.success and 'duplicate key' in result.text
        assert not (tmp_path / 'ws').exists()
        previous.store._check_open()
    finally:
        previous.close()


@pytest.mark.parametrize('failure', ['tampered', 'missing'])
def test_current_copy_failure_keeps_previous_service_and_workspace_untouched(qtbot, tmp_path, failure):
    from patchtrace.sample import synthetic_pe

    window = MainWindow(settings=QSettings(str(tmp_path / 'failure.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    dialog.fields['workspace'].setText(str(tmp_path / 'ws'))
    artifact = previous.root / previous.project.artifacts[0].relative_path
    artifact.chmod(0o600)
    if failure == 'missing':
        artifact.unlink()
    else:
        artifact.write_bytes(synthetic_pe(2))
    try:
        dialog.buttons['use_current'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert 'PT-KBC-VERIFY' in dialog.status.text()
        assert not dialog.fields['older'].text()
        assert not dialog.buttons['create'].isEnabled()
        assert window.service is previous
        previous.store._check_open()
        assert not (tmp_path / 'ws').exists()
    finally:
        dialog.reject()
        window.close()


@pytest.mark.parametrize('change', ['switch', 'revision', 'artifact'])
def test_late_current_input_result_is_rejected_after_project_changes(qtbot, tmp_path, change):
    import threading

    from patchtrace.kbcorrelation.investigation_service import execute_request

    window = MainWindow(settings=QSettings(str(tmp_path / 'late.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    started, release = threading.Event(), threading.Event()

    def execute(request, token):
        result = execute_request(request, token)
        started.set()
        assert release.wait(5)
        return result

    dialog._execute = execute
    try:
        dialog.buttons['use_current'].click()
        qtbot.waitUntil(started.is_set)
        assert window.service is previous
        if change == 'switch':
            current = ProjectService.sample(tmp_path / 'current')
            window.set_service(current)
        elif change == 'revision':
            previous.project.revision += 1
        else:
            previous.project.artifacts[0].name = 'changed.exe'
        release.set()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert 'PT-KBC-STALE' in dialog.status.text()
        assert not dialog.fields['older'].text()
        assert dialog._preview is None
        assert not dialog.buttons['use_current'].isEnabled()
        assert window.service is (current if change == 'switch' else previous)
    finally:
        release.set()
        dialog.reject()
        window.close()


def test_current_pair_hash_change_between_verification_and_inspection_refuses_commit(tmp_path, monkeypatch):
    import threading
    from dataclasses import replace

    from kbc_k3_support import FixedClock
    from test_kb_investigation_service import ready

    from patchtrace.kbcorrelation import wiring
    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
    from patchtrace.kbcorrelation.store import WorkspaceStore
    from patchtrace.sample import synthetic_pe

    ws, inv, scope, _, _ = ready(tmp_path)
    previous = ProjectService.sample(tmp_path / 'previous')
    snapshot = captured(previous)
    def factory(root):
        return wiring.build_service(root, clock=FixedClock())
    request = InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope,
                                   current_inputs=snapshot, confirm_same_component=True,
                                   older=previous.root / previous.project.artifacts[0].relative_path,
                                   newer=previous.root / previous.project.artifacts[1].relative_path)
    try:
        preview = execute_request(request, threading.Event(), service_factory=factory)
        assert preview.success, preview.text
        with WorkspaceStore(ws) as store:
            before = store.current_revision(inv).revision
        actual = wiring.inspect_local_file

        def changed(path, **kwargs):
            Path(path).chmod(0o600)
            Path(path).write_bytes(synthetic_pe(2))
            return actual(path, **kwargs)

        monkeypatch.setattr(wiring, 'inspect_local_file', changed)
        destination = tmp_path / 'not-created'
        create = replace(request, operation='create', destination=destination,
                         expected_pair_id=preview.data['pair']['pair_id'],
                         expected_revision=preview.data['investigation_revision'])
        result = execute_request(create, threading.Event(), service_factory=factory)
        assert not result.success and result.error_code == 'PT-KBC-STALE'
        assert not destination.exists()
        with WorkspaceStore(ws) as store:
            assert store.current_revision(inv).revision == before
        previous.store._check_open()
    finally:
        previous.close()


def test_basename_hint_is_optional_and_cannot_change_inspected_bytes(tmp_path):
    from kbc_k3_support import write_pair

    from patchtrace.kbcorrelation.wiring import inspect_local_file

    older, _ = write_pair(tmp_path)
    ordinary = inspect_local_file(str(older))
    hinted = inspect_local_file(str(older), basename='manual-hint.dll')
    assert ordinary.basename == 'exampledrv.sys'
    assert hinted.basename == 'manual-hint.dll'
    assert (ordinary.sha256, ordinary.size, ordinary.machine) == (hinted.sha256, hinted.size, hinted.machine)


def test_late_current_project_create_retains_path_after_switch(qtbot, tmp_path):
    import threading
    from functools import partial

    from kbc_k3_support import FixedClock
    from test_kb_investigation_service import ready

    from patchtrace.kbcorrelation import wiring
    from patchtrace.kbcorrelation.investigation_service import execute_request

    ws, inv, scope, _, _ = ready(tmp_path)
    window = MainWindow(settings=QSettings(str(tmp_path / 'late-create.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    dialog = window.investigation_dialog()
    qtbot.addWidget(dialog)
    actual = partial(execute_request, service_factory=lambda root: wiring.build_service(root, clock=FixedClock()))
    created, release = threading.Event(), threading.Event()
    destination = tmp_path / 'retained-comparison'

    def execute(request, token):
        result = actual(request, token)
        if request.operation == 'create':
            assert result.success, result.text
            created.set()
            assert release.wait(5)
        return result

    dialog._execute = execute
    dialog.fields['workspace'].setText(str(ws))
    try:
        dialog.buttons['use_current'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog._investigation_id = inv
        scopes = wiring.build_service(ws, clock=FixedClock()).search('CVE-2099-20001', product=scope,
                                                                   investigation=inv).result['scopes']
        dialog._set_scopes(scopes, scope)
        dialog.same_component.setChecked(True)
        dialog.fields['destination'].setText(str(destination))
        dialog.buttons['preview'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog._preview is not None, dialog.status.text()
        dialog.buttons['create'].click()
        qtbot.waitUntil(created.is_set)
        assert window.service is previous
        current = ProjectService.sample(tmp_path / 'current')
        window.set_service(current)
        release.set()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert window.service is current
        assert 'retained without opening' in dialog.status.text()
        assert str(destination) in window.logs.toPlainText()
        retained = ProjectService.open(destination)
        retained.close()  # no lock leaked by late completion
    finally:
        release.set()
        dialog.reject()
        window.close()


@pytest.mark.parametrize('newer_name', ['same.exe', 'SAME.EXE', 'different.exe'])
def test_identical_copy_handles_same_canonical_hint_or_refuses_conflicting_names(tmp_path, newer_name):
    import threading

    from kbc_k3_support import FixedClock
    from test_kb_investigation_service import ready

    from patchtrace.kbcorrelation import wiring
    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
    from patchtrace.sample import synthetic_pe

    ws, inv, scope, _, _ = ready(tmp_path)
    old, new = tmp_path / 'a' / 'same.exe', tmp_path / 'b' / newer_name
    old.parent.mkdir()
    new.parent.mkdir()
    old.write_bytes(synthetic_pe(0))
    new.write_bytes(synthetic_pe(0))
    previous = ProjectService.create(old, new, 'same bytes', tmp_path / 'previous')
    try:
        snapshot = captured(previous)
        request = InvestigationRequest('current_inputs', ws, current_inputs=snapshot)
        result = execute_request(request, threading.Event())
        if newer_name == 'different.exe':
            assert not result.success and result.error_code == 'PT-KBC-UNSUPPORTED'
        else:
            assert result.success, result.text
            assert result.data['older'] == result.data['newer']
            preview = execute_request(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope,
                                                           current_inputs=snapshot, confirm_same_component=True,
                                                           older=Path(result.data['older']),
                                                           newer=Path(result.data['newer'])), threading.Event(),
                                      service_factory=lambda root: wiring.build_service(root, clock=FixedClock()))
            assert not preview.success
            assert 'IDENTICAL_CONTENT' in preview.data['pair']['reason_codes']
            assert preview.data['pair']['older_sha256'] == preview.data['pair']['newer_sha256']
        previous.store._check_open()
    finally:
        previous.close()


def test_derived_hash_filename_is_explicitly_unsupported(tmp_path):
    import threading

    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request

    previous = ProjectService.sample(tmp_path / 'previous')
    try:
        previous.project.artifacts[0].name = previous.project.artifacts[0].sha256 + '.bin'
        result = execute_request(InvestigationRequest('current_inputs', tmp_path / 'ws',
                                                     current_inputs=captured(previous)), threading.Event())
        assert not result.success and result.error_code == 'PT-KBC-UNSUPPORTED'
        assert not (tmp_path / 'ws').exists()
        previous.store._check_open()
    finally:
        previous.close()


@pytest.mark.parametrize('raw', ['x' * 16385, 'é' * 8193], ids=['character-cap', 'utf8-byte-cap'])
def test_snapshot_record_limits_precede_decoding_and_file_access(tmp_path, raw):
    import threading

    from patchtrace.kbcorrelation.investigation_service import (
        CurrentProjectInputs,
        InvestigationRequest,
        execute_request,
    )

    snapshot = CurrentProjectInputs('captured-project', 1, tmp_path / 'missing', raw, '{}')
    result = execute_request(InvestigationRequest('current_inputs', tmp_path / 'ws', current_inputs=snapshot),
                             threading.Event())
    assert not result.success and result.error_code == 'PT-KBC-INPUT'
    assert 'limit' in result.text
    assert not (tmp_path / 'ws').exists()
