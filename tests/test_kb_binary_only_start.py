"""Real offline binary-only desktop route; authored PE bytes are never executed."""
from dataclasses import replace
from functools import partial

import pytest
from kbc_k3_support import FixedClock, write_pair
from test_kb_investigation_service import run
from test_ui_kb_investigation import settled

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def manual_preview(tmp_path):
    old, new = write_pair(tmp_path / 'inputs')
    request = InvestigationRequest('preview', tmp_path / 'workspace', older=old, newer=new,
                                   manual_pair_start=True)
    result = run(request)
    assert result.success, result.text
    assert result.data['investigation_revision'] is None
    return request, result


def test_binary_only_real_dialog_create_reopen_and_persist_manual_provenance(qtbot, tmp_path):
    opened = []
    execute = partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=execute, on_created=opened.append)
    qtbot.addWidget(dialog)
    try:
        old, new = write_pair(tmp_path / 'inputs')
        for key, value in (('older', old), ('newer', new), ('destination', tmp_path / 'project')):
            dialog.fields[key].setText(str(value))
        assert not dialog.buttons['preview'].isEnabled()  # missing behavior before explicit new mode
        dialog.manual_pair_start.setChecked(True)
        assert not dialog.fields['lead'].isEnabled()
        assert not dialog.scope.isEnabled()
        assert dialog.buttons['preview'].isEnabled()
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is not None, dialog.status.text()
        assert 'no advisory linkage' in dialog.details.toPlainText()
        assert 'unverified' in dialog.details.toPlainText().lower()
        assert dialog._preview[1].data['investigation_revision'] is None
        dialog.buttons['create'].click()
        settled(qtbot, dialog)
        assert opened == [(tmp_path / 'project').resolve()]
        with ProjectService.open(opened[0]) as project:
            assert len(project.project.artifacts) == 2
        with WorkspaceStore(tmp_path / 'workspace') as store:
            ids = [row[0] for row in store.db.execute('SELECT investigation_id FROM investigations')]
            assert len(ids) == 1
            revision = store.current_revision(ids[0])
            assert revision.lead.kind == 'pair'
            assert revision.selected_scope_id is None
            assert {d.op for d in store.decisions(ids[0])} >= {'orientation', 'pair-approval'}
        exported = tmp_path / 'bundle.json'
        outcome = wiring.build_service(tmp_path / 'workspace', clock=FixedClock()).export(
            str(opened[0]), str(exported), overwrite=False)
        assert outcome.exit == 0
        import json
        bundle = json.loads(exported.read_text())
        assert bundle['context']['cards'] == []
        assert bundle['scope_id'] is None
    finally:
        dialog.reject()


@pytest.mark.parametrize('field,value', [('investigation_id', 'existing'), ('scope_id', 'scope'),
                                        ('expected_revision', 1)])
def test_manual_start_cannot_bypass_advisory_revision_or_scope(tmp_path, field, value):
    request, _ = manual_preview(tmp_path)
    result = run(replace(request, **{field: value}))
    assert not result.success and result.error_code == 'PT-KBC-INPUT'


def test_manual_create_requires_preview_and_rechecks_bytes(tmp_path):
    request, preview = manual_preview(tmp_path)
    destination = tmp_path / 'project'
    create = replace(request, operation='create', destination=destination)
    assert not run(create).success
    request.newer.write_bytes(synthetic_pe(2))
    result = run(replace(create, expected_pair_id=preview.data['pair']['pair_id']))
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert not destination.exists()


def test_manual_pair_requires_same_component_confirmation(tmp_path):
    old, new = write_pair(tmp_path / 'inputs', newer_name='other.sys')
    request = InvestigationRequest('preview', tmp_path / 'workspace', older=old, newer=new,
                                   manual_pair_start=True)
    assert not run(request).success
    assert run(replace(request, confirm_same_component=True)).success


def test_mode_switch_invalidates_preview_and_clears_previous_advisory_scope(qtbot, tmp_path):
    execute = partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=execute)
    qtbot.addWidget(dialog)
    try:
        old, new = write_pair(tmp_path / 'inputs')
        dialog.fields['older'].setText(str(old))
        dialog.fields['newer'].setText(str(new))
        dialog.manual_pair_start.setChecked(True)
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is not None
        dialog.manual_pair_start.setChecked(False)
        assert dialog._preview is None
        assert not dialog.buttons['preview'].isEnabled()
        assert not dialog.buttons['create'].isEnabled()
        dialog._investigation_id = 'previous'
        dialog.scope.addItem('previous product', 'previous-scope')
        dialog.scope.setCurrentIndex(1)
        dialog.manual_pair_start.setChecked(True)
        request = dialog._request('preview')
        assert request.investigation_id is None and request.scope_id is None
        assert dialog._preview is None
    finally:
        dialog.reject()


def test_cancelled_manual_start_does_not_create_workspace(tmp_path):
    import threading
    token = threading.Event()
    token.set()
    old, new = write_pair(tmp_path / 'inputs')
    workspace = tmp_path / 'workspace'
    request = InvestigationRequest('preview', workspace, older=old, newer=new, manual_pair_start=True)
    result = run(request, token)
    assert not result.success and result.error_code == 'PT-KBC-CANCEL'
    assert not workspace.exists()


def test_cancel_discards_late_real_manual_preview(qtbot, tmp_path):
    import threading

    from patchtrace.gui.qt.tasks import TaskRunner

    started, release = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)

    def execute(request, token):
        result = run(request, token)
        started.set()
        release.wait(5)
        return result

    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=execute, tasks=runner)
    qtbot.addWidget(dialog)
    try:
        old, new = write_pair(tmp_path / 'inputs')
        dialog.fields['older'].setText(str(old))
        dialog.fields['newer'].setText(str(new))
        dialog.manual_pair_start.setChecked(True)
        dialog.buttons['preview'].click()
        qtbot.waitUntil(started.is_set)
        dialog.buttons['cancel'].click()
        release.set()
        qtbot.waitUntil(lambda: not runner.busy())
        assert dialog._preview is None
        assert not dialog.buttons['create'].isEnabled()
        assert 'Cancelled' in dialog.status.text()
    finally:
        release.set()
        dialog.reject()
        runner.shutdown()


def test_current_project_inputs_can_start_binary_only_without_advisory(qtbot, tmp_path):
    from patchtrace.kbcorrelation.investigation_service import CurrentProjectInputs

    previous = ProjectService.sample(tmp_path / 'previous')
    artifacts = {a.side: a for a in previous.project.artifacts}
    snapshot = CurrentProjectInputs(previous.project.id, previous.project.revision, previous.root,
                                    artifacts['older'].model_dump_json(), artifacts['newer'].model_dump_json())
    execute = partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=execute, current_inputs=snapshot,
                                 current_project=previous.root)
    qtbot.addWidget(dialog)
    before = (previous.root / 'project.sqlite3').read_bytes()
    try:
        dialog.manual_pair_start.setChecked(True)
        dialog.buttons['use_current'].click()
        settled(qtbot, dialog)
        assert dialog._input_origin is snapshot
        assert 'advisory scope' not in dialog.status.text()
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is None
        dialog.same_component.setChecked(True)
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is not None, dialog.status.text()
        assert dialog._preview[1].data['input_origin']['project_id'] == previous.project.id
        assert dialog._preview[0].scope_id is None
        assert (previous.root / 'project.sqlite3').read_bytes() == before
    finally:
        dialog.reject()
        previous.close()
