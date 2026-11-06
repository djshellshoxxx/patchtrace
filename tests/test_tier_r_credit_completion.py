"""Constructed completion/budget controls; no native engine or corpus acceptance."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_tier_r_output_persistence import LABELS, provider, store_labels

from tools.calibration.common import canonical_json
from tools.calibration.tier_r import cli
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import report_schemas as RS


def prepared(folder):
    report = E.evaluate([LABELS], [provider()], b_count=20)
    output = E.engine_output_doc(provider().outputs[LABELS.pair_id], LABELS, 'hidden')
    store = OS.OutputStore(folder)
    store.write(LABELS.pair_id, 'rz-diff', output)
    return store, report


def test_aggregate_budget_preflight_matches_exact_final_bytes(tmp_path, monkeypatch):
    store, report = prepared(tmp_path / 'reference')
    store.finalize([report])
    raw = (store.folder / OS.CREDIT_FILE).read_bytes()
    records = [{k: v for k, v in row.items() if k != 'report_sha256'} for row in json.loads(raw)['outputs']]
    monkeypatch.setattr(RS, 'MAX_CREDIT_BYTES', len(raw))
    OS.preflight_credit_manifest([report], records)
    other, other_report = prepared(tmp_path / 'boundary')
    other.finalize([other_report])
    assert (other.folder / OS.CREDIT_FILE).read_bytes() == raw
    monkeypatch.setattr(RS, 'MAX_CREDIT_BYTES', len(raw) - 1)
    with pytest.raises(OS.OutputError, match='exceeds'):
        OS.preflight_credit_manifest([report], records)
    with pytest.raises(OS.OutputError, match='credit manifest'):
        OS.read_credited_outputs(store.folder)
    too_large, same_report = prepared(tmp_path / 'oversize')
    with pytest.raises(OS.OutputError, match='exceeds'):
        too_large.finalize([same_report])
    assert not (too_large.folder / OS.CREDIT_FILE).exists()
    assert len(list(too_large.folder.glob(f'{LABELS.pair_id}.*.json'))) == 1


@pytest.mark.parametrize('stage', ['sentinel', 'credit', 'verification', 'removal'])
def test_each_completion_failure_preserves_report_without_credit(tmp_path, monkeypatch, stage):
    outputs = tmp_path / 'outputs'
    publish, verify, unlink = OS._publish_owned_bytes, OS._verify_completed_outputs, Path.unlink

    def fail_publish(path, raw):
        if Path(path).name == {'sentinel': OS.COMPLETION_FILE, 'credit': OS.CREDIT_FILE}.get(stage):
            raise OS.OutputError(f'injected {stage} publication failure')
        return publish(path, raw)

    def fail_verify(folder):
        result = verify(folder)
        if stage == 'verification':
            raise OS.OutputError('injected postcredit verification failure')
        return result

    def fail_unlink(path, *args, **kwargs):
        if stage == 'removal' and path.name == OS.COMPLETION_FILE:
            raise PermissionError('injected sentinel removal failure')
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(OS, '_publish_owned_bytes', fail_publish)
    monkeypatch.setattr(OS, '_verify_completed_outputs', fail_verify)
    monkeypatch.setattr(Path, 'unlink', fail_unlink)
    with pytest.raises(E.EvaluationRetentionError) as caught:
        E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    failure = caught.value
    report = C.load_report((outputs / OS.UNCREDITED_REPORT).read_bytes())
    assert report.report_sha256 == failure.report['report_sha256']
    assert report.pairs[0].status == 'ok' and report.pairs[0].metrics is not None
    marker = RS.EvaluationFailure.model_validate_json((outputs / OS.FAILURE_FILE).read_bytes())
    assert marker.credited is False and marker.status == 'failed'
    assert marker.report_sha256 == report.report_sha256
    assert failure.diagnostics['report'] == (outputs / OS.UNCREDITED_REPORT).as_posix()
    assert (outputs / OS.CREDIT_FILE).exists() == (stage in ('verification', 'removal'))
    assert (outputs / OS.COMPLETION_FILE).exists() == (stage != 'sentinel')
    with pytest.raises(OS.OutputError, match='incomplete|failed'):
        OS.read_credited_outputs(outputs)


@pytest.mark.parametrize('failed_files', [('marker',), ('report',), ('marker', 'report')])
def test_diagnostic_write_failure_keeps_original_report_and_durable_refusal(tmp_path, monkeypatch, failed_files):
    outputs = tmp_path / 'outputs'
    publish, verify = OS.publish_bytes, OS._verify_completed_outputs
    names = {'marker': OS.FAILURE_FILE, 'report': OS.UNCREDITED_REPORT}

    def fail_publish(path, raw):
        if Path(path).name in {names[item] for item in failed_files}:
            raise OS.OutputError('injected diagnostic failure')
        return publish(path, raw)

    def fail_verify(folder):
        verify(folder)
        raise OS.OutputError('injected postcredit verification failure')

    monkeypatch.setattr(OS, 'publish_bytes', fail_publish)
    monkeypatch.setattr(OS, '_verify_completed_outputs', fail_verify)
    with pytest.raises(E.EvaluationRetentionError) as caught:
        E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    failure = caught.value
    C.load_report(C.dump_json(failure.report))
    assert set(failure.diagnostics['errors']) == set(failed_files)
    assert (outputs / OS.CREDIT_FILE).exists()
    assert (outputs / OS.COMPLETION_FILE).exists()
    with pytest.raises(OS.OutputError, match='incomplete'):
        OS.read_credited_outputs(outputs)


def test_budget_failure_cli_is_failed_completion_and_exposes_report(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    monkeypatch.setattr(RS, 'MAX_CREDIT_BYTES', 1)
    publish = OS.publish_bytes

    def fail_report(path, raw):
        if Path(path).name == OS.UNCREDITED_REPORT:
            raise OS.OutputError('injected report diagnostic failure')
        return publish(path, raw)

    monkeypatch.setattr(OS, 'publish_bytes', fail_report)
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff']) == cli.FINDINGS
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'failed' and result['credited'] is False
    assert result['report_data']['pairs'][0]['metrics'] is not None
    assert not (store / 'reports').exists()
    assert result['diagnostics']['attempted']['report'] == (Path(result['outputs']) / OS.UNCREDITED_REPORT).as_posix()
    assert 'report' in result['diagnostics']['errors']


def test_completed_store_cannot_hide_prior_completion(tmp_path):
    store, report = prepared(tmp_path / 'outputs')
    store.finalize([report])
    before = {p.name: p.read_bytes() for p in store.folder.iterdir()}
    with pytest.raises(OS.OutputError, match='finalized'):
        store.finalize([report])
    with pytest.raises(OS.OutputError, match='finalized'):
        store.retain_failure(report, OS.OutputError('later unrelated failure'))
    assert {p.name: p.read_bytes() for p in store.folder.iterdir()} == before
    assert OS.read_credited_outputs(store.folder)
    assert set(OS.MANAGED_FILES) == {OS.MANAGED_MARKER, OS.CREDIT_FILE}


@pytest.mark.parametrize('name', ['completion', 'marker', 'report'])
@pytest.mark.parametrize('kind', ['file', 'broken_link'])
@pytest.mark.parametrize('completed', [False, True])
def test_incomplete_artifacts_never_select_legacy_or_completed_credit(tmp_path, name, kind, completed):
    folder = tmp_path / 'outputs'
    if completed:
        store, report = prepared(folder)
        store.finalize([report])
    else:
        folder.mkdir()
    path = folder / {'completion': OS.COMPLETION_FILE, 'marker': OS.FAILURE_FILE,
                     'report': OS.UNCREDITED_REPORT}[name]
    if kind == 'file':
        path.write_bytes(b'not even valid JSON')
    else:
        try:
            path.symlink_to(folder / 'missing')
        except OSError:
            pytest.skip('symlink creation unavailable')
    with pytest.raises(OS.OutputError, match='incomplete|failed'):
        OS.read_credited_outputs(folder)
    with pytest.raises(OS.OutputError, match='ambiguous'):
        OS.legacy_output_paths(tmp_path)


def test_diagnostics_never_overwrite_existing_user_bytes(tmp_path, monkeypatch):
    outputs = tmp_path / 'outputs'
    verify = OS._verify_completed_outputs

    def fail_verify(folder):
        verify(folder)
        (folder / OS.FAILURE_FILE).write_bytes(b'user marker')
        (folder / OS.UNCREDITED_REPORT).write_bytes(b'user report')
        raise OS.OutputError('injected failure')

    monkeypatch.setattr(OS, '_verify_completed_outputs', fail_verify)
    with pytest.raises(E.EvaluationRetentionError) as caught:
        E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    assert (outputs / OS.FAILURE_FILE).read_bytes() == b'user marker'
    assert (outputs / OS.UNCREDITED_REPORT).read_bytes() == b'user report'
    assert set(caught.value.diagnostics['errors']) == {'marker', 'report'}


def test_failure_schema_is_bounded_and_cannot_claim_credit():
    RS.OutputCompletion.model_validate_json(OS._COMPLETION_BYTES)
    valid = {'contract': RS.FAILURE_CONTRACT, 'status': 'failed', 'credited': False,
             'report_file': OS.UNCREDITED_REPORT, 'report_sha256': 'a' * 64, 'error': 'failed'}
    RS.EvaluationFailure.model_validate_json(canonical_json(valid))
    for change in ({'credited': True}, {'status': 'ok'}, {'report_file': '../report.json'}, {'error': 'x' * 1001}):
        with pytest.raises(ValueError):
            RS.EvaluationFailure.model_validate_json(canonical_json({**valid, **change}))


@pytest.mark.parametrize('replacement', [False, True])
def test_changed_sentinel_is_preserved_and_never_removed(tmp_path, monkeypatch, replacement):
    store, report = prepared(tmp_path / 'outputs')
    verify = OS._verify_completed_outputs
    sentinel = store.folder / OS.COMPLETION_FILE

    def change_sentinel(folder):
        result = verify(folder)
        if replacement:
            raw = sentinel.read_bytes()
            sentinel.rename(folder / 'original-sentinel')  # Hold inode; no reuse can mask the replacement.
            sentinel.write_bytes(raw)
        else:
            sentinel.write_bytes(b'foreign completion bytes')
        return result

    monkeypatch.setattr(OS, '_verify_completed_outputs', change_sentinel)
    with pytest.raises(OS.OutputError, match='sentinel'):
        store.finalize([report])
    assert sentinel.exists()
    with pytest.raises(OS.OutputError, match='incomplete'):
        OS.read_credited_outputs(store.folder)
    with pytest.raises(OS.OutputError, match='finalized'):
        store.finalize([report])


def test_success_removes_sentinel_only_after_validation_with_no_later_io(tmp_path, monkeypatch):
    store, report = prepared(tmp_path / 'outputs')
    sentinel = store.folder / OS.COMPLETION_FILE
    verify, check_owner, unlink = OS._verify_completed_outputs, store._check_owner, Path.unlink
    state = {'verified': False, 'completed': False}

    def checked_verify(folder):
        assert sentinel.exists() and not state['completed']
        result = verify(folder)
        state['verified'] = True
        return result

    def checked_owner():
        assert not state['completed'], 'fallible owner check after the final transition'
        check_owner()

    def checked_unlink(path, *args, **kwargs):
        if path == sentinel:
            assert state['verified']
            state['completed'] = True
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(OS, '_verify_completed_outputs', checked_verify)
    monkeypatch.setattr(store, '_check_owner', checked_owner)
    monkeypatch.setattr(Path, 'unlink', checked_unlink)
    store.finalize([report])
    assert state == {'verified': True, 'completed': True}


def test_unexpected_diagnostic_failure_cannot_discard_the_assembled_report(tmp_path, monkeypatch):
    monkeypatch.setattr(RS, 'MAX_CREDIT_BYTES', 1)

    def broken_diagnostics(*args):
        raise RuntimeError('unexpected diagnostic failure')

    monkeypatch.setattr(OS.OutputStore, 'retain_failure', broken_diagnostics)
    with pytest.raises(E.EvaluationRetentionError) as caught:
        E.evaluate([LABELS], [provider()], output_dir=tmp_path / 'outputs', b_count=20)
    failure = caught.value
    C.load_report(C.dump_json(failure.report))
    assert 'credit manifest' in str(failure.cause)
    assert set(failure.diagnostics['errors']) == {'marker', 'report'}


def test_preflight_rejects_duplicate_metadata_and_missing_success_reference(tmp_path):
    store, report = prepared(tmp_path / 'reference')
    store.finalize([report])
    document = json.loads((store.folder / OS.CREDIT_FILE).read_bytes())
    record = {key: value for key, value in document['outputs'][0].items() if key != 'report_sha256'}
    for records in ([], [record, record], [{**record, 'output_sha256': '0' * 64}], [{**record, 'version': 123}]):
        with pytest.raises(OS.OutputError):
            OS.preflight_credit_manifest([report], records)
