"""LBL-31 regression tests: durable Tier R engine output files use the scorer's exact SHA.

All engine responses in this file are synthetic. These tests make no live accuracy claim.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from test_tier_r_eval_metrics import FUNCS, make_labels  # noqa: E402
from tools.calibration.tier_r import cli, contracts as C, evaluate as E  # noqa: E402
from tools.calibration.tier_r import output_store as OS  # noqa: E402
from tools.calibration.tier_r import report_schemas as RS  # noqa: E402


LABELS = make_labels(FUNCS, pair_id='lbl31-synthetic')


def provider() -> E.StaticProvider:
    output = E.EngineOutput(
        'rz-diff', 'ok', version='synthetic',
        predictions=(E.Prediction(0x1000, 0x1000, False, 1000),
                     E.Prediction(0x1020, 0x1020, True, 900)),
    )
    return E.StaticProvider('rz-diff', {LABELS.pair_id: output})


def test_evaluate_persists_exact_scored_document_and_digest(tmp_path):
    target = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], output_dir=target, b_count=20)
    path = target / 'lbl31-synthetic.rz-diff.json'
    raw = path.read_bytes()
    record = RS.load_engine_output(raw)
    assert record.engine == 'rz-diff'
    assert record.predictions[0].old_rva == 0x1000
    assert record.older_sha256 == LABELS.older.sha256
    assert record.newer_sha256 == LABELS.newer.sha256
    assert hashlib.sha256(raw).hexdigest() == report['pairs'][0]['output_sha256']
    assert report['pairs'][0]['status'] == 'ok'


def test_evaluate_does_not_persist_blocked_result(tmp_path):
    target = tmp_path / 'outputs'
    p = E.StaticProvider('rz-diff', {})
    report = E.evaluate([LABELS], [p], output_dir=target, b_count=20)
    assert list(target.glob('*.json')) == []
    assert report['pairs'][0]['status'] == 'blocked'
    assert report['pairs'][0]['output_sha256'] is None


def test_output_size_failure_is_not_a_successful_engine_run(tmp_path, monkeypatch):
    monkeypatch.setattr(OS, 'MAX_ENGINE_OUTPUT_BYTES', 50)
    target = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], output_dir=target, b_count=20)
    assert report['pairs'][0]['status'] == 'failed'
    assert report['pairs'][0]['output_sha256'] is None
    assert report['engines'][0]['runs'] == 0
    assert list(target.iterdir()) == []


def test_output_store_refuses_stale_files_and_invalid_names(tmp_path):
    folder = tmp_path / 'outputs'
    folder.mkdir()
    (folder / 'old.rz-diff.json').write_text('{}')
    with pytest.raises(OS.OutputError, match='nonempty'):
        OS.prepare_output_dir(folder)
    with pytest.raises(OS.OutputError):
        OS.output_file_name('../escape', 'rz-diff')
    with pytest.raises(OS.OutputError):
        OS.output_file_name('safe', '../escape')


def test_cli_outputs_option_round_trips_to_training_document(tmp_path, monkeypatch, capsys):
    store = tmp_path / 'store'
    label_dir = store / 'labels'
    label_dir.mkdir(parents=True)
    (label_dir / 'lbl31-synthetic.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    outputs = tmp_path / 'engine-outputs'
    code = cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff',
                     '--outputs', str(outputs)])
    response = json.loads(capsys.readouterr().out)
    assert (code, response['status']) == (0, 'ok')
    assert response['outputs'] == outputs.as_posix()
    assert RS.load_engine_output((outputs / 'lbl31-synthetic.rz-diff.json').read_bytes()).engine == 'rz-diff'
    # Report hash remains a digest of report content, not output-folder location.
    report = C.load_report(Path(response['report']).read_bytes())
    assert report.pairs[0].output_sha256 == hashlib.sha256(
        (outputs / 'lbl31-synthetic.rz-diff.json').read_bytes()).hexdigest()


def test_cli_rejects_reusing_directory_with_old_engine_outputs(tmp_path, monkeypatch, capsys):
    store = tmp_path / 'store'
    label_dir = store / 'labels'
    label_dir.mkdir(parents=True)
    (label_dir / 'lbl31-synthetic.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    outputs = tmp_path / 'outputs'
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff', '--outputs', str(outputs)]) == 0
    capsys.readouterr()
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff', '--outputs', str(outputs)]) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'error'


def test_training_artifacts_copy_exact_scored_files_and_verify_tampering(tmp_path):
    from tools.calibration.tier_r import training_artifacts as TA
    store = tmp_path / 'known-answer'
    labels = store / 'labels'
    labels.mkdir(parents=True)
    (labels / 'lbl31-synthetic.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    outputs = store / 'outputs' / 'rz-diff'
    report = E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    artifacts = tmp_path / 'artifact'
    assert TA.export_training_artifacts([report], store, artifacts) == {'labels': 1, 'outputs': 1}
    assert TA.verify_training_artifacts([report], artifacts) == {'labels': 1, 'outputs': 1}
    changed = artifacts / 'outputs' / 'lbl31-synthetic.rz-diff.json'
    changed.write_bytes(changed.read_bytes() + b' ')
    with pytest.raises(TA.ArtifactError, match='SHA-256 mismatch'):
        TA.verify_training_artifacts([report], artifacts)


def test_training_artifacts_reject_missing_label_or_unexpected_file(tmp_path):
    from tools.calibration.tier_r import training_artifacts as TA
    store = tmp_path / 'known-answer'
    labels = store / 'labels'
    labels.mkdir(parents=True)
    (labels / 'lbl31-synthetic.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    report = E.evaluate([LABELS], [provider()], output_dir=store / 'outputs' / 'rz-diff', b_count=20)
    (labels / 'lbl31-synthetic.json').unlink()
    with pytest.raises(TA.ArtifactError, match='missing'):
        TA.export_training_artifacts([report], store, tmp_path / 'artifact')
    (labels / 'lbl31-synthetic.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    other = tmp_path / 'good'
    TA.export_training_artifacts([report], store, other)
    (other / 'outputs' / 'extra.json').write_text('{}')
    with pytest.raises(TA.ArtifactError, match='unexpected'):
        TA.verify_training_artifacts([report], other)
