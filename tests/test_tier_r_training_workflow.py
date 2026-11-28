"""Pinned artifact topology and actual unlocked smoke/report commands on authored evidence."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_tier_r_training_artifacts import transfer
from test_tier_r_training_handoff import batch as batch
from test_tier_r_training_handoff import consolidate
from test_train_helpers import make_pair_labels

from tools.calibration import train
from tools.calibration.common import canonical_json, digest
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import shard as S

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/corpus-tier-r.yml'


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def test_training_requires_explicit_boolean_dispatch_and_both_successful_jobs():
    document = workflow()
    opt = document[True]['workflow_dispatch']['inputs']['train']
    assert opt['type'] == 'boolean' and opt['default'] is False
    job = document['jobs']['train']
    assert set(job['needs']) == {'shard', 'merge'}
    for term in ("github.event_name == 'workflow_dispatch'", 'inputs.train',
                 "needs.shard.result == 'success'", "needs.merge.result == 'success'"):
        assert term in job['if']
    assert '||' not in job['if'] and 'always()' not in job['if']
    assert not job.get('continue-on-error')


def test_shard_upload_has_only_the_completed_root_and_keeps_managed_marker():
    job = workflow()['jobs']['shard']
    run = next(step for step in job['steps'] if step.get('name') == 'Run shard')
    assert '--collect-artifacts' in run['run']
    upload = next(step for step in job['steps']
                  if step.get('with', {}).get('name') == 'tier-r-training-${{ matrix.shard }}')
    assert upload.get('if', 'success()') == 'success()'
    assert upload['with']['path'] == 'shard-out/training/'
    assert upload['with']['include-hidden-files'] is True
    assert upload['with']['if-no-files-found'] == 'error'
    assert not upload['with'].get('overwrite')


def test_merge_keeps_shard_roots_and_publishes_only_verified_consolidation():
    job = workflow()['jobs']['merge']
    download = next(step for step in job['steps'] if step.get('with', {}).get('pattern') == 'tier-r-training-*')
    assert download['with']['merge-multiple'] is False
    assert download['with']['path'] == 'training-shards'
    merges = [step['run'] for step in job['steps'] if '.tier_r.shard merge ' in step.get('run', '')]
    assert len(merges) == 2 and all('--artifacts training-shards' in script for script in merges)
    assert any('cmp merged/training/training-artifacts.json merged-again/training/training-artifacts.json' in s
               for s in merges)
    upload = next(step for step in job['steps'] if step.get('with', {}).get('name') == 'tier-r-training-merged')
    assert upload.get('if', 'success()') == 'success()'
    assert upload['with']['include-hidden-files'] is True
    assert upload['with']['if-no-files-found'] == 'error'
    assert upload['with']['path'].split() == ['merged/training/', 'merged/tier-r-aggregate.json',
                                            'merged/tier-r-merge.json']
    aggregate = next(step for step in job['steps'] if step.get('with', {}).get('name') == 'tier-r-aggregate')
    assert 'merged/' not in aggregate['with']['path'].split(), 'broad upload would make an incomplete second transport'


def training_scripts():
    steps = workflow()['jobs']['train']['steps']
    verify = next(step['run'] for step in steps if '.tier_r.shard verify-training ' in step.get('run', ''))
    run = next(step['run'] for step in steps if '.calibration.train run ' in step.get('run', ''))
    return verify, run


def test_training_verifies_before_consumption_and_has_no_lock_or_preregistration_input():
    job = workflow()['jobs']['train']
    verify, run = training_scripts()
    scripts = [step.get('run', '') for step in job['steps']]
    assert scripts.index(verify) < scripts.index(run)
    assert '--artifacts verified/training' in verify
    assert '--report verified/tier-r-aggregate.json' in verify and '--provenance verified/tier-r-merge.json' in verify
    assert '--labels verified/training/labels' in run and '--outputs verified/training/outputs' in run
    assert '--smoke' in run and 'mkdir train-out' in run
    assert '.tier_r.shard verify-training-result ' in run and '.calibration.train report ' in run
    assert '--exit-code "$rc"' in run and 'exit-code.txt' in run
    assert not any(step.get('continue-on-error') for step in job['steps'])
    for forbidden in ('--prereg', '--locked-form', '--unlocked-prereg', 'run_locked_test', '--artifact '):
        assert forbidden not in '\n'.join(scripts)
    download = next(step for step in job['steps'] if step.get('with', {}).get('name') == 'tier-r-training-merged')
    assert download['with']['path'] == 'verified'


@pytest.fixture
def trained(batch, tmp_path, capsys):
    consolidate(batch)
    out = tmp_path / 'train-out'
    code = train.main(['run', '--labels', str(batch[2] / 'labels'), '--outputs', str(batch[2] / 'outputs'),
                       '--smoke', '--tool-git', 'authored-handoff-control', '--out', str(out)])
    summary = json.loads(capsys.readouterr().out)
    report = json.loads((out / 'report.json').read_bytes())
    assert code == train.FINDINGS and summary['status'] == 'halted'
    assert {gate['status'] for gate in report['gates'].values()} == {'insufficient-data'}
    return summary, report, code


def test_existing_training_cli_yields_a_verified_unlocked_insufficient_data_report(trained, tmp_path, capsys):
    summary, report, code = trained
    result = transfer().verify_smoke_result(summary, report, code)
    assert result['status'] == 'insufficient-data' and result['exit_code'] == 1
    assert result['report_sha256'] == report['report_sha256']
    assert report['prereg_sha256'] is None and report['dataset']['preregistered'] is False
    assert report['dataset']['config'] == train.TrainConfig.smoke_config().as_dict()
    report_path = tmp_path / 'report-for-cli.json'
    summary_path = tmp_path / 'summary-for-cli.json'
    report_path.write_bytes(canonical_json(report))
    summary_path.write_bytes(canonical_json(summary))
    assert S.main(['verify-training-result', '--summary', str(summary_path), '--report', str(report_path),
                   '--exit-code', str(code)]) == S.OK
    assert json.loads(capsys.readouterr().out) == result
    assert train.main(['report', str(report_path), '--out', str(tmp_path / 'verified.md')]) == train.OK
    assert (tmp_path / 'verified.md').is_file()


def test_zero_exit_smoke_still_verifies_when_only_sample_size_blocks_a_fit(tmp_path, capsys):
    # Eight natural lineages meet the smoke lineage floor, but one correspondence
    # each is still below the fitter's sample floor. No model fit is invoked.
    docs = [make_pair_labels(f'authored-source-{index}', n_funcs=1) for index in range(8)]
    labels = tmp_path / 'labels'
    labels.mkdir()
    for doc in docs:
        (labels / f'{doc.pair_id}.json').write_bytes(C.dump_json(doc.model_dump(mode='json')))
    answer = E.EngineOutput('rz-diff', 'ok', version='authored-control',
                            predictions=(E.Prediction(0x1000, 0x1000, False, 1000),))
    outputs = tmp_path / 'outputs'
    E.evaluate(docs, [E.StaticProvider('rz-diff', {doc.pair_id: answer for doc in docs})],
               output_dir=outputs, b_count=20)
    out = tmp_path / 'train'
    assert train.main(['run', '--labels', str(labels), '--outputs', str(outputs), '--smoke', '--out', str(out)]) == 0
    summary = json.loads(capsys.readouterr().out)
    report = json.loads((out / 'report.json').read_bytes())
    assert report['dataset']['n_lineages_natural'] == 8 and report['dataset']['n_natural'] < train.FIT_MIN['rows']
    assert {gate['status'] for gate in report['gates'].values()} == {'insufficient-data'}
    assert transfer().verify_smoke_result(summary, report, 0)['exit_code'] == 0


@pytest.mark.parametrize('damage', ['leak', 'unknown-halt', 'missing-halt', 'mismatched-summary', 'gate-status',
                                     'locked', 'preregistered', 'full-config', 'wrong-origin', 'wrong-key',
                                     'wrong-report-digest', 'exit-zero', 'exit-usage', 'exit-blocked'])
def test_smoke_result_check_never_masks_failure_or_uses_a_stale_report(trained, damage):
    summary, report, code = copy.deepcopy(trained)
    if damage in ('leak', 'unknown-halt'):
        summary['halt'].append('PT-KA-LEAK: authored refusal' if damage == 'leak' else 'unexpected processing failure')
    elif damage == 'missing-halt':
        summary.pop('halt')
    elif damage == 'mismatched-summary':
        summary['report_sha256'] = 'e' * 64
    elif damage == 'gate-status':
        summary['gates']['G1'] = 'pass'
    elif damage == 'locked':
        report['prereg_sha256'] = 'f' * 64
    elif damage == 'preregistered':
        report['dataset']['preregistered'] = True
    elif damage == 'full-config':
        report['dataset']['config'] = train.TrainConfig().as_dict()
    elif damage == 'wrong-origin':
        report['dataset']['origin'] = 'rows'
    elif damage == 'wrong-key':
        summary['train_key'] = 'f' * 64
    elif damage.startswith('exit-'):
        code = {'exit-zero': 0, 'exit-usage': 2, 'exit-blocked': 3}[damage]
    else:
        report['tool_git'] = 'unrelated'
    if damage in ('locked', 'preregistered', 'full-config', 'wrong-origin'):
        report['report_sha256'] = digest(report, 'report_sha256')
        summary['report_sha256'] = report['report_sha256']
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_smoke_result(summary, report, code)


@pytest.mark.parametrize('corrupt', [False, True], ids=['complete-smoke', 'missing-managed-marker'])
@pytest.mark.skipif(os.name == 'nt', reason='executes the Ubuntu workflow Bash commands; static wiring checks are portable')
def test_actual_workflow_shell_reaches_report_or_stops_before_training(batch, tmp_path, corrupt):
    consolidate(batch)
    work = tmp_path / 'workflow-workspace'
    verified = work / 'verified'
    verified.mkdir(parents=True)
    batch[2].rename(verified / 'training')
    S.write_merge(batch[3], batch[4], verified)
    if corrupt:
        (verified / 'training' / 'outputs' / OS.MANAGED_MARKER).unlink()
    verify, run = training_scripts()
    env = {**os.environ, 'PATH': f'{Path(sys.executable).parent}{os.pathsep}{os.environ.get("PATH", "")}',
           'PYTHONPATH': f'{ROOT}{os.pathsep}{ROOT / "src"}', 'GITHUB_SHA': 'b' * 40}
    proc = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', verify + '\n' + run], cwd=work, env=env,
                          capture_output=True, text=True, timeout=30)
    if corrupt:
        assert proc.returncode != 0
        assert not (work / 'train-out').exists()
    else:
        assert proc.returncode == 0, proc.stderr
        out = work / 'train-out'
        assert (out / 'exit-code.txt').read_text().strip() == '1'
        assert json.loads((out / 'handoff.json').read_bytes())['status'] == 'insufficient-data'
        report = json.loads((out / 'report.json').read_bytes())
        assert {gate['status'] for gate in report['gates'].values()} == {'insufficient-data'}
        assert report['prereg_sha256'] is None and (out / 'verified-report.md').is_file()
