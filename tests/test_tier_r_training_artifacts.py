"""Constructed-provider shard -> real evaluator -> verified merge -> actual reader.

No target images, native engines, fit, or final evaluation are executed here.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_tier_r_output_persistence import LABELS, provider

from tools.calibration import train
from tools.calibration.common import canonical_json, digest
from tools.calibration.tier_r import cli
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import shard as S
from tools.calibration.tier_r import training_artifacts as TA


def plan():
    doc = {'contract': S.PLAN_CONTRACT, 'seed': 1, 'subset': 'suites', 'engines': ['rz-diff'],
           'of': 1, 'cases_total': 1, 'shards': [{'shard': 0, 'cases': ['suite:_template/tiny']}]}
    doc['plan_sha256'] = digest(doc, 'plan_sha256')
    return doc


@pytest.fixture
def built(tmp_path, monkeypatch):
    observed = {}
    monkeypatch.setattr(cli.E, 'default_providers', lambda *a, **k: [provider()])

    def runner(argv, timeout, env):
        store = Path(env['PATCHTRACE_CALIB_ROOT']) / 'known-answer'
        if argv[3] != 'evaluate':
            (store / 'labels').mkdir(parents=True, exist_ok=True)
            raw = C.dump_json(LABELS.model_dump(mode='json'))
            (store / 'labels' / TA.pair_name(LABELS.pair_id)).write_bytes(raw)
            observed['labels_raw'] = raw
            return 0, json.dumps({'status': 'ok', 'written': [TA.pair_name(LABELS.pair_id)]}), None
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = cli.main([*argv[3:], '--store', str(store)])
        observed['evaluation'] = json.loads(output.getvalue())
        return rc, output.getvalue(), None

    def run(*, modify_runner=None, out=None, scratch=None):
        dest = out or tmp_path / 'shards'
        doc = S.run_shard(plan(), 0, runner=modify_runner or runner,
                          scratch=scratch or tmp_path / 'scratch', artifacts_dir=dest / 'training')
        S.write_shard(doc, dest)
        return doc, dest, observed
    run.runner = runner
    return run


def merge(source, out):
    return S.main(['merge', '--in', str(source), '--artifacts', str(source / 'training'), '--out', str(out)])


def test_actual_shard_evaluate_merge_reader_preserves_exact_bytes(built, tmp_path):
    doc, source, observed = built()
    assert all(c['status'] == 'ok' for c in doc['cases'])
    original = observed['evaluation']
    source_report = Path(original['report']).read_bytes()
    source_output = Path(original['outputs']) / OS.output_file_name(LABELS.pair_id, 'rz-diff')
    out = tmp_path / 'merged'
    assert merge(source, out) == S.OK
    bundle = out / 'training'
    report_sha = doc['reports'][0]['report_sha256']
    assert (bundle / 'reports' / f'{report_sha}.json').read_bytes() == source_report
    assert (bundle / 'labels' / TA.pair_name(LABELS.pair_id)).read_bytes() == observed['labels_raw']
    assert (bundle / 'outputs' / source_output.name).read_bytes() == source_output.read_bytes()
    found = train.load_outputs(bundle / 'outputs', allow_legacy=False)
    assert list(found) == [(LABELS.older.sha256, LABELS.newer.sha256, 'rz-diff')]
    assert found[next(iter(found))][1] == hashlib.sha256(source_output.read_bytes()).hexdigest()
    assert json.loads((bundle / TA.MANIFEST).read_bytes())['pair_cases'] == {
        LABELS.pair_id: {'case': 'suite:_template/tiny', 'shard': 0}}


def test_evaluator_failed_exit_one_stays_failed_in_actual_shard(built, monkeypatch):
    monkeypatch.setattr(cli.E, 'default_providers', lambda *a, **k: [provider(returned_engine='ghidriff')])
    doc, source, observed = built()
    assert observed['evaluation']['status'] == 'failed'
    assert next(c for c in doc['cases'] if c['id'] == 'evaluate:rz-diff')['status'] == 'failed'
    outputs = source / 'training' / 'shard-0' / 'outputs'
    assert OS.read_credited_outputs(outputs) == []
    assert train.load_outputs(outputs, allow_legacy=False) == {}


def test_cli_failed_evaluation_exits_one_and_boolean_only(built, monkeypatch, tmp_path):
    monkeypatch.setattr(cli.E, 'default_providers', lambda *a, **k: [provider(returned_engine='ghidriff')])
    monkeypatch.setattr(S, 'default_runner', built.runner)
    target = tmp_path / 'github-output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(target))
    p = tmp_path / 'plan.json'
    p.write_bytes(canonical_json(plan()))
    assert S.main(['run-shard', '--plan', str(p), '--shard', '0', '--out', str(tmp_path / 'shards'),
                   '--collect-artifacts']) == S.FINDINGS
    assert target.read_text() == 'verified_training=true\n'


def test_failed_uncredited_output_is_preserved_but_never_transferred(built):
    def runner(argv, timeout, env):
        result = built.runner(argv, timeout, env)
        if argv[3] == 'evaluate':
            summary = json.loads(result[1])
            (Path(summary['outputs']) / 'uncredited.rz-diff.json').write_bytes(b'preserved failed evidence')
        return result
    doc, source, observed = built(modify_runner=runner)
    assert all(c['status'] == 'ok' for c in doc['cases'])
    assert (Path(observed['evaluation']['outputs']) / 'uncredited.rz-diff.json').exists()
    assert not (source / 'training' / 'shard-0' / 'outputs' / 'uncredited.rz-diff.json').exists()


@pytest.mark.parametrize('damage', ['report-byte', 'label-byte', 'output-byte', 'marker', 'credit', 'manifest',
                                   'extra-visible', 'extra-hidden', 'extra-binary', 'missing'])
def test_merge_rejects_damage_before_writing_any_result(built, tmp_path, damage):
    doc, source, _ = built()
    bundle = source / 'training' / 'shard-0'
    names = {'report-byte': bundle / 'reports' / (doc['reports'][0]['report_sha256'] + '.json'),
             'label-byte': bundle / 'labels' / TA.pair_name(LABELS.pair_id),
             'output-byte': bundle / 'outputs' / OS.output_file_name(LABELS.pair_id, 'rz-diff'),
             'marker': bundle / 'outputs' / OS.MANAGED_MARKER,
             'credit': bundle / 'outputs' / OS.CREDIT_FILE, 'manifest': bundle / TA.MANIFEST}
    if damage in names:
        names[damage].write_bytes(names[damage].read_bytes() + b' ')
    elif damage == 'missing':
        (bundle / 'labels' / TA.pair_name(LABELS.pair_id)).unlink()
    else:
        name = {'extra-visible': 'stray.json', 'extra-hidden': '.secret.json', 'extra-binary': 'x.dll'}[damage]
        (bundle / 'outputs' / name).write_bytes(b'MZ')
    out = tmp_path / 'merged'
    assert merge(source, out) == S.USAGE
    assert not out.exists()


@pytest.mark.parametrize('part', ['training', 'bundle', 'labels', 'outputs', 'reports', 'manifest', 'label',
                                 'output', 'report', 'marker', 'credit'])
def test_actual_merge_rejects_source_links_at_every_component(built, tmp_path, part):
    doc, source, _ = built()
    bundle = source / 'training' / 'shard-0'
    selected = {'training': source / 'training', 'bundle': bundle, 'labels': bundle / 'labels',
                'outputs': bundle / 'outputs', 'reports': bundle / 'reports', 'manifest': bundle / TA.MANIFEST,
                'label': bundle / 'labels' / TA.pair_name(LABELS.pair_id),
                'output': bundle / 'outputs' / OS.output_file_name(LABELS.pair_id, 'rz-diff'),
                'report': bundle / 'reports' / (doc['reports'][0]['report_sha256'] + '.json'),
                'marker': bundle / 'outputs' / OS.MANAGED_MARKER, 'credit': bundle / 'outputs' / OS.CREDIT_FILE}[part]
    target = tmp_path / 'external'
    selected.rename(target)
    try:
        selected.symlink_to(target, target_is_directory=target.is_dir())
    except OSError:
        pytest.skip('native symlink creation unavailable; reparse attribute consumer test remains mandatory')
    assert merge(source, tmp_path / 'merged') == S.USAGE
    assert not (tmp_path / 'merged').exists()


def test_actual_merge_refuses_windows_training_parent_reparse(built, tmp_path, monkeypatch):
    _doc, source, _ = built()
    parent = source / 'training'
    original = Path.lstat

    def reparse(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400,
                                   st_dev=info.st_dev, st_ino=info.st_ino)
        return info
    monkeypatch.setattr(Path, 'lstat', reparse)
    assert merge(source, tmp_path / 'merged') == S.USAGE
    assert not (tmp_path / 'merged').exists()


def test_target_training_parent_reparse_refused_before_publication(built, tmp_path, monkeypatch):
    _doc, source, _ = built()
    out = tmp_path / 'merged'
    out.mkdir()
    original = Path.lstat

    def reparse(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == out:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400,
                                   st_dev=info.st_dev, st_ino=info.st_ino)
        return info
    monkeypatch.setattr(Path, 'lstat', reparse)
    assert merge(source, out) == S.USAGE
    assert list(out.iterdir()) == []


def test_partial_publication_is_preserved_without_completion(built, tmp_path, monkeypatch):
    original = TA.publish_bytes

    def fail_report(path, raw):
        if path.parent.name == 'reports':
            raise OS.OutputError('constructed report publication failure')
        return original(path, raw)
    monkeypatch.setattr(TA, 'publish_bytes', fail_report)
    doc, source, _ = built()
    assert doc['cases'][-1]['id'] == 'transfer:training'
    assert doc['cases'][-1]['status'] == 'failed'
    bundle = source / 'training' / 'shard-0'
    assert (bundle / 'labels' / TA.pair_name(LABELS.pair_id)).exists()
    assert not (bundle / TA.MANIFEST).exists()
    assert merge(source, tmp_path / 'merged') == S.USAGE


def test_existing_bundle_never_replaced(built, tmp_path):
    _doc, source, _ = built()
    bundle = source / 'training' / 'shard-0'
    before = {str(p.relative_to(bundle)): p.read_bytes() for p in bundle.rglob('*') if p.is_file()}
    doc, _source, _ = built(scratch=tmp_path / 'scratch-again')
    assert doc['cases'][-1]['status'] == 'failed'
    assert before == {str(p.relative_to(bundle)): p.read_bytes() for p in bundle.rglob('*') if p.is_file()}


def test_duplicate_builder_pair_refused_even_with_identical_bytes(built, monkeypatch):
    monkeypatch.setattr(S, 'case_steps', lambda _id: [['build-suite', 'x'], ['build-suite', 'x']])
    doc, source, _ = built()
    assert 'duplicate' in doc['cases'][-1]['reason']
    assert not (source / 'training' / 'shard-0' / TA.MANIFEST).exists()


def test_unreported_scratch_labels_are_not_adopted(built):
    def runner(argv, timeout, env):
        rc, stdout, reason = built.runner(argv, timeout, env)
        if argv[3] != 'evaluate':
            stdout = json.dumps({'status': 'ok', 'written': []})
        return rc, stdout, reason
    doc, source, _ = built(modify_runner=runner)
    assert 'case ownership' in doc['cases'][-1]['reason']
    assert not (source / 'training' / 'shard-0' / TA.MANIFEST).exists()


def test_duplicate_pair_across_shards_is_rejected(built, tmp_path):
    doc, source, _ = built()
    other = copy.deepcopy(doc)
    other['shard'] = 1
    other['shard_sha256'] = digest(other, 'shard_sha256')
    bundle = source / 'training' / 'shard-0'
    raw_reports, labels, outputs, cases = TA.verify_bundle(
        bundle, owner=TA.shard_owner(doc), expected_reports=doc['reports'])
    TA._write_bundle(source / 'training' / 'shard-1', TA.shard_owner(other), cases, raw_reports, labels, outputs)
    with pytest.raises(TA.ArtifactError, match='duplicate pair ownership'):
        TA.merge_training_artifacts([doc, other], source / 'training', tmp_path / 'merged')
    assert not (tmp_path / 'merged').exists()


def test_training_schema_is_generated_without_drift(tmp_path):
    expected = Path(__file__).resolve().parents[1] / 'docs/schemas/corpus/TrainingManifest.json'
    assert TA.write_schema(tmp_path).read_bytes() == expected.read_bytes()


@pytest.mark.parametrize('damage', ['shard', 'case', 'kind', 'status'])
def test_merged_manifest_case_ownership_is_bound_to_diagnostics(built, tmp_path, damage):
    doc, source, _ = built()
    out = tmp_path / 'merged'
    assert merge(source, out) == S.OK
    bundle = out / 'training'
    path = bundle / TA.MANIFEST
    manifest = json.loads(path.read_bytes())
    owner = copy.deepcopy(manifest['owner'])
    if damage == 'shard':
        manifest['pair_cases'][LABELS.pair_id]['shard'] = 255
    elif damage == 'case':
        manifest['pair_cases'][LABELS.pair_id]['case'] = 'suite:foreign/case'
    elif damage == 'kind':
        manifest['pair_cases'][LABELS.pair_id] = 'suite:_template/tiny'
    else:
        owner['shards'][0]['cases'][0]['status'] = 'failed'
        manifest['owner'] = owner
    manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
    path.write_bytes(canonical_json(manifest))
    with pytest.raises(TA.ArtifactError, match='case'):
        TA.verify_bundle(bundle, owner=owner, expected_reports=doc['reports'])


@pytest.mark.parametrize('damage', ['case', 'plan', 'shard', 'provider', 'report'])
def test_rehashed_manifest_cannot_reassign_shard_evidence(built, tmp_path, damage):
    _doc, source, _ = built()
    path = source / 'training' / 'shard-0' / TA.MANIFEST
    manifest = json.loads(path.read_bytes())
    if damage == 'case':
        manifest['pair_cases'][LABELS.pair_id] = 'suite:foreign/case'
    elif damage == 'plan':
        manifest['owner']['plan_sha256'] = 'a' * 64
    elif damage == 'shard':
        manifest['owner']['shard'] = 1
    elif damage == 'provider':
        key = 'outputs/' + OS.output_file_name(LABELS.pair_id, 'rz-diff')
        manifest['files'][key.replace('rz-diff', 'ghidriff')] = manifest['files'].pop(key)
    else:
        manifest['reports'] = ['b' * 64]
    manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
    path.write_bytes(canonical_json(manifest))
    assert merge(source, tmp_path / 'merged') == S.USAGE
    assert not (tmp_path / 'merged').exists()


@pytest.mark.parametrize('field,value', [('version', 'forged-version'), ('symbols', 'visible'),
                                        ('older_sha256', 'b' * 64), ('newer_sha256', 'c' * 64)])
def test_rehashed_transfer_cannot_override_managed_output_ownership(built, tmp_path, field, value):
    _doc, source, _ = built()
    bundle = source / 'training' / 'shard-0'
    credits = bundle / 'outputs' / OS.CREDIT_FILE
    document = json.loads(credits.read_bytes())
    document['outputs'][0][field] = value
    credits.write_bytes(canonical_json(document))
    path = bundle / TA.MANIFEST
    manifest = json.loads(path.read_bytes())
    manifest['files']['outputs/' + OS.CREDIT_FILE] = hashlib.sha256(credits.read_bytes()).hexdigest()
    manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
    path.write_bytes(canonical_json(manifest))
    assert merge(source, tmp_path / 'merged') == S.USAGE
    assert not (tmp_path / 'merged').exists()


def test_aggregate_credit_limit_is_fail_closed_and_preserves_shard_diagnostics(built, tmp_path, monkeypatch):
    doc, source, _ = built()
    before = (source / 'shard-0.json').read_bytes()
    real_finalize = OS.OutputStore.finalize

    def bounded_finalize(store, reports):
        monkeypatch.setattr(OS.RS, 'MAX_OUTPUT_BYTES', 100)
        return real_finalize(store, reports)
    monkeypatch.setattr(OS.OutputStore, 'finalize', bounded_finalize)
    out = tmp_path / 'merged'
    assert merge(source, out) == S.USAGE
    assert (source / 'shard-0.json').read_bytes() == before
    assert not (out / 'training' / TA.MANIFEST).exists()
    assert (out / 'training' / 'labels' / TA.pair_name(LABELS.pair_id)).exists()
    assert (out / 'training' / 'reports' / (doc['reports'][0]['report_sha256'] + '.json')).exists()


def test_source_report_must_belong_to_requested_provider(built):
    def runner(argv, timeout, env):
        result = built.runner(argv, timeout, env)
        if argv[3] == 'evaluate':
            summary = json.loads(result[1])
            report_path = Path(summary['report'])
            doc = json.loads(report_path.read_bytes())
            doc['engines'][0]['engine'] = 'ghidriff'
            doc['report_sha256'] = digest(doc, 'report_sha256')
            report_path.write_bytes(C.dump_json(doc))
        return result
    doc, source, _ = built(modify_runner=runner)
    assert doc['cases'][-1]['status'] == 'failed'
    assert not (source / 'training' / 'shard-0' / TA.MANIFEST).exists()


def test_deep_malformed_manifest_is_structured_cli_refusal(built, tmp_path):
    _doc, source, _ = built()
    (source / 'training' / 'shard-0' / TA.MANIFEST).write_bytes(b'[' * 10000 + b'0' + b']' * 10000)
    assert merge(source, tmp_path / 'merged') == S.USAGE
    assert not (tmp_path / 'merged').exists()


def test_deep_malformed_report_preserves_failed_shard_diagnostic(built):
    def runner(argv, timeout, env):
        result = built.runner(argv, timeout, env)
        if argv[3] == 'evaluate':
            summary = json.loads(result[1])
            Path(summary['report']).write_bytes(b'[' * 10000 + b'0' + b']' * 10000)
        return result
    doc, source, _ = built(modify_runner=runner)
    assert doc['cases'][-1]['id'] == 'transfer:training'
    assert doc['cases'][-1]['status'] == 'failed'
    assert (source / 'shard-0.json').exists()
    assert not (source / 'training' / 'shard-0' / TA.MANIFEST).exists()


def test_legacy_diagnostic_without_case_map_is_structured_transfer_refusal(built, tmp_path):
    doc, source, _ = built()
    doc.pop('pair_cases')
    doc['shard_sha256'] = digest(doc, 'shard_sha256')
    (source / 'shard-0.json').write_bytes(canonical_json(doc))
    assert merge(source, tmp_path / 'merged') == S.USAGE
    assert not (tmp_path / 'merged').exists()


@pytest.mark.parametrize('side', ['source', 'target'])
def test_actual_merge_refuses_link_before_dotdot(built, tmp_path, side):
    import shutil

    _doc, source, _ = built()
    external = tmp_path / 'external'
    (external / 'child').mkdir(parents=True)
    link = tmp_path / 'linked'
    try:
        link.symlink_to(external / 'child', target_is_directory=True)
    except OSError:
        pytest.skip('native symlink creation unavailable; injected reparse controls remain mandatory')
    if side == 'source':
        shutil.copytree(source, external / 'shards')
        source = link / '..' / 'shards'
        out = tmp_path / 'merged'
    else:
        out = link / '..' / 'merged'
    assert merge(source, out) == S.USAGE
    assert not (tmp_path / 'merged').exists()
    assert not (external / 'merged').exists()


def test_known_aggregate_credit_limit_is_checked_before_transfer_destination(built, tmp_path, monkeypatch):
    _doc, source, _ = built()
    before = (source / 'shard-0.json').read_bytes()
    checked = []
    original = OS.preflight_credit_manifest

    def small_budget(reports, output_records):
        checked.append(output_records)
        monkeypatch.setattr(OS.RS, 'MAX_CREDIT_BYTES', 100)
        return original(reports, output_records)

    monkeypatch.setattr(OS, 'preflight_credit_manifest', small_budget)
    out = tmp_path / 'merged'
    assert merge(source, out) == S.USAGE
    assert len(checked) == 1
    assert checked[0][0]['pair_id'] == LABELS.pair_id
    assert checked[0][0]['version'] == 'constructed-control'
    assert set(checked[0][0]) == {'pair_id', 'engine', 'output_sha256', 'older_sha256',
                               'newer_sha256', 'symbols', 'version'}
    assert not out.exists(), 'known aggregate metadata overflow created partial destination evidence'
    assert (source / 'shard-0.json').read_bytes() == before
