"""Hermetic real evaluator/credit/CLI handoff; authored providers, no native acceptance."""
from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from test_tier_r_output_persistence import LABELS, provider
from test_tier_r_training_artifacts import shard_document, transfer

from tools.calibration import train
from tools.calibration.common import canonical_json, digest
from tools.calibration.tier_r import cli
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import shard as S


@pytest.fixture
def batch(tmp_path):
    root = tmp_path / 'downloaded'
    root.mkdir()
    labels = tmp_path / 'labels'
    labels.mkdir()
    (labels / f'{LABELS.pair_id}.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    docs = []
    for index, engine in enumerate(('rz-diff', 'ghidriff')):
        outputs = tmp_path / f'run-{index}'
        report = E.evaluate([LABELS], [provider(engine)], output_dir=outputs, b_count=20)
        doc = shard_document(report, index, 2)
        doc['engines'] = [engine]
        doc['cases'][0]['id'] = f'evaluate:{engine}'
        doc['shard_sha256'] = digest(doc, 'shard_sha256')
        transfer().export_training_artifacts(doc, labels, [outputs], root / f'tier-r-training-{index}')
        docs.append(doc)
    report, provenance = S.merge(docs)
    return docs, root, tmp_path / 'merged-training', report, provenance


def consolidate(batch):
    docs, root, destination, report, provenance = batch
    return transfer().merge_training_artifacts(docs, root, destination, report, provenance)


def test_complete_set_is_recredited_from_original_reports_and_reaches_training(batch):
    docs, root, destination, report, provenance = batch
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*.json')}
    manifest = consolidate(batch)
    assert transfer().verify_merged_artifacts(destination, report, provenance) == manifest
    assert manifest['aggregate_sha256'] == report['report_sha256']
    assert manifest['merge_sha256'] == provenance['merge_sha256']
    assert [item['shard'] for item in manifest['shards']] == [0, 1]
    credit = json.loads((destination / 'outputs' / OS.CREDIT_FILE).read_bytes())
    assert credit['reports'] == [doc['reports'][0] for doc in docs]
    assert report not in credit['reports']
    assert len(train.load_outputs(destination / 'outputs', allow_legacy=False)) == 2
    rows = train.build_from_labels(destination / 'labels', destination / 'outputs')
    assert len(rows) == 1 and rows[0].label_digest == LABELS.digest_sha256
    assert len(list((destination / 'labels').iterdir())) == 1
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob('*.json')} == before


def test_second_merge_is_identical_even_when_input_documents_are_reversed(batch):
    docs, root, destination, report, provenance = batch
    first = consolidate(batch)
    second_root = destination.with_name('again')
    second = transfer().merge_training_artifacts(list(reversed(docs)), root, second_root, report, provenance)
    assert first == second
    assert {p.relative_to(destination): p.read_bytes() for p in destination.rglob('*.json')} == {
        p.relative_to(second_root): p.read_bytes() for p in second_root.rglob('*.json')}


@pytest.mark.parametrize('damage', ['missing', 'extra', 'flat', 'foreign', 'output', 'label-format', 'marker'])
def test_bad_download_set_cannot_create_consolidated_credit(batch, damage):
    docs, root, destination, _report, _provenance = batch
    second = root / 'tier-r-training-1'
    if damage == 'missing':
        second.rename(root.parent / 'withheld')
    elif damage == 'extra':
        (root / 'tier-r-training-2').mkdir()
    elif damage == 'flat':
        (root / 'tier-r-training-0').rename(root.parent / 'flat-data')
        for path in (root.parent / 'flat-data').iterdir():
            path.rename(root / path.name)
    elif damage == 'foreign':
        path = second / transfer().MANIFEST
        document = json.loads(path.read_bytes())
        document['shards'][0]['plan_sha256'] = 'f' * 64
        document['manifest_sha256'] = digest(document, 'manifest_sha256')
        path.write_bytes(canonical_json(document))
    elif damage == 'output':
        (second / 'outputs' / OS.output_file_name(LABELS.pair_id, 'ghidriff')).write_bytes(b'{}')
    elif damage == 'marker':
        (second / 'outputs' / OS.MANAGED_MARKER).unlink()
    else:
        # A valid separately published artifact can still conflict with the exact
        # label bytes owned by another engine shard, despite the same model digest.
        path = second / 'labels' / f'{LABELS.pair_id}.json'
        raw = canonical_json(json.loads(path.read_bytes()))
        assert raw != path.read_bytes()
        path.write_bytes(raw)
        manifest = json.loads((second / transfer().MANIFEST).read_bytes())
        ref = next(item for item in manifest['files'] if item['path'].startswith('labels/'))
        ref.update(size=len(raw), sha256=transfer()._hash(raw))
        manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
        (second / transfer().MANIFEST).write_bytes(canonical_json(manifest))
        assert transfer().verify_training_artifacts(docs[1], second)
    with pytest.raises(transfer().ArtifactError):
        consolidate(batch)
    assert not destination.exists()


@pytest.mark.parametrize('damage', ['missing-shard', 'duplicate-shard', 'foreign-plan', 'failed', 'unknown-status',
                                     'aggregate', 'provenance'])
def test_complete_origin_and_merge_identity_are_required(batch, damage):
    docs, root, destination, report, provenance = batch
    docs, report, provenance = copy.deepcopy((docs, report, provenance))
    if damage == 'missing-shard':
        docs.pop()
    elif damage == 'duplicate-shard':
        docs[1] = docs[0]
    elif damage == 'foreign-plan':
        docs[1]['plan_sha256'] = 'f' * 64
        docs[1]['shard_sha256'] = digest(docs[1], 'shard_sha256')
    elif damage in ('failed', 'unknown-status'):
        docs[1]['cases'][0]['status'] = 'failed' if damage == 'failed' else 'error'
        docs[1]['shard_sha256'] = digest(docs[1], 'shard_sha256')
    elif damage == 'aggregate':
        report['notes'].append('unrelated aggregate')
        report['report_sha256'] = digest(report, 'report_sha256')
    else:
        provenance['seed'] += 1
        provenance['merge_sha256'] = digest(provenance, 'merge_sha256')
    with pytest.raises(transfer().ArtifactError):
        transfer().merge_training_artifacts(docs, root, destination, report, provenance)
    assert not destination.exists()


def test_complete_batch_budget_is_checked_before_reading_any_output_body(batch, monkeypatch):
    module = transfer()
    total = sum(item['size'] for folder in batch[1].iterdir()
                for item in json.loads((folder / module.MANIFEST).read_bytes())['files'])
    monkeypatch.setattr(module, 'MAX_BATCH_BYTES', total - 1)
    monkeypatch.setattr(OS, 'read_credited_outputs', lambda *_: pytest.fail('output read before complete batch budget'))
    with pytest.raises(module.ArtifactError):
        consolidate(batch)
    assert not batch[2].exists()


def test_valid_label_change_between_metadata_and_semantic_admission_is_refused(batch, monkeypatch):
    module = transfer()
    original = module._admit

    def change_before_admission(reports, labels, outputs, **kwargs):
        path = Path(labels) / f'{LABELS.pair_id}.json'
        raw = path.read_bytes()
        path.write_bytes(raw + b' ')
        return original(reports, labels, outputs, **kwargs)

    monkeypatch.setattr(module, '_admit', change_before_admission)
    with pytest.raises(module.ArtifactError):
        consolidate(batch)
    assert not batch[2].exists()


@pytest.mark.parametrize('damage', ['missing-marker', 'extra-label', 'foreign-report', 'foreign-provenance',
                                     'report-ownership', 'aggregate-content'])
def test_consumer_rechecks_completed_consolidation_before_training(batch, damage):
    _docs, _root, destination, report, provenance = batch
    consolidate(batch)
    report, provenance = copy.deepcopy((report, provenance))
    if damage == 'missing-marker':
        (destination / 'outputs' / OS.MANAGED_MARKER).unlink()
    elif damage == 'extra-label':
        (destination / 'labels' / 'unlisted.json').write_bytes(b'{}')
    elif damage == 'foreign-report':
        report['notes'].append('foreign report')
        report['report_sha256'] = digest(report, 'report_sha256')
    elif damage == 'foreign-provenance':
        provenance['shards'][0]['shard_sha256'] = 'f' * 64
        provenance['merge_sha256'] = digest(provenance, 'merge_sha256')
    else:
        path = destination / transfer().MANIFEST
        manifest = json.loads(path.read_bytes())
        if damage == 'report-ownership':
            manifest['shards'][1]['reports'] = manifest['shards'][0]['reports']
        else:
            report['notes'].append('internally rehashed but unrelated to source reports')
            report['report_sha256'] = digest(report, 'report_sha256')
            provenance['report_sha256'] = report['report_sha256']
            provenance['merge_sha256'] = digest(provenance, 'merge_sha256')
            manifest.update(aggregate_sha256=report['report_sha256'], merge_sha256=provenance['merge_sha256'])
        manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
        path.write_bytes(canonical_json(manifest))
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_merged_artifacts(destination, report, provenance)


def authored_plan():
    document = {'contract': S.PLAN_CONTRACT, 'seed': 1, 'subset': 'suites', 'engines': ['rz-diff'], 'of': 1,
                'cases_total': 1, 'shards': [{'shard': 0, 'cases': ['suite:_template/tiny']}]}
    document['plan_sha256'] = digest(document, 'plan_sha256')
    return document


def evaluator_runner(monkeypatch, *, case_status='findings', damage=None, scopes=None):
    monkeypatch.setattr(E, 'default_providers', lambda *_a, **_kw: [provider()])

    def run(argv, _timeout, env):
        scope = Path(env['PATCHTRACE_CALIB_ROOT'])
        if scopes is not None:
            scopes.add(scope)
        store = scope / 'known-answer'
        if argv[3] != 'evaluate':
            labels = store / 'labels'
            labels.mkdir(parents=True, exist_ok=True)
            (labels / f'{LABELS.pair_id}.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
            return (1 if case_status == 'findings' else 3), json.dumps({'status': case_status}), None
        stream = io.StringIO()
        with redirect_stdout(stream):
            rc = cli.main([*argv[3:], '--store', str(store)])
        summary = json.loads(stream.getvalue())
        if damage == 'credit':
            (Path(summary['outputs']) / OS.CREDIT_FILE).unlink()
        elif damage == 'reported-output':
            summary['outputs'] = str(scope.parent / 'foreign-output')
        return rc, json.dumps(summary), None

    return run


def test_shard_exports_actual_cli_outputs_before_temporary_scratch_is_removed(tmp_path, monkeypatch):
    scopes = set()
    destination = tmp_path / 'training'
    document = S.run_shard(authored_plan(), 0, runner=evaluator_runner(monkeypatch, scopes=scopes),
                           artifacts_dir=destination)
    assert document['cases'][0]['status'] == 'findings'  # Valid build findings remain non-failing.
    assert transfer().verify_training_artifacts(document, destination)
    assert scopes and all(not scope.exists() for scope in scopes)
    assert all('functions' not in item for item in document['labels'])
    assert len(train.load_outputs(destination / 'outputs', allow_legacy=False)) == 1


@pytest.mark.parametrize('damage', ['credit', 'reported-output'])
def test_requested_collection_failure_is_a_failed_case_and_cli_exit_one(tmp_path, monkeypatch, damage):
    monkeypatch.setattr(S, 'default_runner', evaluator_runner(monkeypatch, damage=damage))
    plan_path = tmp_path / 'plan.json'
    plan_path.write_bytes(canonical_json(authored_plan()))
    out = tmp_path / 'out'
    assert S.main(['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(out),
                   '--collect-artifacts']) == S.FINDINGS
    doc = json.loads((out / 'shard-0.json').read_bytes())
    failed = next(case for case in doc['cases'] if case['id'] == 'evaluate:artifact-transfer')
    assert failed['status'] == 'failed'
    assert doc['shard_sha256'] == digest(doc, 'shard_sha256')
    assert 'evaluate:artifact-transfer' in S.merge([doc])[1]['failing_cases']
    assert not (out / 'training' / transfer().MANIFEST).exists()


def test_blocked_case_stays_blocked_and_cannot_export(tmp_path, monkeypatch):
    destination = tmp_path / 'training'
    doc = S.run_shard(authored_plan(), 0, runner=evaluator_runner(monkeypatch, case_status='blocked'),
                      artifacts_dir=destination)
    assert doc['cases'][0]['status'] == 'blocked'
    assert not any(case['id'] == 'evaluate:artifact-transfer' for case in doc['cases'])
    assert not destination.exists()


def test_missing_report_from_one_requested_engine_cannot_be_hidden_by_another(tmp_path, monkeypatch):
    plan = authored_plan()
    plan['engines'] = ['bindiff', 'rz-diff']
    plan['plan_sha256'] = digest(plan, 'plan_sha256')
    actual = evaluator_runner(monkeypatch)

    def runner(argv, timeout, env):
        if argv[3] == 'evaluate' and argv[5] == 'bindiff':
            return 0, '', None
        return actual(argv, timeout, env)

    destination = tmp_path / 'training'
    doc = S.run_shard(plan, 0, runner=runner, artifacts_dir=destination)
    assert any(case['id'] == 'evaluate:artifact-transfer' and case['status'] == 'failed' for case in doc['cases'])
    assert not destination.exists()


@pytest.mark.parametrize('damage', ['duplicate-member', 'byte-cap', 'linked-file'])
def test_shard_input_admission_refuses_ambiguous_unbounded_or_linked_documents(batch, tmp_path, monkeypatch, damage):
    shards = tmp_path / 'shards'
    paths = [S.write_shard(doc, shards) for doc in batch[0]]
    if damage == 'duplicate-member':
        raw = canonical_json(batch[0][0]).replace(b'"seed":1', b'"seed":999,"seed":1')
        paths[0].write_bytes(raw)
    elif damage == 'byte-cap':
        monkeypatch.setattr(S, 'MAX_SHARD_BYTES', paths[0].stat().st_size - 1)
    else:
        original = tmp_path / 'original.json'
        paths[0].rename(original)
        paths[0].symlink_to(original)
    with pytest.raises(S.ShardError):
        S.load_shards(shards)


def test_merge_cli_refuses_bad_artifact_with_exit_one_and_retains_aggregate_diagnostics(batch, tmp_path):
    docs, root, _destination, _report, _provenance = batch
    shards = tmp_path / 'shards'
    for doc in docs:
        S.write_shard(doc, shards)
    (root / 'tier-r-training-1' / 'outputs' / OS.MANAGED_MARKER).unlink()
    out = tmp_path / 'merge-command'
    assert S.main(['merge', '--in', str(shards), '--artifacts', str(root), '--out', str(out)]) == S.FINDINGS
    assert (out / 'tier-r-aggregate.json').is_file() and (out / 'tier-r-merge.json').is_file()
    assert not (out / 'training' / transfer().MANIFEST).exists()
