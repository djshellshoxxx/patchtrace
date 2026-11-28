"""Authored evaluator -> exact managed transport -> actual training reader; no native claims."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from test_tier_r_output_persistence import LABELS, provider, store_labels

from tools.calibration import train
from tools.calibration.common import canonical_json, digest
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import shard


def transfer():
    return importlib.import_module('tools.calibration.tier_r.training_artifacts')


def shard_document(report, index=0, count=1):
    document = {'contract': shard.SHARD_CONTRACT, 'shard': index, 'of': count, 'seed': 1,
                'plan_sha256': 'a' * 64, 'subset': 'smoke', 'engines': ['rz-diff'],
                'cases': [{'id': 'evaluate:rz-diff', 'status': 'ok', 'reason': None, 'digest': None}],
                'labels': [shard._label_meta(LABELS.model_dump(mode='json'))], 'features': [], 'reports': [report]}
    document['shard_sha256'] = digest(document, 'shard_sha256')
    return document


@pytest.fixture
def produced(tmp_path):
    store = store_labels(tmp_path)
    output = store / 'outputs' / 'actual-evaluator-run'
    report = E.evaluate([LABELS], [provider()], output_dir=output, b_count=20)
    assert OS.read_credited_outputs(output)
    return store, output, shard_document(report), tmp_path / 'artifact'


def exported(produced):
    store, output, document, destination = produced
    manifest = transfer().export_training_artifacts(document, store / 'labels', [output], destination)
    return manifest, destination


def test_exact_evaluator_bytes_and_complete_credit_reach_actual_training_reader(produced):
    store, output, document, destination = produced
    before = {p.relative_to(store): p.read_bytes() for p in store.rglob('*.json')}
    manifest, _ = exported(produced)
    assert transfer().verify_training_artifacts(document, destination) == manifest
    label_name = f'{LABELS.pair_id}.json'
    output_name = OS.output_file_name(LABELS.pair_id, 'rz-diff')
    assert (destination / 'labels' / label_name).read_bytes() == (store / 'labels' / label_name).read_bytes()
    assert (destination / 'outputs' / output_name).read_bytes() == (output / output_name).read_bytes()
    assert all((destination / 'outputs' / name).is_file() for name in OS.MANAGED_FILES)
    assert len(train.load_outputs(destination / 'outputs', allow_legacy=False)) == 1
    rows = train.build_from_labels(destination / 'labels', destination / 'outputs')
    assert len(rows) == 1 and rows[0].label_digest == LABELS.digest_sha256
    assert {p.relative_to(store): p.read_bytes() for p in store.rglob('*.json')} == before
    assert all(p.suffix == '.json' for p in destination.rglob('*') if p.is_file())


@pytest.mark.parametrize('missing', [OS.MANAGED_MARKER, OS.CREDIT_FILE])
def test_transfer_cannot_infer_credit_from_a_loose_output_folder(produced, missing):
    _store, output, _document, destination = produced
    (output / missing).unlink()
    with pytest.raises(transfer().ArtifactError):
        exported(produced)
    assert not destination.exists()


@pytest.mark.parametrize('failure', [OS.COMPLETION_FILE, OS.FAILURE_FILE, OS.UNCREDITED_REPORT])
def test_incomplete_or_failed_run_never_becomes_a_completed_artifact(produced, failure):
    _store, output, _document, destination = produced
    (output / failure).write_bytes(b'{}')
    with pytest.raises(transfer().ArtifactError):
        exported(produced)
    assert not destination.exists()


@pytest.mark.parametrize('kind', ['label', 'output', 'credit'])
def test_changed_report_referenced_bytes_refuse_before_destination_creation(produced, kind):
    store, output, _document, destination = produced
    path = {'label': store / 'labels' / f'{LABELS.pair_id}.json',
            'output': output / OS.output_file_name(LABELS.pair_id, 'rz-diff'),
            'credit': output / OS.CREDIT_FILE}[kind]
    path.write_bytes(b'{}')
    with pytest.raises(transfer().ArtifactError):
        exported(produced)
    assert not destination.exists()


@pytest.mark.parametrize('kind', ['file', 'empty-directory', 'occupied-directory'])
def test_existing_destination_is_never_adopted_or_changed(produced, kind):
    _store, _output, _document, destination = produced
    if kind == 'file':
        destination.write_bytes(b'earlier evidence')
    else:
        destination.mkdir()
        if kind == 'occupied-directory':
            (destination / 'earlier.json').write_bytes(b'earlier evidence')
    with pytest.raises(transfer().ArtifactError):
        exported(produced)
    if kind == 'file':
        assert destination.read_bytes() == b'earlier evidence'
    elif kind == 'occupied-directory':
        assert (destination / 'earlier.json').read_bytes() == b'earlier evidence'
    else:
        assert not list(destination.iterdir())


@pytest.mark.parametrize('relative', ['image.dll', 'extra.json', 'outputs/unowned.json', 'labels/unowned.json'])
def test_unlisted_artifact_members_are_not_ignored(produced, relative):
    _manifest, destination = exported(produced)
    (destination / relative).write_bytes(b'{}')
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_training_artifacts(produced[2], destination)


@pytest.mark.parametrize('field,value', [('shard', 1), ('of', 2), ('plan_sha256', 'b' * 64)])
def test_foreign_shard_ownership_is_refused(produced, field, value):
    _manifest, destination = exported(produced)
    other = {**produced[2], field: value}
    other['shard_sha256'] = digest(other, 'shard_sha256')
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_training_artifacts(other, destination)


def test_aggregate_source_budget_refuses_before_loading_outputs(produced, monkeypatch):
    module = transfer()
    monkeypatch.setattr(module, 'MAX_ARTIFACT_BYTES', 1)
    monkeypatch.setattr(OS, 'read_credited_outputs', lambda *_a, **_k: pytest.fail('over-budget full output read'))
    with pytest.raises(module.ArtifactError):
        exported(produced)
    assert not produced[3].exists()


def test_manifest_duplicates_are_not_hidden_by_a_matching_digest(produced):
    _manifest, destination = exported(produced)
    path = destination / 'training-artifacts.json'
    original = path.read_text()
    path.write_text('{"contract":"invalid",' + original.lstrip()[1:])
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_training_artifacts(produced[2], destination)


def test_label_licence_is_required_even_when_all_report_digests_match(produced):
    store, output, _document, destination = produced
    value = LABELS.model_dump(mode='json')
    for side in ('older', 'newer'):
        value[side]['source']['license_spdx'] = 'GPL-3.0-only'
    labels = C.load_labels(canonical_json(C.finalize_labels(value)))
    (store / 'labels' / f'{labels.pair_id}.json').write_bytes(C.dump_json(labels.model_dump(mode='json')))
    different = output.with_name('unlicensed-run')
    report = E.evaluate([labels], [provider()], output_dir=different, b_count=20)
    with pytest.raises(transfer().ArtifactError):
        transfer().export_training_artifacts(shard_document(report), store / 'labels', [different], destination)
    assert not destination.exists()


@pytest.mark.parametrize('changed', ['label', 'valid-other-credit'])
def test_changed_destination_evidence_cannot_receive_a_completed_manifest(produced, monkeypatch, changed):
    real_finalize = OS.OutputStore.finalize

    def change_after_completion(store, reports):
        real_finalize(store, reports)
        if changed == 'label':
            path = store.folder.parent / 'labels' / f'{LABELS.pair_id}.json'
            path.write_bytes(b'{}')
        else:
            path = store.folder / OS.CREDIT_FILE
            document = json.loads(path.read_bytes())
            report = document['reports'][0]
            report['notes'].append('authored unrelated owner')
            report['report_sha256'] = digest(report, 'report_sha256')
            for row in document['outputs']:
                row['report_sha256'] = report['report_sha256']
            path.write_bytes(canonical_json(document))
            assert OS.read_credited_outputs(store.folder)  # Valid locally, foreign to the shard.

    monkeypatch.setattr(OS.OutputStore, 'finalize', change_after_completion)
    with pytest.raises(transfer().ArtifactError):
        exported(produced)
    assert not (produced[3] / 'training-artifacts.json').exists()


def test_manifest_capacity_is_preflighted_before_creating_a_destination(produced, monkeypatch):
    module = transfer()
    monkeypatch.setattr(module, 'MAX_MANIFEST_BYTES', 32)
    with pytest.raises(module.ArtifactError):
        exported(produced)
    assert not produced[3].exists()


@pytest.mark.parametrize('kind', ['leaf', 'ancestor'])
def test_linked_label_paths_are_refused_before_any_destination_write(produced, tmp_path, kind):
    store, _output, _document, destination = produced
    folder = store / 'labels'
    if kind == 'leaf':
        path = folder / f'{LABELS.pair_id}.json'
        original = tmp_path / 'saved-label.json'
    else:
        path = folder
        original = tmp_path / 'saved-labels'
    path.rename(original)
    path.symlink_to(original, target_is_directory=kind == 'ancestor')
    with pytest.raises(transfer().ArtifactError):
        exported(produced)
    assert not destination.exists()


def test_linked_destination_parent_is_refused_before_creating_any_child(produced, tmp_path):
    store, output, document, _destination = produced
    foreign = tmp_path / 'foreign-parent'
    foreign.mkdir()
    link = tmp_path / 'linked-parent'
    link.symlink_to(foreign, target_is_directory=True)
    with pytest.raises(transfer().ArtifactError):
        transfer().export_training_artifacts(document, store / 'labels', [output], link / 'nested' / 'training')
    assert not list(foreign.iterdir())


def test_both_managed_metadata_files_are_explicitly_bound(produced):
    manifest, destination = exported(produced)
    files = {row['path']: row for row in manifest['files']}
    for name in OS.MANAGED_FILES:
        path = 'outputs/' + name
        assert path in files and files[path]['size'] == (destination / path).stat().st_size
    (destination / 'outputs' / OS.MANAGED_MARKER).unlink()
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_training_artifacts(produced[2], destination)


def test_valid_managed_output_with_foreign_image_hashes_cannot_bind_to_labels(produced):
    store, output, source_shard, destination = produced
    original = output / OS.output_file_name(LABELS.pair_id, 'rz-diff')
    value = json.loads(original.read_bytes())
    value['older_sha256'] = 'f' * 64
    other = OS.OutputStore(output.with_name('foreign-images'))
    sha = other.write(LABELS.pair_id, 'rz-diff', value)
    report = json.loads(json.dumps(source_shard['reports'][0]))
    report['pairs'][0]['output_sha256'] = sha
    report['report_sha256'] = digest(report, 'report_sha256')
    other.finalize([report])
    assert OS.read_credited_outputs(other.folder)
    with pytest.raises(transfer().ArtifactError):
        transfer().export_training_artifacts(shard_document(report), store / 'labels', [other.folder], destination)
    assert not destination.exists()


def test_microsoft_metadata_is_not_transferred_even_with_valid_label_digest(produced):
    store, output, _document, destination = produced
    value = LABELS.model_dump(mode='json')
    value['project'] = 'Microsoft-authored-refusal-control'
    labels = C.load_labels(canonical_json(C.finalize_labels(value)))
    (store / 'labels' / f'{labels.pair_id}.json').write_bytes(C.dump_json(labels.model_dump(mode='json')))
    other = output.with_name('metadata-control')
    report = E.evaluate([labels], [provider()], output_dir=other, b_count=20)
    with pytest.raises(transfer().ArtifactError):
        transfer().export_training_artifacts(shard_document(report), store / 'labels', [other], destination)
    assert not destination.exists()


def test_transport_schema_is_generated_from_the_runtime_model():
    module = transfer()
    from tools.calibration.tier_r import schemas
    rendered = schemas.render()
    assert 'TrainingArtifacts.json' in rendered
    stored = Path('docs/schemas/corpus/TrainingArtifacts.json').read_text()
    assert stored == rendered['TrainingArtifacts.json']
    assert json.loads(stored)['properties']['contract']['const'] == module.CONTRACT
