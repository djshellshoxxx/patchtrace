"""Independent real managed-transfer/consumer controls for ee2210bb; authored evidence only."""
import hashlib
import json
import shutil

import pytest
from test_tier_r_training_artifacts import exported, transfer
from test_tier_r_training_artifacts import produced as produced
from test_tier_r_training_handoff import batch as batch
from test_tier_r_training_handoff import consolidate
from test_tier_r_training_workflow import trained as trained

from tools.calibration import train
from tools.calibration.common import canonical_json, digest
from tools.calibration.tier_r import shard


def test_consumer_works_from_a_fresh_unicode_path_after_original_production_is_removed(
        batch, tmp_path, tmp_path_factory, capsys):
    consolidate(batch)
    consumer = tmp_path_factory.mktemp('independent-consumer')
    relocated = consumer / 'retained evidence Ω'
    shutil.copytree(batch[2], relocated)
    report, provenance = batch[3:]
    before = {p.relative_to(relocated): p.read_bytes() for p in relocated.rglob('*.json')}
    shutil.rmtree(tmp_path)
    assert transfer().verify_merged_artifacts(relocated, report, provenance)
    rows = train.build_from_labels(relocated / 'labels', relocated / 'outputs')
    assert len(rows) == 1
    out = consumer / 'fresh result'
    code = train.main(['run', '--labels', str(relocated / 'labels'), '--outputs', str(relocated / 'outputs'),
                       '--smoke', '--out', str(out)])
    summary = json.loads(capsys.readouterr().out)
    result = transfer().verify_smoke_result(summary, json.loads((out / 'report.json').read_bytes()), code)
    assert result['status'] == 'insufficient-data' and result['exit_code'] == 1
    assert {p.relative_to(relocated): p.read_bytes() for p in relocated.rglob('*.json')} == before


def test_reformatting_output_cannot_be_admitted_by_rehashing_only_transport(produced):
    manifest, destination = exported(produced)
    entry = next(item for item in manifest['files'] if item['path'].endswith('.rz-diff.json'))
    path = destination / entry['path']
    original = path.read_bytes()
    changed = canonical_json(json.loads(original)) + b'\n\n'
    assert changed != original
    path.write_bytes(changed)
    entry.update(size=len(changed), sha256=hashlib.sha256(changed).hexdigest())
    manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
    (destination / transfer().MANIFEST).write_bytes(canonical_json(manifest))
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_training_artifacts(produced[2], destination)


@pytest.mark.parametrize('alias_parent', [False, True])
def test_consumer_refuses_a_linked_artifact_root_or_ancestor(batch, tmp_path, alias_parent):
    consolidate(batch)
    alias = tmp_path / 'alias'
    alias.symlink_to(batch[2].parent if alias_parent else batch[2], target_is_directory=True)
    path = alias / batch[2].name if alias_parent else alias
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_merged_artifacts(path, batch[3], batch[4])


@pytest.mark.parametrize('code', [-9, 2, 3, 137, True])
def test_other_process_outcomes_cannot_be_reclassified_as_lineage_insufficiency(trained, code):
    summary, report, _original = trained
    with pytest.raises(transfer().ArtifactError):
        transfer().verify_smoke_result(summary, report, code)


def test_verify_result_cli_refuses_a_valid_report_with_mismatched_actual_exit(trained, tmp_path, capsys):
    summary, report, _code = trained
    summary_path, report_path = tmp_path / 'summary.json', tmp_path / 'report.json'
    summary_path.write_bytes(canonical_json(summary))
    report_path.write_bytes(canonical_json(report))
    assert shard.main(['verify-training-result', '--summary', str(summary_path), '--report', str(report_path),
                       '--exit-code', '137']) == shard.FINDINGS
    captured = capsys.readouterr()
    assert 'training artifact refused' not in captured.out and 'training result' in captured.err
