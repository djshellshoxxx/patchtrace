"""Synthetic producer-boundary regressions; no native Ghidriff compatibility claim."""
from __future__ import annotations

import pytest

from patchtrace.models import AnalysisRun, Artifact, ComparisonProject
from patchtrace.normalization import normalize_ghidriff
from patchtrace.sample import sample_diff

RESERVED = ('upstream_similarity', 'diff_types', 'upstream_name', 'instructions_hash',
            'assembly_unavailable', 'upstream_one_to_many')


@pytest.fixture
def inputs():
    run = AnalysisRun(status='completed')
    project = ComparisonProject(name='p', runs=[run], artifacts=[
        Artifact(side='older', name='o.dll', sha256='a' * 64, size=1, relative_path='artifacts/o.bin'),
        Artifact(side='newer', name='n.dll', sha256='b' * 64, size=1, relative_path='artifacts/n.bin')])
    return sample_diff(project), project, run.id


@pytest.mark.parametrize('reserved', RESERVED)
@pytest.mark.parametrize('location', ['added', 'deleted', 'old', 'new'])
def test_reserved_function_metadata_rejected(inputs, reserved, location):
    raw, project, run_id = inputs
    if location in {'old', 'new'}:
        record = raw['functions']['modified'][0][location]
    else:
        record = raw['functions'][location][0]
    # Presence alone is forbidden, including null values that may otherwise look harmless.
    record[reserved] = None
    with pytest.raises(ValueError, match='PT-SCHEMA:.*PatchTrace-reserved metadata key'):
        normalize_ghidriff(raw, project, run_id)


def test_ordinary_metadata_and_derived_pair_claims_survive(inputs):
    raw, project, run_id = inputs
    pair = raw['functions']['modified'][0]
    pair['old']['producer_annotation'] = {'source': 'native', 'count': 3}
    pair['old']['instructions'] = 123
    result = normalize_ghidriff(raw, project, run_id)
    old = next(match for match in result if match.category == 'modified').older[0]
    assert old.metadata['producer_annotation'] == {'source': 'native', 'count': 3}
    assert old.metadata['instructions_hash'] == 123
    assert old.metadata['assembly_unavailable']
    assert old.metadata['upstream_name'] == pair['old']['name']
    assert old.metadata['upstream_similarity'] == pair['ratio']
    assert old.metadata['diff_types'] == pair['diff_type']


def test_planted_similarity_cannot_supply_missing_pair_ratio(inputs):
    raw, project, run_id = inputs
    pair = raw['functions']['modified'][0]
    pair['ratio'] = None
    pair['new']['upstream_similarity'] = 0.99
    with pytest.raises(ValueError, match='PT-SCHEMA:.*reserved metadata key upstream_similarity'):
        normalize_ghidriff(raw, project, run_id)


def test_rejected_import_preserves_source_and_committed_results(tmp_path):
    import json

    from patchtrace.persistence import safe_path
    from patchtrace.sample import synthetic_pe
    from patchtrace.service import ProjectService

    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    source = tmp_path / 'diff.json'
    with ProjectService.create(older, newer, 'p', tmp_path / 'project') as service:
        source.write_text(json.dumps(sample_diff(service.project)), encoding='utf-8')
        service.import_diff(source)
        before = service.project.model_dump()
        history = service.store.history()
        run = service.project.runs[-1]
        committed_raw = safe_path(service.root, run.raw_path)
        committed_bytes = committed_raw.read_bytes()
        raw = sample_diff(service.project)
        raw['functions']['modified'][0]['old']['upstream_similarity'] = 0.99
        rejected_bytes = json.dumps(raw, indent=2).encode('utf-8')
        source.write_bytes(rejected_bytes)
        with pytest.raises(ValueError, match='PT-SCHEMA:.*reserved metadata key upstream_similarity'):
            service.import_diff(source)
        assert source.read_bytes() == rejected_bytes
        assert service.project.model_dump() == before
        assert service.store.history() == history
        assert committed_raw.read_bytes() == committed_bytes
