"""H8: one project-owned copy of the raw Ghidriff output (SPEC-07h)."""
import json
from uuid import uuid4

import pytest

from patchtrace.models import AnalysisRun
from patchtrace.sample import sample_diff, synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    svc = ProjectService.create(older, newer, 'Comparison', tmp_path / 'project')
    yield svc
    svc.close()


def _backend_style(service):
    run_id = str(uuid4())
    path = service.root / 'runs' / run_id / 'raw' / 'json' / 'result.ghidriff.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(sample_diff(service.project)), encoding='utf-8')
    run = AnalysisRun(id=run_id, status='completed', raw_path=path.relative_to(service.root).as_posix(),
                      raw_sha256='0' * 64)
    return path, run


def _copies(service, run_id):
    return sorted((service.root / 'runs' / run_id).rglob('*.ghidriff.json'))


def test_backend_output_is_reused_in_place(service):
    path, run = _backend_style(service)
    service.apply_analysis(path, run)
    stored = service.project.runs[-1]
    assert stored.raw_path == path.relative_to(service.root).as_posix()
    assert _copies(service, run.id) == [path]
    assert stored.raw_sha256 != '0' * 64
    service.close()
    with ProjectService.open(service.root) as reopened:  # raw hash still verifies
        assert reopened.project.runs[-1].raw_path == stored.raw_path


def test_import_from_outside_copies_once_and_reprepare_is_idempotent(service, tmp_path):
    outside = tmp_path / 'outside.ghidriff.json'
    outside.write_text(json.dumps(sample_diff(service.project)), encoding='utf-8')
    prepared = service.prepare_import(outside)
    assert len(_copies(service, prepared.run.id)) == 1
    service.apply_import(prepared)
    assert service.project.runs[-1].raw_path == f'runs/{prepared.run.id}/raw/result.ghidriff.json'


def test_discard_import_removes_staged_copy_but_not_backend_output(service, tmp_path):
    outside = tmp_path / 'outside.ghidriff.json'
    outside.write_text(json.dumps(sample_diff(service.project)), encoding='utf-8')
    prepared = service.prepare_import(outside)
    assert len(_copies(service, prepared.run.id)) == 1
    service.discard_import(prepared)
    assert _copies(service, prepared.run.id) == []
    path, run = _backend_style(service)
    discarded = service.prepare_analysis(path, run)
    service.discard_import(discarded)
    assert path.is_file()
