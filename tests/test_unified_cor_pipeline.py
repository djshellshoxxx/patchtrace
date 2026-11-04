"""SPEC-31 pipeline audit `cor`: the isolated worker must be able to end by ITS OWN deadline (U7-06 partial result)
before the parent kills the process tree. Synthetic project; the child is stood in for by a stub runner."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from unified_s0_fixtures import make_project

from patchtrace.jobs import ProcessResult
from patchtrace.unified import exchange, pipeline, worker
from patchtrace.unified.pipeline import UnifiedOptions

GIB = 1024 ** 3


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def test_the_worker_deadline_comes_before_the_parents_kill_deadline(project):
    seen = {}

    def behaviour(argv, kwargs):
        start = argv.index('unified')
        request = exchange.read_request(Path(argv[start + 3]))
        seen.update(budget=request.budget_seconds, kill=kwargs['timeout_seconds'])
        return ProcessResult(worker.main(argv[start + 2:]), '', None, '')

    def runner(argv, **kwargs):
        return behaviour(list(argv), kwargs)

    options = UnifiedOptions(isolate=True, runner=runner, total_ram_bytes=8 * GIB, timeout_s=120)
    pipeline.run_unified(project, options)
    # the child's clock starts after the interpreter booted and the inputs were read, so an equal budget would
    # always lose to the parent's kill and the partial result of a spent deadline could never be written
    assert seen['budget'] < seen['kill'] == 120
    assert seen['kill'] - seen['budget'] >= 10


def staging(service) -> list[str]:
    parent = service.root / 'runs' / service.project.runs[-1].id / 'unified' / 'results'
    return sorted(p.name for p in parent.iterdir()) if parent.is_dir() else []


@pytest.mark.parametrize('interrupt', [KeyboardInterrupt, SystemExit])
def test_an_interrupt_during_execute_leaves_no_staging_or_private_directory(project, monkeypatch, interrupt):
    before = {p.name for p in Path(tempfile.gettempdir()).glob('pt-unified-*')}

    def boom(*args, **kwargs):
        raise interrupt()
    monkeypatch.setattr(pipeline, 'run_request', boom)
    request = pipeline.prepare(project, UnifiedOptions(isolate=False))
    with pytest.raises(interrupt):
        pipeline.execute(request)
    assert staging(project) == []
    assert {p.name for p in Path(tempfile.gettempdir()).glob('pt-unified-*')} == before


def test_a_raw_output_the_worker_cannot_use_does_not_make_every_result_stale(tmp_path):
    """The plan classifies the raw output like the worker (`load_raw`), so the id it predicts is the id published."""
    from patchtrace.sample import create_sample
    service = create_sample(tmp_path / 'sample')
    try:
        first = pipeline.run_unified(service, UnifiedOptions(isolate=False, use_ir=False))
        loaded = pipeline.load_current(service, pipeline.make_plan(service, use_ir=False))
        assert loaded.state == 'current' and loaded.manifest.result_id == first.result_id
        again = pipeline.run_unified(service, UnifiedOptions(isolate=False, use_ir=False))
        assert again.status == 'cached' and again.result_id == first.result_id
    finally:
        service.close()
