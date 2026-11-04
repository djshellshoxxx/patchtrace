"""SPEC-31 pipeline audit `cor`: the isolated worker must be able to end by ITS OWN deadline (U7-06 partial result)
before the parent kills the process tree. Synthetic project; the child is stood in for by a stub runner."""
from __future__ import annotations

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
