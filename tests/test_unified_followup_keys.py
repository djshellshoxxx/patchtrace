"""Post-merge follow-up (final-audit engine round, finding p9): every input the worker reads is in the result key."""
from __future__ import annotations

import pytest
from unified_s0_fixtures import make_project

from patchtrace.unified import pipeline
from patchtrace.unified.pipeline import UnifiedOptions


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def _correct_a_pair(service):
    match = next(m for m in service.project.matches if m.category == 'modified' and m.older and m.newer)
    service.correct_match(match.id, [match.older[0].id], [], 'removed', 'analyst decision')


def test_a_correction_changes_the_result_key_even_when_the_manual_source_is_not_selected(project):
    """correct_match reshapes the non-manual matches the worker reads (names, ids, modified edges); a result made
    before it must not be served from the cache, and a refresh must not fail with result-drift."""
    options = UnifiedOptions(isolate=False, sources=('ghidriff',))
    first = pipeline.run_unified(project, options)
    _correct_a_pair(project)
    second = pipeline.run_unified(project, options)
    assert second.status != 'cached' and second.result_id != first.result_id
    refreshed = pipeline.run_unified(project, UnifiedOptions(isolate=False, sources=('ghidriff',), refresh=True))
    assert refreshed.result_id == second.result_id


def test_projects_without_corrections_keep_their_result_ids(project):
    from patchtrace.unified import keys
    plan = pipeline.make_plan(project, sources=('ghidriff',))
    assert plan.identity.manual_digest == keys.manual_digest([])
