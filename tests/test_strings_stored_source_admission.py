"""Stored Strings results stay bound to current artifacts and original cache provenance.

Only synthetic PE data and an authored fake FLOSS program are used. Analyzed
files are never executed; these tests do not qualify native FLOSS behavior.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from test_ui_strings_run import fake_floss, make_project, tool_store

from patchtrace.intelligence.tools import runner
from patchtrace.intelligence.tools.common import evidence_entry_id
from patchtrace.strings.cli import compute
from patchtrace.strings.contracts import StringsError


@pytest.fixture
def produced(tmp_path):
    with make_project(tmp_path, 'floss-static') as service:
        request = runner.RunRequest(
            tuple(runner.ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                  for a in service.project.artifacts),
            runner.Setup(floss=fake_floss(tmp_path, service)), profile='context', engines=('floss',))
        store = tool_store(service)
        first = runner.run_tools(request, store, threading.Event())
        assert len(first) == 2 and all(job.evidence is not None and not job.run.cache_hit for job in first)
        yield service, store, request, first


def args(source='auto'):
    return SimpleNamespace(source=source, anchors=None, min_length=4)


def test_orientation_swap_never_reuses_evidence_of_the_previous_artifact(produced):
    service, _store, _request, _first = produced
    assert set(compute(args(), service, threading.Event()).sources.values()) == {'floss'}
    service.swap_orientation()
    expected = {a.side: a.sha256 for a in service.project.artifacts}
    swapped = compute(args(), service, threading.Event())
    assert {side: table.basis.artifact_sha256 for side, table in swapped.tables.items()} == expected
    assert set(swapped.sources.values()) == {'builtin-scan'}
    service.swap_orientation()
    assert set(compute(args(), service, threading.Event()).sources.values()) == {'floss'}


def test_explicit_floss_refuses_pre_swap_results(produced):
    service, _store, _request, _first = produced
    service.swap_orientation()
    with pytest.raises(StringsError, match='no stored FLOSS evidence'):
        compute(args('floss'), service, threading.Event())


@pytest.mark.parametrize('source', ['auto', 'floss'])
def test_cached_results_keep_the_original_source_and_raw_provenance(produced, source):
    service, store, request, first = produced
    before = compute(args(source), service, threading.Event())
    cached = runner.run_tools(request, store, threading.Event())
    assert all(job.run.cache_hit and job.run.raw_sidecar is None and job.run.stdout_digest is None
               for job in cached)
    after = compute(args(source), service, threading.Event())
    assert after.sources == before.sources == {'older': 'floss', 'newer': 'floss'}
    for side in ('older', 'newer'):
        original = next(job for job in first if job.run.side == side)
        assert after.tables[side].basis.parts == before.tables[side].basis.parts
        part = after.tables[side].basis.parts[0]
        assert part.raw_sha256 == original.run.stdout_digest
        assert part.executable_sha256 == original.run.manifest.executable_sha256


@pytest.mark.parametrize('kind', ['run', 'evidence'])
@pytest.mark.parametrize('field', ['stale', 'project_id'])
def test_selected_metadata_refusal_preserves_auto_fallback_and_explicit_refusal(produced, kind, field):
    service, _store, _request, first = produced
    assert set(compute(args(), service, threading.Event()).sources.values()) == {'floss'}
    job = next(job for job in first if job.run.side == 'newer')
    identity = job.run.run_id if kind == 'run' else evidence_entry_id(job.evidence)
    if field == 'stale':
        service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (identity,))
    else:
        service.store.connection.execute('UPDATE enrichment_entries SET project_id=? WHERE id=?',
                                         ('authored-other-project', identity))
    after = compute(args(), service, threading.Event())
    assert after.sources == {'older': 'floss', 'newer': 'builtin-scan'}
    with pytest.raises(StringsError, match='no stored FLOSS evidence for the newer artifact'):
        compute(args('floss'), service, threading.Event())
