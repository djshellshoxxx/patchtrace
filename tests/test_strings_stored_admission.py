"""Stored Strings sources through the real producer and store, with authored FLOSS only.

Inputs are synthetic PE bytes and are never executed. The fake FLOSS process
prints committed fixtures; these checks establish caller admission, not native
FLOSS compatibility. Cache records are produced by runner.run_tools itself.
"""
from __future__ import annotations

import hashlib
import json
import threading
from types import SimpleNamespace

import pytest
from test_ui_strings_run import fake_floss, make_project, tool_store

from patchtrace.intelligence.tools import runner
from patchtrace.intelligence.tools.common import evidence_entry_id
from patchtrace.strings import compose, copy
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


def _job(first, side='newer'):
    return next(job for job in first if job.run.side == side)


def _invalidate(service, row_id, field):
    if field == 'stale':
        service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row_id,))
    else:
        service.store.connection.execute(
            'UPDATE enrichment_entries SET project_id=? WHERE id=?', ('foreign-authored-project', row_id))


@pytest.mark.parametrize(('part', 'field', 'value'), [
    (0, 'engine', 'die'), (0, 'side', 'newer'), (0, 'input_artifact_hash', 'f' * 64),
    (1, 'side', 'newer'), (1, 'artifact_sha256', 'f' * 64), (1, 'config_digest', 'f' * 64),
    (1, 'cache_key', 'f' * 64), (1, 'engine', 'die'), (1, 'run_id', 'another-run'),
])
def test_stored_source_rejects_mismatched_identity(produced, part, field, value):
    service, store, _request, first = produced
    job = _job(first, 'older')
    artifact = next(a for a in service.project.artifacts if a.side == 'older')
    assert compose.stored_floss(store, artifact) is not None
    row_id = job.run.run_id if part == 0 else evidence_entry_id(job.evidence)
    row = service.store.connection.execute('SELECT body FROM enrichment_entries WHERE id=?',
                                           (row_id,)).fetchone()
    body = json.loads(row[0])
    body[field] = value
    text = json.dumps(body)
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                     (text, hashlib.sha256(text.encode()).hexdigest(), row_id))
    assert compose.stored_floss(store, artifact) is None


@pytest.mark.parametrize('choice', ['auto', 'floss'])
def test_real_cached_source_retains_original_evidence_provenance(produced, choice):
    service, store, request, first = produced
    before = compute(args(choice), service, threading.Event())
    assert set(before.sources.values()) == {'floss'}
    cached = runner.run_tools(request, store, threading.Event())
    assert all(job.run.cache_hit and job.run.raw_sidecar is None and job.run.stdout_digest is None
               for job in cached)
    assert all(job.evidence.run_id == _job(first, job.run.side).run.run_id != job.run.run_id for job in cached)
    after = compute(args(choice), service, threading.Event())
    assert after.sources == before.sources
    for side in ('older', 'newer'):
        assert after.tables[side].basis.parts == before.tables[side].basis.parts
        part = after.tables[side].basis.parts[0]
        assert part.raw_sha256 == _job(first, side).run.stdout_digest
        assert part.executable_sha256 == _job(first, side).run.manifest.executable_sha256


@pytest.mark.parametrize('kind', ['run', 'evidence'])
@pytest.mark.parametrize('field', ['stale', 'project_id'])
def test_metadata_refusal_falls_back_only_for_auto(produced, kind, field):
    service, _store, _request, first = produced
    assert set(compute(args(), service, threading.Event()).sources.values()) == {'floss'}
    job = _job(first)
    _invalidate(service, job.run.run_id if kind == 'run' else evidence_entry_id(job.evidence), field)
    after = compute(args(), service, threading.Event())
    assert after.sources == {'older': 'floss', 'newer': 'builtin-scan'}
    with pytest.raises(StringsError, match='no stored FLOSS evidence for the newer artifact'):
        compute(args('floss'), service, threading.Event())


def test_invalid_latest_cache_row_does_not_silently_reuse_an_older_run(produced):
    service, store, request, _first = produced
    cached = runner.run_tools(request, store, threading.Event())
    selected = _job(cached).run
    assert selected.cache_hit
    service.store.connection.execute('UPDATE enrichment_entries SET run_id=? WHERE id=?',
                                     ('foreign-guard-run', selected.run_id))
    after = compute(args(), service, threading.Event())
    assert after.sources['newer'] == 'builtin-scan'
    with pytest.raises(StringsError, match='no stored FLOSS evidence for the newer artifact'):
        compute(args('floss'), service, threading.Event())


def test_dock_keeps_real_cached_floss_sources(qtbot, produced):
    from test_ui_strings_source import scan, start
    service, store, request, _first = produced
    controller = start(qtbot, service)
    scan(qtbot, controller)
    assert controller.view.kind == 'ready'
    before = controller.loaded.delta
    assert {row.source for row in controller.loaded.rows} == {copy.SOURCE_LABELS['floss']}
    cached = runner.run_tools(request, store, threading.Event())
    assert all(job.run.cache_hit and job.run.raw_sidecar is None for job in cached)
    scan(qtbot, controller)
    assert controller.view.kind == 'ready'
    assert controller.loaded.delta == before
    assert {row.source for row in controller.loaded.rows} == {copy.SOURCE_LABELS['floss']}


@pytest.mark.parametrize(('kind', 'field'), [('run', 'stale'), ('evidence', 'project_id')])
def test_dock_metadata_refusal_preserves_the_prior_display_for_explicit_floss(qtbot, produced, kind, field):
    from test_ui_strings_source import choose, scan, start, status, table_texts
    service, _store, _request, first = produced
    controller = start(qtbot, service, choice='floss')
    scan(qtbot, controller)
    assert controller.view.kind == 'ready'
    previous, rows = controller.loaded, table_texts(controller)
    job = _job(first)
    _invalidate(service, job.run.run_id if kind == 'run' else evidence_entry_id(job.evidence), field)
    scan(qtbot, controller)
    assert controller.loaded is previous and table_texts(controller) == rows
    assert status(controller) == copy.STATES['floss-not-stored'].format(side='newer')
    choose(controller, 'auto')
    scan(qtbot, controller)
    assert controller.view.kind == 'ready'
    assert {row.status: row.source for row in controller.loaded.rows} == {
        'only-older': copy.SOURCE_LABELS['floss'], 'only-newer': copy.SOURCE_LABELS['builtin-scan']}
