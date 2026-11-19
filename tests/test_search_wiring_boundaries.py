"""Stored-source admission and actual filesystem controls; fake tools supply no native acceptance."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest
from test_capa_cli import stored_project
from test_intel_tools_cli import clean_env  # noqa: F401

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import snapshot as tool_snapshot
from patchtrace.intelligence.tools import store as tool_storage
from patchtrace.intelligence.tools.common import EVIDENCE_KIND, RUN_KIND, ToolEvidenceSet
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.search import wiring
from patchtrace.search.errors import SearchError
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    root = stored_project(tmp_path, analysed=False)
    with ProjectService.open(root) as opened:
        yield opened


def _specs(snapshot):
    return {spec.group: spec for spec in snapshot.extra_specs()}


def _store(service):
    return ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)


def _row(service, kind, side='older'):
    return next(entry for entry in EnrichmentStore(service.store).entries(kind) if entry.body.get('side') == side)


def _rewrite(service, entry, text, *, update_digest=True, connection=None):
    digest = hashlib.sha256(text.encode()).hexdigest() if update_digest else entry.body_sha256
    db = connection or service.store.connection
    db.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?', (text, digest, entry.id))
    if connection is not None:
        connection.commit()


@pytest.mark.parametrize('budget', ['rows', 'bytes'])
def test_metadata_budget_precedes_loading_any_stored_body(service, monkeypatch, budget):
    monkeypatch.setattr(wiring, 'SNAPSHOT_ROWS' if budget == 'rows' else 'SNAPSHOT_BYTES', 1)
    queries = []
    service.store.connection.set_trace_callback(queries.append)
    snapshot = wiring.snapshot_sources(service)
    service.store.connection.set_trace_callback(None)
    assert {spec.status for spec in snapshot.extra_specs()} == {'unavailable'}
    assert not any('THEN body END' in query for query in queries)


@pytest.mark.parametrize('text', ['{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}', '[' * 80 + ']' * 80])
def test_strict_stored_json_failure_is_not_empty_tool_evidence(service, text):
    entry = _row(service, RUN_KIND)
    _rewrite(service, entry, text)
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].status == 'unavailable'
    assert specs['tool:capa:newer'].status == 'unavailable'
    assert specs['adv'].buildable and specs['cve'].buildable


@pytest.mark.parametrize('external', [False, True])
def test_snapshot_reuse_detects_same_timestamp_and_digest_body_mutation(service, external):
    first = wiring.snapshot_sources(service)
    assert wiring.snapshot_sources(service, first) is first
    entry = _row(service, RUN_KIND)
    if external:
        database = service.store.connection.execute('PRAGMA database_list').fetchone()[2]
        with sqlite3.connect(database) as db:
            _rewrite(service, entry, '{}', update_digest=False, connection=db)
    else:
        _rewrite(service, entry, '{}', update_digest=False)
    second = wiring.snapshot_sources(service, first)
    assert second is not first and second.key is None
    assert _specs(second)['tool:capa:older'].status == 'unavailable'


def test_corrupt_newest_produced_run_does_not_fall_back_to_older_evidence(service):
    store = _store(service)
    prior = store.latest('capa', 'older')[0]
    newer = prior.model_copy(update={'run_id': 'newest-without-evidence', 'started_at': '2099-01-01T00:00:00Z'})
    store.publish_run(newer)
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].status == 'unavailable'
    assert specs['tool:capa:newer'].buildable


@pytest.mark.parametrize('field', ['side', 'artifact_sha256', 'config_digest', 'cache_key'])
def test_tool_evidence_must_bind_the_current_artifact_and_run(service, field):
    entry = _row(service, EVIDENCE_KIND)
    body = dict(entry.body)
    body[field] = 'newer' if field == 'side' else 'f' * 64
    _rewrite(service, entry, json.dumps(body))
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].status == 'unavailable'
    assert specs['tool:capa:newer'].buildable


def _sidecar(service, monkeypatch, side='older') -> Path:
    store = _store(service)
    evidence = store.latest('capa', side)[1]
    monkeypatch.setattr(tool_storage, 'INLINE_LIMIT', 1)
    store.publish_evidence(evidence)
    entry = _row(service, EVIDENCE_KIND, side)
    assert entry.body['kind'] == 'sidecar'
    return service.root / entry.body['sidecar']


def test_sidecar_mutation_and_repair_are_revalidated_without_database_change(service, monkeypatch):
    path = _sidecar(service, monkeypatch)
    original = path.read_bytes()
    first = wiring.snapshot_sources(service)
    assert first.key is None and _specs(first)['tool:capa:older'].buildable
    path.write_bytes(b'X' * len(original))
    second = wiring.snapshot_sources(service, first)
    assert _specs(second)['tool:capa:older'].status == 'unavailable'
    assert _specs(second)['tool:capa:newer'].buildable
    path.write_bytes(original)
    third = wiring.snapshot_sources(service, second)
    assert _specs(third)['tool:capa:older'].buildable


def test_declared_sidecar_budget_is_checked_before_reading(service, monkeypatch):
    _sidecar(service, monkeypatch)
    monkeypatch.setattr(wiring, 'SIDECAR_BYTES', 8)
    monkeypatch.setattr(tool_snapshot, 'read_owned_bytes', lambda *a, **k: pytest.fail('over-budget sidecar was opened'))
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].status == 'unavailable'
    assert specs['tool:capa:newer'].buildable


def test_sidecar_byte_budget_is_shared_across_selected_groups(service, monkeypatch):
    older, newer = _sidecar(service, monkeypatch), _sidecar(service, monkeypatch, 'newer')
    monkeypatch.setattr(wiring, 'SIDECAR_BYTES', older.stat().st_size + newer.stat().st_size - 1)
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].buildable
    assert specs['tool:capa:newer'].status == 'unavailable'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX special-file admission')
@pytest.mark.parametrize('special', ['fifo', 'symlink'])
def test_special_sidecar_is_refused_and_external_bytes_preserved(service, monkeypatch, tmp_path, special):
    path = _sidecar(service, monkeypatch)
    outside = tmp_path / 'outside'
    outside.write_bytes(path.read_bytes())
    expected = outside.read_bytes()
    path.unlink()
    if special == 'fifo':
        os.mkfifo(path)
    else:
        path.symlink_to(outside)
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].status == 'unavailable'
    assert outside.read_bytes() == expected


@pytest.mark.parametrize('damage', ['collection-limit', 'unknown-fields'])
def test_evidence_shape_is_admitted_before_model_construction(service, monkeypatch, damage):
    entry = _row(service, EVIDENCE_KIND)
    body = dict(entry.body)
    if damage == 'collection-limit':
        monkeypatch.setitem(tool_snapshot.EVIDENCE_ROWS, 'capabilities', 1)
        body['capabilities'] = [{}, {}]
    else:
        body['unknown'] = 'not admitted'
    _rewrite(service, entry, json.dumps(body))
    original = ToolEvidenceSet.model_validate_json

    def checked(data, *args, **kwargs):
        if json.loads(data).get('side') == 'older':
            pytest.fail('rejected evidence entered model construction')
        return original(data, *args, **kwargs)

    monkeypatch.setattr(ToolEvidenceSet, 'model_validate_json', checked)
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['tool:capa:older'].status == 'unavailable'


def test_incomplete_advisory_source_is_unavailable_without_hiding_tool_groups(service, monkeypatch):
    monkeypatch.setattr(wiring._StoredAdvisories, 'advisories', lambda _self: ([], ['missing stored source']))
    specs = _specs(wiring.snapshot_sources(service))
    assert specs['adv'].status == 'unavailable'
    assert specs['tool:capa:older'].buildable and specs['tool:capa:newer'].buildable


def test_project_snapshot_is_independent_and_bounded_before_copy(service, monkeypatch):
    captured = wiring.copy_project(service.project)
    name = captured.name
    service.project.name = 'mutated owner value'
    assert captured.name == name
    monkeypatch.setattr(wiring, 'PROJECT_NODES', 1)
    monkeypatch.setattr(type(service.project), 'model_copy', lambda *a, **k: pytest.fail('oversized project copied'))
    with pytest.raises(SearchError, match='snapshot budget'):
        wiring.copy_project(service.project)
