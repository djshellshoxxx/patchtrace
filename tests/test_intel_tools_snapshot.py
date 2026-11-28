"""Bounded stored-source capture over authored records; no executable runs."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from pe_builder import build_pe

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import snapshot as S
from patchtrace.intelligence.tools import store as TS
from patchtrace.intelligence.tools.common import (
    EVIDENCE_KIND,
    RUN_KIND,
    EvidenceLink,
    StringEvidence,
    ToolError,
    ToolEvidenceSet,
    ToolManifest,
    ToolRun,
    cache_key,
    config_digest,
)
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.owned_publication import OwnedPublicationError
from patchtrace.service import ProjectService


def publish_tool(service, side, *, engine='floss', label='StoredCaptureNeedle', run_id=None, empty=False):
    artifact = next(a for a in service.project.artifacts if a.side == side)
    manifest = ToolManifest(engine=engine, version='1.0', executable_sha256='a' * 64,
                            license='authored-test', supported=True)
    key = cache_key(artifact.sha256, manifest, {})
    run_id = run_id or f'authored-{engine}-{side}'
    raw = b'{"authored":true}'
    raw_sha = hashlib.sha256(raw).hexdigest()
    raw_path = f'intel-tools/raw/{engine}-{raw_sha}.json'
    path = service.root / raw_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    strings = () if empty else (StringEvidence(
        value_hash=hashlib.sha256(label.encode()).hexdigest(), length=len(label), display_value=label,
        encoding='ASCII', type='static', source_location=EvidenceLink(tool_run_id=run_id,
        artifact_sha256=artifact.sha256), confidence_class='tool-reported', extraction_method='floss-static',
        source_run_id=run_id),)
    evidence = ToolEvidenceSet(run_id=run_id, engine=engine, side=side, artifact_sha256=artifact.sha256,
        config_digest=config_digest(manifest, {}), cache_key=key, strings=strings)
    run = ToolRun(run_id=run_id, engine=engine, side=side, input_artifact_hash=artifact.sha256,
        config_digest=evidence.config_digest, cache_key=key, started_at='2026-11-28T00:00:00Z', elapsed=0,
        status='none-found' if empty else 'ok', evidence_count=len(strings), profile='context', manifest=manifest,
        stdout_digest=raw_sha, raw_sidecar=raw_path)
    store = ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)
    store.publish_run(run)
    store.publish_evidence(evidence)
    return store, run, evidence


@pytest.fixture
def captured(tmp_path):
    for side, stamp in (('older', 1), ('newer', 2)):
        (tmp_path / f'{side}.exe').write_bytes(build_pe(timestamp=stamp))
    with ProjectService.create(tmp_path / 'older.exe', tmp_path / 'newer.exe', 'stored sources',
                               tmp_path / 'case') as service:
        store, _run, _evidence = publish_tool(service, 'older')
        publish_tool(service, 'newer')
        yield service, store


def entry(service, kind, side='newer'):
    return next(e for e in EnrichmentStore(service.store).entries(kind) if e.body['side'] == side)


def rewrite(service, row, body):
    text = json.dumps(body, allow_nan=False)
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
        (text, hashlib.sha256(text.encode()).hexdigest(), row.id))


def refused(sources, side='newer'):
    with pytest.raises(ToolError, match='unavailable'):
        sources.admitted('floss', side)


def test_values_survive_store_close_and_can_be_read_in_worker(captured):
    service, _store = captured
    sources = S.capture_tool_sources(service, engines=('floss',))
    expected = sources.admitted('floss', 'newer')
    service.close()
    with ThreadPoolExecutor(max_workers=1) as worker:
        assert worker.submit(sources.admitted, 'floss', 'newer').result() == expected
    assert sources.latest('floss', 'newer') == (expected.run, expected.evidence)
    with pytest.raises(ToolError, match='not captured'):
        sources.latest('capa', 'newer')


@pytest.mark.parametrize('kind', [RUN_KIND, EVIDENCE_KIND])
@pytest.mark.parametrize('field,value', [('stale', 1), ('project_id', 'foreign-project'),
    ('run_id', 'foreign-guard'), ('raw_sha256', 'b' * 64), ('input_digest', 'b' * 64),
    ('status', 'failed'), ('id', 'foreign-id'), ('project_revision', 10_000)])
def test_selected_side_metadata_failure_preserves_valid_other_side(captured, kind, field, value):
    service, _store = captured
    row = entry(service, kind)
    service.store.connection.execute(f'UPDATE enrichment_entries SET {field}=? WHERE id=?', (value, row.id))
    sources = S.capture_tool_sources(service)
    refused(sources)
    assert sources.latest('floss', 'older') is not None
    assert sources.latest('capa', 'newer') is None


@pytest.mark.parametrize('kind', [RUN_KIND, EVIDENCE_KIND])
@pytest.mark.parametrize('damage', ['duplicate', 'blob', 'bad-hash'])
def test_original_json_and_storage_class_checked_before_admission(captured, kind, damage):
    service, _store = captured
    row = entry(service, kind)
    text, sha = row.body_json, row.body_sha256
    if damage == 'duplicate':
        text = text[:-1] + ',"run_id":' + json.dumps(row.body['run_id']) + '}'
        sha = hashlib.sha256(text.encode()).hexdigest()
    elif damage == 'blob':
        text = sqlite3.Binary(text.encode())
    else:
        sha = 'f' * 64
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                     (text, sha, row.id))
    refused(S.capture_tool_sources(service))


@pytest.mark.parametrize('field,value', [('stale', 0.5), ('project_revision', 0.5),
    ('id', sqlite3.Binary(b'authored-newer')), ('created', 'x' * 65)])
def test_metadata_is_bounded_with_exact_sqlite_storage_classes(captured, field, value):
    service, _store = captured
    row = entry(service, RUN_KIND)
    service.store.connection.execute('PRAGMA ignore_check_constraints=ON')  # authored damaged persisted row
    service.store.connection.execute(f'UPDATE enrichment_entries SET {field}=? WHERE id=?', (value, row.id))
    refused(S.capture_tool_sources(service))


@pytest.mark.parametrize('field', ['options', 'manifest', 'raw_sidecar', 'stdout_digest'])
def test_recorded_producer_configuration_and_raw_identity_are_rechecked(captured, field):
    service, _store = captured
    row = entry(service, RUN_KIND)
    body = dict(row.body)
    if field == 'options':
        body[field] = {'changed': 'yes'}
    elif field == 'manifest':
        body[field] = {**body[field], 'version': 'changed'}
    elif field == 'raw_sidecar':
        body[field] = 'intel-tools/raw/floss-' + 'f' * 64 + '.json'
    else:
        body[field] = 'f' * 64
    rewrite(service, row, body)
    refused(S.capture_tool_sources(service))


def test_cached_run_keeps_admitted_origin_and_rejects_cached_origin(captured):
    service, store = captured
    run, evidence = store.latest('floss', 'newer')
    cached = run.model_copy(update={'run_id': 'cache-hit', 'cache_hit': True,
                                    'raw_sidecar': None, 'stdout_digest': None})
    store.publish_run(cached)
    result = S.capture_tool_sources(service).admitted('floss', 'newer')
    assert result.run == cached and result.evidence == evidence and result.evidence_run == run
    store.publish_run(run.model_copy(update={'cache_hit': True}))
    refused(S.capture_tool_sources(service))


def test_missing_and_produced_empty_are_distinct(captured):
    service, _store = captured
    _store, run, evidence = publish_tool(service, 'newer', run_id='empty', empty=True)
    sources = S.capture_tool_sources(service)
    assert sources.latest('capa', 'newer') is None
    assert sources.latest('floss', 'newer') == (run, evidence)


@pytest.mark.parametrize('budget', ['SNAPSHOT_ROWS', 'SNAPSHOT_BYTES', 'SIDECAR_BYTES'])
def test_aggregate_budgets_fail_before_unbounded_materialization(captured, monkeypatch, budget):
    service, store = captured
    if budget == 'SIDECAR_BYTES':
        monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
        store.publish_evidence(store.latest('floss', 'newer')[1])
    monkeypatch.setattr(S, budget, 1)
    sources = S.capture_tool_sources(service)
    refused(sources)
    assert sources.capture_error
    with pytest.raises(ToolError, match='capture is unavailable'):
        sources.require_capture()


def test_global_capture_failure_is_distinct_from_per_side_refusal(captured, monkeypatch):
    service, _store = captured
    row = entry(service, RUN_KIND)
    service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    sources = S.capture_tool_sources(service)
    assert sources.capture_error is None
    sources.require_capture()
    refused(sources)
    assert sources.latest('floss', 'older') is not None
    monkeypatch.setattr(S, 'SNAPSHOT_ROWS', 1)
    sources = S.capture_tool_sources(service)
    assert sources.capture_error
    with pytest.raises(ToolError, match='capture is unavailable'):
        sources.require_capture()


@pytest.mark.parametrize('damage', ['bytes', 'size', 'counts', 'unknown', 'symlink'])
def test_sidecar_identity_and_held_file_admission(captured, monkeypatch, damage):
    service, store = captured
    monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
    store.publish_evidence(store.latest('floss', 'newer')[1])
    row = entry(service, EVIDENCE_KIND)
    path = service.root / row.body['sidecar']
    assert S.capture_tool_sources(service).latest('floss', 'newer') is not None
    if damage == 'bytes':
        path.write_bytes(b'X' * path.stat().st_size)
    elif damage == 'symlink':
        other = path.with_suffix('.other')
        path.rename(other)
        path.symlink_to(other)
    else:
        body = dict(row.body)
        body[damage] = {'strings': 99} if damage == 'counts' else 1
        rewrite(service, row, body)
    refused(S.capture_tool_sources(service))


def test_capture_does_not_commit_or_mutate_owner_transaction(captured):
    service, _store = captured
    db = service.store.connection
    db.execute('UPDATE enrichment_entries SET created=?', ('2026-11-28T01:00:00Z',))
    assert db.in_transaction
    before = tuple(db.iterdump())
    sources = S.capture_tool_sources(service)
    assert sources.latest('floss', 'newer') is not None
    assert db.in_transaction and tuple(db.iterdump()) == before


def test_failed_sidecar_reads_consume_reserved_aggregate_budget(tmp_path, monkeypatch):
    paths = [tmp_path / 'one', tmp_path / 'two']
    for path in paths:
        path.write_bytes(b'1234')
    calls = []
    original = S.read_owned_bytes

    def observed(path, **kw):
        calls.append(kw['maximum'])
        return original(path, **kw)

    monkeypatch.setattr(S, 'read_owned_bytes', observed)
    budget = S.ReadBudget(remaining=4, root=tmp_path)
    with pytest.raises(ValueError):
        budget.read(paths[0], 4, 'f' * 64)
    with pytest.raises(ValueError):
        budget.read(paths[1], 4, 'f' * 64)
    assert calls == [4] and budget.remaining == 0


@pytest.mark.parametrize('sidecar', [False, True])
def test_evidence_row_quota_precedes_typed_allocation(captured, monkeypatch, sidecar):
    service, store = captured
    if sidecar:
        monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
        store.publish_evidence(store.latest('floss', 'newer')[1])
    monkeypatch.setattr(S, 'EVIDENCE_ROWS', {**S.EVIDENCE_ROWS, 'strings': 0})
    refused(S.capture_tool_sources(service))


def test_held_project_identity_refuses_replaced_root(tmp_path):
    root = tmp_path / 'case'
    root.mkdir()
    path = root / 'evidence.json'
    data = b'{"authored":true}'
    path.write_bytes(data)
    budget = S.ReadBudget(remaining=1024, root=root)
    root.rename(tmp_path / 'prior')
    root.mkdir()
    path.write_bytes(data)
    with pytest.raises(OwnedPublicationError, match='identity changed'):
        budget.read(path, len(data), hashlib.sha256(data).hexdigest())


def test_original_sidecar_json_duplicate_members_refuse(captured, monkeypatch):
    service, store = captured
    monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
    store.publish_evidence(store.latest('floss', 'newer')[1])
    row = entry(service, EVIDENCE_KIND)
    prior = (service.root / row.body['sidecar']).read_bytes()
    data = prior[:-1] + b',"run_id":"authored-floss-newer"}'
    sha = hashlib.sha256(data).hexdigest()
    path = service.root / f'intel-tools/{sha}.json'
    path.write_bytes(data)
    rewrite(service, row, {**row.body, 'sidecar': f'intel-tools/{sha}.json', 'sidecar_sha256': sha, 'size': len(data)})
    refused(S.capture_tool_sources(service))
