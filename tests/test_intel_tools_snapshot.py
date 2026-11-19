"""The shared source port reads real stored fixtures, with no live engine or target acceptance."""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_capa_cli import stored_project
from test_intel_tools_cli import clean_env  # noqa: F401

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import snapshot as S
from patchtrace.intelligence.tools import store as TS
from patchtrace.intelligence.tools.common import EVIDENCE_KIND, RUN_KIND, ToolError
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.service import ProjectService


@pytest.fixture
def captured(tmp_path):
    root = stored_project(tmp_path, analysed=False)
    with ProjectService.open(root) as service:
        yield service, ToolStore(EnrichmentStore(service.store), root, service.project.id, service.project.revision)


def test_public_source_values_remain_readable_after_store_closes(tmp_path):
    root = stored_project(tmp_path, analysed=False)
    with ProjectService.open(root) as service:
        sources = S.capture_tool_sources(service, engines=('capa',))
        pair = sources.latest('capa', 'older')
    with ThreadPoolExecutor(max_workers=1) as worker:
        assert worker.submit(sources.latest, 'capa', 'older').result() == pair
    assert pair[0].input_artifact_hash == pair[1].artifact_sha256
    with pytest.raises(ToolError, match='not captured'):
        sources.latest('floss', 'older')


def test_public_port_separates_missing_from_corrupt_evidence(captured):
    service, _store = captured
    entry = next(entry for entry in EnrichmentStore(service.store).entries(EVIDENCE_KIND)
                 if entry.body['side'] == 'older')
    service.store.connection.execute('UPDATE enrichment_entries SET body=? WHERE id=?', ('{}', entry.id))
    sources = S.capture_tool_sources(service)
    assert sources.latest('floss', 'older') is None
    with pytest.raises(ToolError, match='unavailable'):
        sources.latest('capa', 'older')


def test_shared_port_validates_sidecar_and_current_artifact(captured, monkeypatch):
    service, store = captured
    run, evidence = store.latest('capa', 'older')
    monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
    store.publish_evidence(evidence)
    assert S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')[0] == run
    body = next(entry.body for entry in EnrichmentStore(service.store).entries(EVIDENCE_KIND)
                if entry.body['side'] == 'older')
    path = service.root / body['sidecar']
    before = path.read_bytes()
    path.write_bytes(b'X' * len(before))
    sources = S.capture_tool_sources(service, engines=('capa',))
    with pytest.raises(ToolError, match='unavailable'):
        sources.latest('capa', 'older')
    assert sources.latest('capa', 'newer') is not None


@pytest.mark.parametrize('budget', ['SNAPSHOT_ROWS', 'SNAPSHOT_BYTES', 'SIDECAR_BYTES'])
def test_public_port_enforces_its_own_shared_budgets(captured, monkeypatch, budget):
    service, store = captured
    if budget == 'SIDECAR_BYTES':
        evidence = store.latest('capa', 'older')[1]
        monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
        store.publish_evidence(evidence)
    monkeypatch.setattr(S, budget, 1)
    sources = S.capture_tool_sources(service, engines=('capa',))
    with pytest.raises(ToolError, match='unavailable'):
        sources.latest('capa', 'older')


def test_public_port_rejects_edited_run_configuration(captured):
    service, _store = captured
    entry = next(entry for entry in EnrichmentStore(service.store).entries(EVIDENCE_KIND)
                 if entry.body['side'] == 'older')
    body = {**entry.body, 'config_digest': 'f' * 64}
    text = json.dumps(body)
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                     (text, hashlib.sha256(text.encode()).hexdigest(), entry.id))
    with pytest.raises(ToolError, match='unavailable'):
        S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')


@pytest.mark.parametrize('field', ['raw_sidecar', 'stdout_digest'])
def test_raw_provenance_must_name_the_recorded_stdout_digest(captured, field):
    service, _store = captured
    entry = next(entry for entry in EnrichmentStore(service.store).entries(RUN_KIND)
                 if entry.body['side'] == 'older')
    body = dict(entry.body)
    body[field] = 'intel-tools/raw/capa-' + 'f' * 64 + '.json' if field == 'raw_sidecar' else 'f' * 64
    text = json.dumps(body)
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                     (text, hashlib.sha256(text.encode()).hexdigest(), entry.id))
    with pytest.raises(ToolError, match='unavailable'):
        S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')


def test_cached_run_without_new_raw_output_retains_persisted_evidence(captured):
    service, store = captured
    run, evidence = store.latest('capa', 'older')
    cached = run.model_copy(update={'run_id': 'cached-current', 'cache_hit': True,
                                   'raw_sidecar': None, 'stdout_digest': None})
    store.publish_run(cached)
    captured_run, captured_evidence = S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')
    assert captured_run.run_id == cached.run_id and captured_run.cache_hit is True
    assert captured_run.raw_sidecar is None and captured_run.stdout_digest is None
    assert captured_evidence == evidence
