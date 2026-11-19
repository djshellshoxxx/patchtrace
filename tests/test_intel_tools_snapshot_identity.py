"""Regressions from independent review of 58b5421c, extended across stored identity boundaries.

These use actual SQLite rows and content-addressed sidecars from authored tool
fixtures. No native execution or raw-output replay acceptance is claimed.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from test_capa_cli import stored_project
from test_intel_tools_snapshot import captured as captured
from test_intel_tools_snapshot import clean_env  # noqa: F401

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import snapshot as S
from patchtrace.intelligence.tools import store as TS
from patchtrace.intelligence.tools.common import (
    EVIDENCE_KIND,
    RUN_KIND,
    ToolError,
    ToolEvidenceSet,
    cache_key,
    config_digest,
)
from patchtrace.service import ProjectService


def _entry(service, kind, run_id=None):
    return next(entry for entry in EnrichmentStore(service.store).entries(kind)
                if entry.body['side'] == 'older' and (run_id is None or entry.body['run_id'] == run_id))


def _rewrite(service, entry, body):
    text = json.dumps(body)
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                     (text, hashlib.sha256(text.encode()).hexdigest(), entry.id))


def _refuses(service):
    with pytest.raises(ToolError):
        S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')


@pytest.mark.parametrize('kind', [RUN_KIND, EVIDENCE_KIND])
@pytest.mark.parametrize('field', ['raw_sha256', 'input_digest', 'id', 'run_id', 'project_id',
                                  'status', 'stale', 'project_revision'])
def test_row_guard_status_and_identity_are_bound(captured, kind, field):
    service, _store = captured
    entry = _entry(service, kind)
    value = {'status': 'failed', 'stale': 1, 'project_revision': service.project.revision + 1}.get(field, 'f' * 64)
    service.store.connection.execute(f'UPDATE enrichment_entries SET {field}=? WHERE id=?', (value, entry.id))
    _refuses(service)


@pytest.mark.parametrize('field', ['executable_sha256', 'version', 'rules_sha256', 'signatures_sha256',
                                  'backend_version', 'supported', 'options'])
def test_run_configuration_digest_binds_manifest_and_options(captured, field):
    service, _store = captured
    entry = _entry(service, RUN_KIND)
    body = dict(entry.body)
    if field == 'options':
        body['options'] = {**body['options'], 'edited': 'yes'}
    else:
        value = False if field == 'supported' else 'f' * 64
        body['manifest'] = {**body['manifest'], field: value}
    _rewrite(service, entry, body)
    _refuses(service)


def test_non_cached_sidecar_cannot_rebind_prior_run(captured, monkeypatch):
    service, store = captured
    run, evidence = store.latest('capa', 'older')
    monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
    store.publish_evidence(evidence)
    newer = run.model_copy(update={'run_id': 'newer-unrelated-run'})
    store.publish_run(newer)
    entry = _entry(service, EVIDENCE_KIND)
    _rewrite(service, entry, {**entry.body, 'run_id': newer.run_id})
    _refuses(service)


@pytest.mark.parametrize('damage', ['counts', 'unknown-field'])
def test_sidecar_header_cannot_contradict_its_held_evidence(captured, monkeypatch, damage):
    service, store = captured
    evidence = store.latest('capa', 'older')[1]
    monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
    store.publish_evidence(evidence)
    entry = _entry(service, EVIDENCE_KIND)
    body = dict(entry.body)
    if damage == 'counts':
        body['counts'] = {**body['counts'], 'capabilities': evidence.evidence_count() + 1}
    else:
        body['unknown'] = 'not admitted'
    _rewrite(service, entry, body)
    _refuses(service)


def test_evidence_content_identity_is_rechecked_after_valid_body_edit(captured):
    service, _store = captured
    entry = _entry(service, EVIDENCE_KIND)
    body = {**entry.body, 'analysis': {**entry.body['analysis'], 'edited': 'yes'}}
    _rewrite(service, entry, body)
    _refuses(service)


@pytest.mark.parametrize('damage', ['missing', 'cached-producer', 'failed-producer', 'other-config', 'wrong-count'])
def test_cache_reuse_requires_the_compatible_retained_producer(captured, damage):
    service, store = captured
    run, _evidence = store.latest('capa', 'older')
    cached = run.model_copy(update={'run_id': 'cached-current', 'cache_hit': True,
                                   'raw_sidecar': None, 'stdout_digest': None})
    store.publish_run(cached)
    producer = _entry(service, RUN_KIND, run.run_id)
    if damage == 'missing':
        service.store.connection.execute('DELETE FROM enrichment_entries WHERE id=?', (producer.id,))
    elif damage == 'wrong-count':
        store.publish_run(cached.model_copy(update={'evidence_count': cached.evidence_count + 1}))
    else:
        body = dict(producer.body)
        if damage == 'cached-producer':
            body['cache_hit'] = True
        elif damage == 'failed-producer':
            body.update(status='failed', error_code='PT-TOOL-RUN')
            service.store.connection.execute('UPDATE enrichment_entries SET status=? WHERE id=?',
                                             ('failed', producer.id))
        else:
            options = {**run.options, 'different': 'yes'}
            key = cache_key(run.input_artifact_hash, run.manifest, options)
            body.update(options=options, cache_key=key, config_digest=config_digest(run.manifest, options))
            service.store.connection.execute('UPDATE enrichment_entries SET input_digest=? WHERE id=?',
                                             (key, producer.id))
        _rewrite(service, producer, body)
    _refuses(service)


def test_actual_runner_cache_hit_retains_its_prior_producer(tmp_path):
    root = stored_project(tmp_path, analysed=False)
    with ProjectService.open(root) as service:
        prior, evidence = S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')
    assert cli.main(['intel-tools', 'run', str(root), '--capa', prior.manifest.cli_path,
                     '--capa-accept-untested', '--json']) == 0
    with ProjectService.open(root) as service:
        current, retained = S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older')
    assert current.cache_hit and current.run_id != prior.run_id
    assert current.raw_sidecar is current.stdout_digest is None
    assert retained == evidence and retained.run_id == prior.run_id


def test_empty_produced_and_cached_results_need_no_raw_sidecar(captured):
    service, store = captured
    prior, _evidence = store.latest('capa', 'older')
    empty = prior.model_copy(update={'run_id': 'empty-producer', 'evidence_count': 0, 'status': 'none-found',
                                    'raw_sidecar': None, 'stdout_digest': None})
    evidence = ToolEvidenceSet(run_id=empty.run_id, engine=empty.engine, side=empty.side,
                               artifact_sha256=empty.input_artifact_hash, cache_key=empty.cache_key,
                               config_digest=empty.config_digest)
    store.publish_run(empty)
    store.publish_evidence(evidence)
    assert S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older') == (empty, evidence)
    cached = empty.model_copy(update={'run_id': 'empty-cached', 'cache_hit': True})
    store.publish_run(cached)
    assert S.capture_tool_sources(service, engines=('capa',)).latest('capa', 'older') == (cached, evidence)
