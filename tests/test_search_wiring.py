"""Production Search over real authored stores; no provider or target executes."""
from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from pathlib import Path

import pytest
from test_intel_tools_snapshot import captured as captured
from test_intel_tools_snapshot import entry, publish_tool, rewrite

from patchtrace.enrichment.contracts import AttributedText, CveSnapshot
from patchtrace.enrichment.cve import _snapshot_id
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.intelligence.storage import FACTS_KIND, SOURCE_KIND, AdvisoryStore
from patchtrace.intelligence.tools import store as TS
from patchtrace.intelligence.tools.common import RUN_KIND
from patchtrace.search import cli
from patchtrace.service import ProjectService

ADVISORY = Path(__file__).parent / 'fixtures/csaf/synthetic-advisory-rev1.json'


def invoke(root, cache, *argv):
    out, err = io.StringIO(), io.StringIO()
    result = cli.main([str(root), '--cache-dir', str(cache), '--json', *argv], stdout=out, stderr=err)
    return result, json.loads(out.getvalue())


def add_advisory(service):
    return AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                         service.project.revision).add(ADVISORY.read_bytes(), origin='local-import', uri=None,
                         file_name=ADVISORY.name, retrieved_at='2026-11-28T00:00:00Z')


def add_cve(service):
    digests = {'authored': 'b' * 64}
    snap = CveSnapshot(snapshot_id=_snapshot_id('CVE-2099-10002', 1, digests), cve_id='CVE-2099-10002',
        normalization_version=1, response_digests=digests, retrieved_at='2026-11-28T00:00:00Z',
        descriptions=(AttributedText(source='authored', text='StoredSnapshotNeedle'),))
    guard = Guard(service.project.id, 'cve', '0' * 64, snap.snapshot_id)
    EnrichmentStore(service.store).publish('cve-snapshot', guard, guard, service.project.revision, 'complete',
        snap.model_dump(mode='json'), f'cve-snapshot:{snap.snapshot_id}')
    return snap


def specs(service, prior=None):
    from patchtrace.search.wiring import snapshot_sources
    result = snapshot_sources(service, prior)
    return result, {item.group: item for item in result.extra_specs()}


def test_ordinary_cli_finds_stored_tool_output_and_lists_all_source_groups(captured, tmp_path):
    service, _store = captured
    root = service.root
    service.close()
    code, doc = invoke(root, tmp_path / 'cache', '--query', 'StoredCaptureNeedle', '--kind', 'string', '--rebuild')
    assert code == 0
    assert {e['group'] for h in doc['result']['hits'] for e in h['evidence']} == {
        'tool:floss:older', 'tool:floss:newer'}
    code, doc = invoke(root, tmp_path / 'cache', '--status')
    groups = {row['group']: row for row in doc['result']['coverage']}
    assert code == 0 and {'adv', 'cve', *(f'tool:{engine}:{side}' for engine in ('floss', 'capa', 'diec')
        for side in ('older', 'newer'))} <= groups.keys()
    assert groups['tool:floss:newer']['status'] == 'indexed'
    assert groups['tool:capa:newer']['status'] == 'unavailable'


@pytest.mark.parametrize('kind,needle,group', [('advisory', 'CVE-2099-10001', 'adv'),
                                              ('cve', 'StoredSnapshotNeedle', 'cve')])
def test_ordinary_cli_reads_retained_advisory_and_cve_sources(captured, tmp_path, kind, needle, group):
    service, _store = captured
    add_advisory(service)
    add_cve(service)
    root = service.root
    service.close()
    code, doc = invoke(root, tmp_path / 'cache', '--query', needle, '--kind', kind)
    assert code == 0 and any(e['group'] == group for h in doc['result']['hits'] for e in h['evidence'])
    assert str(tmp_path) not in json.dumps(doc)


@pytest.mark.parametrize('filters', [(), ('--kind', 'advisory')])
def test_corrupt_advisory_is_unavailable_and_cannot_report_complete_absence(captured, tmp_path, filters):
    service, _store = captured
    stored = add_advisory(service)
    fact = next(e for e in EnrichmentStore(service.store).entries(FACTS_KIND)
                if e.body['source_id'] == stored.source.sha256)
    (service.root / fact.body['path']).write_bytes(b'corrupt')
    root = service.root
    service.close()
    code, doc = invoke(root, tmp_path / 'cache', '--query', 'absent-needle', *filters)
    assert code == 3 and doc['status'] == 'partial'
    assert next(e for e in doc['result']['coverage'] if e['group'] == 'adv')['status'] == 'unavailable'


@pytest.mark.parametrize('needle,code', [('StoredCaptureNeedle', 0), ('AbsentStoredNeedle', 3)])
def test_unqualified_search_reports_refused_retained_tool_coverage(captured, tmp_path, needle, code):
    service, _store = captured
    row = entry(service, RUN_KIND, 'older')
    service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    service.store.connection.commit()
    root = service.root
    service.close()
    actual, doc = invoke(root, tmp_path / 'cache', '--query', needle)
    assert actual == code and doc['status'] == 'partial'
    actual, doc = invoke(root, tmp_path / 'cache', '--query', 'AbsentCveNeedle', '--kind', 'cve')
    assert actual == 4 and doc['status'] == 'no-results'


def test_never_produced_optional_tools_do_not_change_the_default_search_population(captured, tmp_path):
    service, _store = captured
    root = service.root
    service.close()
    code, doc = invoke(root, tmp_path / 'cache', '--query', 'AbsentStoredNeedle')
    assert code == 4 and doc['status'] == 'no-results'
    assert next(row for row in doc['result']['coverage'] if row['group'] == 'tool:capa:newer')[
        'status'] == 'unavailable'


@pytest.mark.parametrize('kind', [SOURCE_KIND, FACTS_KIND, 'cve-snapshot'])
@pytest.mark.parametrize('field,value', [('project_id', 'foreign'), ('status', 'failed'),
                                       ('stale', 1), ('project_revision', 999)])
def test_metadata_ownership_and_currency_refuse_whole_advisory_or_cve_group(captured, kind, field, value):
    service, _store = captured
    add_advisory(service)
    add_cve(service)
    row = EnrichmentStore(service.store).entries(kind)[0]
    service.store.connection.execute(f'UPDATE enrichment_entries SET {field}=? WHERE id=?', (value, row.id))
    _snapshot, groups = specs(service)
    assert groups['cve' if kind == 'cve-snapshot' else 'adv'].status == 'unavailable'
    assert groups['tool:floss:newer'].buildable


def test_inline_snapshot_reuse_tracks_local_and_external_database_changes(captured):
    service, _store = captured
    first, _groups = specs(service)
    assert specs(service, first)[0] is first
    row = entry(service, RUN_KIND)
    service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    second, groups = specs(service, first)
    assert second is not first and groups['tool:floss:newer'].status == 'unavailable'
    assert groups['tool:floss:older'].buildable


def test_capture_is_not_reused_after_rollback_of_an_owner_transaction(captured):
    service, _store = captured
    row = entry(service, RUN_KIND)
    service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    pending, groups = specs(service)
    assert groups['tool:floss:newer'].status == 'unavailable'
    service.store.connection.rollback()
    current, groups = specs(service, pending)
    assert current is not pending and groups['tool:floss:newer'].buildable


def test_successful_uncommitted_capture_cannot_survive_rollback(captured):
    service, _store = captured
    row = entry(service, 'tool-evidence')
    body = {**row.body, 'analysis': {'authored': 'changed'}}
    # A complete replacement snapshot is visible inside the owner's transaction;
    # total_changes alone will not detect its later rollback.
    from patchtrace.intelligence.tools.common import ToolEvidenceSet, evidence_entry_id
    value = ToolEvidenceSet.model_validate_json(json.dumps(body))
    rewrite(service, row, body)
    service.store.connection.execute('UPDATE enrichment_entries SET id=? WHERE id=?',
                                     (evidence_entry_id(value), row.id))
    pending, groups = specs(service)
    assert groups['tool:floss:newer'].buildable
    before = groups['tool:floss:newer'].digest16
    service.store.connection.rollback()
    current, groups = specs(service, pending)
    assert current is not pending and groups['tool:floss:newer'].digest16 != before


def test_external_committed_rows_invalidate_the_snapshot(captured):
    service, _store = captured
    first, _groups = specs(service)
    row = entry(service, RUN_KIND)
    with sqlite3.connect(service.root / 'project.sqlite3') as external:
        external.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    current, groups = specs(service, first)
    assert current is not first and groups['tool:floss:newer'].status == 'unavailable'


def test_advisory_anchor_query_uses_captured_ports_and_refuses_unreadable_sources(captured, tmp_path):
    service, _store = captured
    stored = add_advisory(service)
    root = service.root
    service.close()
    code, doc = invoke(root, tmp_path / 'cache', '--anchors-from', 'CVE-2099-10001')
    assert code in (0, 3) and doc['result']['anchors']
    with ProjectService.open(root) as owner:
        owner.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE kind=?', (SOURCE_KIND,))
        owner.store.connection.commit()
    code, doc = invoke(root, tmp_path / 'cache', '--anchors-from', 'CVE-2099-10001')
    assert code == 3 and doc['status'] == 'failed' and 'absence is not known' in doc['error']
    assert stored.source.sha256


def test_saved_query_execution_uses_production_sources(captured, tmp_path):
    service, _store = captured
    root = service.root
    service.close()
    code, saved = invoke(root, tmp_path / 'cache', '--save', 'authored', '--query', 'StoredCaptureNeedle',
                         '--kind', 'string')
    assert code == 0
    identity = saved['result']['item']['saved_id']
    code, doc = invoke(root, tmp_path / 'cache', '--saved-run', identity)
    assert code == 0 and any(e['group'].startswith('tool:floss:') for h in doc['result']['hits']
                            for e in h['evidence'])


def test_sidecar_snapshot_revalidates_without_a_database_write(captured, monkeypatch):
    service, store = captured
    monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
    store.publish_evidence(store.latest('floss', 'newer')[1])
    first, groups = specs(service)
    assert groups['tool:floss:newer'].buildable
    row = entry(service, 'tool-evidence')
    (service.root / row.body['sidecar']).write_bytes(b'corrupt')
    second, groups = specs(service, first)
    assert second is not first and groups['tool:floss:newer'].status == 'unavailable'


def test_changed_evidence_with_same_configuration_uses_new_segment(captured):
    service, _store = captured
    _first, groups = specs(service)
    old = groups['tool:floss:newer'].digest16
    publish_tool(service, 'newer', run_id='replacement-output', label='DifferentStoredNeedle')
    _second, groups = specs(service)
    assert groups['tool:floss:newer'].digest16 != old
    assert [row.display for row in groups['tool:floss:newer'].documents()] == ['DifferentStoredNeedle']


@pytest.mark.parametrize('damage', ['configuration', 'truncated', 'truncated-types', 'stale'])
def test_absence_requires_two_complete_admitted_comparable_sources(captured, damage):
    service, store = captured
    first, _groups = specs(service)
    assert first.comparable('floss')
    if damage == 'configuration':
        row = entry(service, RUN_KIND, 'older')
        rewrite(service, row, {**row.body, 'config_digest': 'f' * 64})
    elif damage in ('truncated', 'truncated-types'):
        flags = {'truncated': True} if damage == 'truncated' else {'truncated_types': ('static',)}
        evidence = store.latest('floss', 'older')[1].model_copy(update=flags)
        # Replace the current evidence row with an ordinarily published truncated set.
        service.store.connection.execute("DELETE FROM enrichment_entries WHERE kind='tool-evidence' AND id=?",
                                          (entry(service, 'tool-evidence', 'older').id,))
        service.store.connection.commit()
        store.publish_evidence(evidence)
    else:
        service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?',
                                         (entry(service, RUN_KIND, 'older').id,))
    second, groups = specs(service)
    assert not second.comparable('floss')
    if damage in ('truncated', 'truncated-types'):
        assert groups['tool:floss:older'].reason


def test_cve_body_integrity_and_identity_are_not_erased_by_reserialization(captured):
    service, _store = captured
    add_cve(service)
    row = EnrichmentStore(service.store).entries('cve-snapshot')[0]
    text = row.body_json[:-1] + ',"cve_id":"CVE-2099-10002"}'
    service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
        (text, hashlib.sha256(text.encode()).hexdigest(), row.id))
    _snap, groups = specs(service)
    assert groups['cve'].status == 'unavailable'


def test_injected_specs_do_not_capture_production_store(captured, tmp_path, monkeypatch):
    from patchtrace.search import wiring
    service, _store = captured
    monkeypatch.setattr(wiring, 'snapshot_sources', lambda *_a, **_k: pytest.fail('injected source path captured'))
    out = io.StringIO()
    assert cli.main(['P', '--status', '--json', '--cache-dir', str(tmp_path / 'cache')],
        opener=lambda _p: (service, None), extra_specs=lambda _request: (), stdout=out) == 0


def test_cli_search_does_not_modify_stored_project(captured, tmp_path):
    service, _store = captured
    root = service.root
    before = tuple(service.store.connection.iterdump())
    service.close()
    assert invoke(root, tmp_path / 'cache', '--query', 'StoredCaptureNeedle')[0] == 0
    with ProjectService.open(root) as reopened:
        assert tuple(reopened.store.connection.iterdump()) == before


def test_production_string_presence_requires_current_complete_counterpart(captured, tmp_path):
    service, _store = captured
    publish_tool(service, 'older', run_id='empty-older', empty=True)
    root = service.root
    service.close()
    code, doc = invoke(root, tmp_path / 'cache', '--query', 'StoredCaptureNeedle', '--kind', 'string')
    assert code == 0 and doc['result']['hits'][0]['presence']['older'] == 'absent'
    with ProjectService.open(root) as owner:
        row = entry(owner, RUN_KIND, 'older')
        owner.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
        owner.store.connection.commit()
    code, doc = invoke(root, tmp_path / 'cache', '--query', 'StoredCaptureNeedle', '--kind', 'string')
    assert code == 0 and doc['result']['hits'][0]['presence']['older'] == 'unknown'


def test_production_tool_strings_preserve_secret_redaction_and_hash_search(captured, tmp_path):
    service, _store = captured
    secret = 'password=hunter2hunter2'
    publish_tool(service, 'newer', run_id='secret-newer', label=secret)
    root = service.root
    service.close()
    _code, doc = invoke(root, tmp_path / 'cache', '--query', 'hunter2hunter2', '--kind', 'string')
    assert not doc['result']['hits'] and secret not in json.dumps(doc)
    code, doc = invoke(root, tmp_path / 'cache', '--query', hashlib.sha256(secret.encode()).hexdigest(),
                        '--kind', 'string')
    assert code == 0 and doc['result']['hits'] and secret not in json.dumps(doc)


def test_advisory_facts_with_duplicate_json_are_not_a_searchable_partial_set(captured):
    service, _store = captured
    add_advisory(service)
    row = EnrichmentStore(service.store).entries(FACTS_KIND)[0]
    path = service.root / row.body['path']
    data = path.read_bytes()
    facts = json.loads(data)
    changed = data[:-1] + b',"title":' + json.dumps(facts['title']).encode() + b'}'
    path.write_bytes(changed)
    rewrite(service, row, {**row.body, 'sha256': hashlib.sha256(changed).hexdigest()})
    _snapshot, groups = specs(service)
    assert groups['adv'].status == 'unavailable'
