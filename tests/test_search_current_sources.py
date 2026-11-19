"""Current-artifact admission for newly connected search groups; synthetic project and real store."""
from __future__ import annotations

import hashlib
import json

import pytest
from test_capa_cli import stored_project
from test_intel_tools_cli import clean_env  # noqa: F401

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools.common import evidence_entry_id
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.search import wiring
from patchtrace.service import ProjectService


def tools(service):
    return ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)


def capa_specs(snapshot):
    return {s.side: s for s in snapshot.extra_specs() if s.group.startswith('tool:capa:')}


def test_orientation_change_does_not_search_the_previous_side_results(tmp_path):
    root = stored_project(tmp_path)
    with ProjectService.open(root) as service:
        first = wiring.snapshot_sources(service)
        assert all(s.buildable for s in capa_specs(first).values()) and first.comparable('capa')
        service.swap_orientation()
        after = wiring.snapshot_sources(service, first)
        assert after is not first
        assert {s.status for s in capa_specs(after).values()} == {'unavailable'}
        assert not after.comparable('capa')


@pytest.mark.parametrize(('part', 'field', 'value'), [
    ('run', 'input_artifact_hash', 'f' * 64),
    ('run', 'engine', 'floss'),
    ('run', 'side', 'older'),
    ('evidence', 'artifact_sha256', 'f' * 64),
    ('evidence', 'engine', 'floss'),
    ('evidence', 'side', 'older'),
    ('evidence', 'cache_key', 'f' * 64),
    ('evidence', 'config_digest', 'f' * 64),
    ('evidence', 'run_id', 'another-run'),
])
def test_selected_tool_rows_require_current_artifact_and_run_identity(tmp_path, part, field, value):
    root = stored_project(tmp_path)
    with ProjectService.open(root) as service:
        run, evidence = tools(service).latest('capa', 'newer')
        selected = run if part == 'run' else evidence
        entry_id = run.run_id if part == 'run' else evidence_entry_id(evidence)
        body = selected.model_dump(mode='json')
        body[field] = value
        encoded = json.dumps(body)
        service.store.connection.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
                                         (encoded, hashlib.sha256(encoded.encode()).hexdigest(), entry_id))
        snapshot = wiring.snapshot_sources(service)
        assert capa_specs(snapshot)['newer'].status == 'unavailable'
        assert not snapshot.comparable('capa')


def test_valid_cache_hit_can_reuse_the_original_evidence_run_id(tmp_path):
    root = stored_project(tmp_path)
    with ProjectService.open(root) as service:
        store = tools(service)
        run, evidence = store.latest('capa', 'newer')
        cached = run.model_copy(update={'run_id': 'cached-search-run', 'cache_hit': True})
        store.publish_run(cached)
        selected, reused = store.latest('capa', 'newer')
        assert selected.run_id == cached.run_id and reused.run_id == evidence.run_id != selected.run_id
        snapshot = wiring.snapshot_sources(service)
        assert capa_specs(snapshot)['newer'].buildable and snapshot.comparable('capa')


def test_body_hash_change_invalidates_snapshot_even_if_created_does_not_change(tmp_path):
    root = stored_project(tmp_path)
    with ProjectService.open(root) as service:
        first = wiring.snapshot_sources(service)
        run, _evidence = tools(service).latest('capa', 'newer')
        db = service.store.connection
        body = run.model_dump(mode='json')
        body['config_digest'] = 'f' * 64
        encoded = json.dumps(body)
        db.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
                   (encoded, hashlib.sha256(encoded.encode()).hexdigest(), run.run_id))
        after = wiring.snapshot_sources(service, first)
        assert after is not first
        assert capa_specs(after)['newer'].status == 'unavailable'
        assert not after.comparable('capa')


def test_metadata_limit_refuses_before_reading_tool_bodies(tmp_path, monkeypatch):
    root = stored_project(tmp_path)
    with ProjectService.open(root) as service:
        monkeypatch.setattr(wiring, 'MAX_SOURCE_ROWS', 0, raising=False)
        reads = []
        entries = EnrichmentStore.entries

        def observed(store, *args, **kwargs):
            reads.append(args)
            return entries(store, *args, **kwargs)

        monkeypatch.setattr(EnrichmentStore, 'entries', observed)
        snapshot = wiring.snapshot_sources(service)
        assert not reads
        assert {s.status for s in snapshot.extra_specs()} == {'unavailable'}
        assert all('limit' in s.reason for s in snapshot.extra_specs())


def test_optional_source_limit_preserves_normal_note_search(tmp_path, monkeypatch, capsys):
    root = stored_project(tmp_path)
    with ProjectService.open(root) as service:
        service.annotate(service.project.id, 'independent investigation marker')
    args = ['search', str(root), '--query', 'independent investigation marker', '--json',
            '--cache-dir', str(tmp_path / 'cache')]
    capsys.readouterr()
    assert cli.main(args) == 0
    capsys.readouterr()
    monkeypatch.setattr(wiring, 'MAX_SOURCE_ROWS', 0)
    code = cli.main(args)
    result = json.loads(capsys.readouterr().out)['result']
    assert code == 0
    assert any(e['kind'] == 'note' for hit in result['hits'] for e in hit['evidence'])
    optional = [r for r in result['coverage'] if r['group'].startswith('tool:') or r['group'] in ('adv', 'cve')]
    assert len(optional) == 8 and {r['status'] for r in optional} == {'unavailable'}
    assert all('limit' in r['reason'] for r in optional)


@pytest.mark.parametrize(('part', 'column', 'value'), [
    ('run', 'stale', 1), ('run', 'project_id', 'foreign-project'),
    ('evidence', 'stale', 1), ('evidence', 'project_id', 'foreign-project'),
])
def test_selected_row_guard_refusal_removes_previous_index_hits(tmp_path, capsys, part, column, value):
    root = stored_project(tmp_path)
    args = ['search', str(root), '--query', 'write file', '--json',
            '--cache-dir', str(tmp_path / 'cache')]

    def query():
        capsys.readouterr()
        code = cli.main(args)
        result = json.loads(capsys.readouterr().out)['result']
        found = [e for h in result['hits'] for e in h['evidence'] if e['group'] == 'tool:capa:newer']
        coverage = next(r for r in result['coverage'] if r['group'] == 'tool:capa:newer')
        return code, found, coverage

    code, found, _coverage = query()
    assert code == 0 and found
    with ProjectService.open(root) as service:
        first = wiring.snapshot_sources(service)
        run, evidence = tools(service).latest('capa', 'newer')
        entry_id = run.run_id if part == 'run' else evidence_entry_id(evidence)
        service.store.connection.execute(f'UPDATE enrichment_entries SET {column}=? WHERE id=?', (value, entry_id))
        second = wiring.snapshot_sources(service, first)
        service.store.connection.commit()
    with ProjectService.open(root) as reopened:
        persisted = reopened.store.connection.execute(f'SELECT {column} FROM enrichment_entries WHERE id=?',
                                                       (entry_id,)).fetchone()
        assert persisted == (value,)
    code, found, coverage = query()  # ordinary auto-build must exclude the previous cache segment
    assert code in (0, 4) and not found
    assert coverage['status'] == 'unavailable' and coverage['reason']
    assert second is not first and not second.comparable('capa')
    assert capa_specs(second)['newer'].status == 'unavailable'
    assert capa_specs(second)['older'].buildable
