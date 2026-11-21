"""Authored malformed storage and real SQLite; no original inputs or comparators executed."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from patchtrace.enrichment import storage
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet
from patchtrace.secondary.runs import EngineRun
from patchtrace.secondary.store import current_sets, publish_run
from patchtrace.service import ProjectService


@pytest.fixture
def case(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        project = service.project
        primary = next(r for r in project.runs if r.status == 'completed' and r.raw_sha256)
        guard = Guard(project.id, primary.id, primary.raw_sha256, 'f' * 64)
        original_snapshot = list(service.store.connection.execute('SELECT * FROM current_snapshot'))
        originals = {p: p.read_bytes() for folder in ('artifacts', 'runs')
                     for p in (service.root / folder).rglob('*') if p.is_file()}
        yield service, EnrichmentStore(service.store), guard
        assert list(service.store.connection.execute('SELECT * FROM current_snapshot')) == original_snapshot
        assert all(path.read_bytes() == content for path, content in originals.items())


def record(case, run_id, *, engine='rz-diff', status='failed', match_set_id=None):
    sides = {a.side: a.sha256 for a in case[0].project.artifacts}
    return EngineRun(run_id=run_id, engine=engine, engine_version='0.9.1', executable_path_sha256=None,
                     argv_digest='d' * 64, older_sha256=sides['older'], newer_sha256=sides['newer'],
                     orientation='older->newer', cache_key='c' * 64, status=status,
                     error_code='PT-SECONDARY-PROCESS' if status == 'failed' else None, returncode=1,
                     started_utc='2099-01-01T00:00:00Z', duration_ms=1, stderr_tail='authored outcome',
                     output_sha256=None, match_set_id=match_set_id)


def seed_run(case, run_id, **options):
    service, store, guard = case
    run = record(case, run_id, **options)
    return store.publish('engine-run', guard, guard, service.project.revision, 'complete',
                         run.model_dump(mode='json'), run.run_id)


def seed_set(case, *, legacy=False):
    service, store, guard = case
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    matches = tuple(SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=a, newer_address=a,
                                   older_name=None, newer_name=None, similarity_milli=500, similarity_text='0.5',
                                   confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')
                    for a in (16, 32))
    match_set = SecondaryMatchSet(contract='secondary/1' if legacy else 'secondary/2', engine='rz-diff',
                                  engine_version='0.9.1', older_sha256=sides['older'], newer_sha256=sides['newer'],
                                  file_sha256='2' * 64 if legacy else '1' * 64, matches=matches,
                                  run_id=None if legacy else 'r0')
    store.publish('secondary-matches', guard, guard, service.project.revision, 'complete',
                  match_set.model_dump(mode='json'), match_set.entry_id)
    return match_set


def seeded(case):
    for i in range(5):
        seed_run(case, f'r{i}')
    legacy = seed_set(case, legacy=True)
    return seed_set(case), legacy


def rows(case):
    return list(case[0].store.connection.execute('SELECT * FROM enrichment_entries ORDER BY id'))


def damage(case, kind, row_id, mode):
    db = case[0].store.connection
    text = db.execute('SELECT body FROM enrichment_entries WHERE id=?', (row_id,)).fetchone()[0]
    body = json.loads(text)
    if mode == 'list':
        text = '[]'
    elif mode == 'syntax':
        text = '{'
    elif mode == 'duplicate':
        text = '{"engine":"bindiff",' + text[1:]
    elif mode == 'nonfinite':
        text = '{"unexpected":NaN,' + text[1:]
    elif mode == 'field':
        body['engine'] = []
        text = json.dumps(body)
    elif mode == 'reference':
        body['match_set_id' if kind == 'engine-run' else 'run_id'] = []
        text = json.dumps(body)
    elif mode == 'contract':
        body['contract'] = 'engine-run/999' if kind == 'engine-run' else 'secondary/999'
        text = json.dumps(body)
    elif mode == 'identity':
        body['run_id' if kind == 'engine-run' else 'older_sha256'] = 'e' * 64
        text = json.dumps(body)
    elif mode == 'oversized':
        text = json.dumps({'padding': 'x' * 16384})
    digest = hashlib.sha256(text.encode()).hexdigest()
    with db:
        db.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                   (text, '0' * 64 if mode == 'digest' else digest, row_id))
        if mode == 'project':
            db.execute('UPDATE enrichment_entries SET project_id=? WHERE id=?', ('foreign-project', row_id))
        if mode == 'row_id':
            db.execute('UPDATE enrichment_entries SET id=? WHERE id=?', (sqlite3.Binary(row_id.encode()), row_id))
        if mode == 'null_id':
            db.execute('UPDATE enrichment_entries SET id=NULL WHERE id=?', (row_id,))


@pytest.mark.parametrize('kind', ['engine-run', 'secondary-matches'])
@pytest.mark.parametrize('mode', ['list', 'syntax', 'duplicate', 'nonfinite', 'field', 'reference',
                                  'contract', 'identity', 'digest', 'project', 'row_id', 'null_id'])
def test_indeterminate_metadata_preserves_every_original_row(case, kind, mode):
    _trusted, legacy = seeded(case)
    damage(case, kind, 'r1' if kind == 'engine-run' else legacy.entry_id, mode)
    before = rows(case)
    assert case[1].prune_runs(keep=1) == 0
    assert rows(case) == before
    assert not list((case[0].root / 'backups').glob('project-pre-retention-*'))


@pytest.mark.parametrize('kind', ['engine-run', 'secondary-matches'])
def test_oversized_body_is_not_decoded_for_eviction(case, monkeypatch, kind):
    _trusted, legacy = seeded(case)
    damage(case, kind, 'r1' if kind == 'engine-run' else legacy.entry_id, 'oversized')
    before = rows(case)
    monkeypatch.setattr(storage, 'MAX_ROW', 8192)
    original = storage.strict_json

    def bounded(text):
        assert len(text.encode()) <= 8192
        return original(text)

    monkeypatch.setattr(storage, 'strict_json', bounded)
    assert case[1].prune_runs(keep=1) == 0
    assert rows(case) == before


def test_healthy_groups_prune_with_backup_and_both_reference_directions_survive(case):
    trusted, _legacy = seeded(case)
    seed_run(case, 'referencing-set', match_set_id=trusted.entry_id)
    seed_run(case, 'other-engine', engine='bindiff')
    before_sets = [row for row in rows(case) if row[1] == 'secondary-matches']
    assert case[1].prune_runs(keep=1) == 4
    assert {e.id for e in case[1].entries('engine-run')} == {'r0', 'referencing-set', 'other-engine'}
    assert [row for row in rows(case) if row[1] == 'secondary-matches'] == before_sets
    assert list((case[0].root / 'backups').glob('project-pre-retention-*.sqlite3'))


@pytest.mark.parametrize('status', ['failed', 'ok'])
def test_committed_attempt_succeeds_when_malformed_reference_blocks_retention(case, status):
    trusted, legacy = seeded(case)
    damage(case, 'secondary-matches', legacy.entry_id, 'list')
    before = rows(case)
    service, store, guard = case
    run = record(case, 'new-attempt', status=status)
    entry = publish_run(store, guard, guard, service.project.revision, run)
    assert entry.id == run.run_id
    assert all(row in rows(case) for row in before)
    assert not service.store.connection.in_transaction
    assert {e.id for e in store.entries('engine-run')} == {'r0', 'r1', 'r2', 'r3', 'r4', run.run_id}
    assert {e.id for e, _ in current_sets(store)} == {trusted.entry_id}


@pytest.mark.parametrize('kind', ['engine-run', 'secondary-matches'])
@pytest.mark.parametrize('mode', ['list', 'row_id', 'null_id'])
def test_global_cap_never_reclaims_uncertain_rows(case, monkeypatch, kind, mode):
    _trusted, legacy = seeded(case)
    damage(case, kind, 'r1' if kind == 'engine-run' else legacy.entry_id, mode)
    service, store, guard = case
    before = rows(case)
    used = service.store.connection.execute('SELECT SUM(LENGTH(CAST(body AS BLOB))) FROM enrichment_entries').fetchone()[0]
    monkeypatch.setattr(storage, 'MAX_TOTAL', used + 1)
    with pytest.raises(EnrichmentError) as caught:
        publish_run(store, guard, guard, service.project.revision, record(case, 'over-cap'))
    assert caught.value.code == 'PT-ENRICH-LIMIT' and caught.value.recoverable
    assert rows(case) == before
    assert not service.store.connection.in_transaction


def test_global_cap_can_reclaim_healthy_unreferenced_attempts(case, monkeypatch):
    trusted, _legacy = seeded(case)
    service, store, guard = case
    used = service.store.connection.execute('SELECT SUM(LENGTH(CAST(body AS BLOB))) FROM enrichment_entries').fetchone()[0]
    monkeypatch.setattr(storage, 'MAX_TOTAL', used + 1)
    result = publish_run(store, guard, guard, service.project.revision, record(case, 'new-attempt'))
    assert result.id == 'new-attempt'
    assert {'r0', 'new-attempt'} <= {e.id for e in store.entries('engine-run')}
    assert len(store.entries('engine-run')) < 6
    assert {e.id for e, _ in current_sets(store)} == {trusted.entry_id}


@pytest.mark.parametrize('all_protected', [False, True])
def test_cap_respects_explicitly_protected_attempts_before_counting_space(case, all_protected):
    seeded(case)
    service, store, guard = case
    protected = {f'r{i}' for i in range(5)} if all_protected else {'r1'}
    before = rows(case)
    used = service.store.connection.execute('SELECT SUM(LENGTH(CAST(body AS BLOB))) FROM enrichment_entries').fetchone()[0]
    if all_protected:
        with pytest.raises(EnrichmentError) as caught:
            store.make_room(1, guard, protect=protected)
        assert caught.value.code == 'PT-ENRICH-LIMIT' and caught.value.recoverable
        assert rows(case) == before
    else:
        freed = store.make_room(1, guard, protect=protected)
        after = rows(case)
        assert all(row in after for row in before if row[0] in protected)
        remaining = service.store.connection.execute('SELECT SUM(LENGTH(CAST(body AS BLOB))) FROM enrichment_entries').fetchone()[0]
        assert freed == used - remaining > 0
        assert store.entry('engine-run', 'r2') is None  # oldest eligible unprotected attempt


@pytest.mark.parametrize('null_other_row', [False, True])
@pytest.mark.parametrize('fits', [False, True])
def test_upsert_counts_all_other_rows_and_preserves_exact_cap_accounting(case, monkeypatch, null_other_row, fits):
    _trusted, legacy = seeded(case)
    if null_other_row:
        damage(case, 'secondary-matches', legacy.entry_id, 'null_id')
    service, store, guard = case
    row_id = 'signals:authored-replacement'
    store.publish('signals', guard, guard, service.project.revision, 'complete', {'authored': 'old'}, row_id)
    before = rows(case)
    db = service.store.connection
    used = db.execute('SELECT SUM(LENGTH(CAST(body AS BLOB))) FROM enrichment_entries').fetchone()[0]
    old_size = db.execute('SELECT LENGTH(CAST(body AS BLOB)) FROM enrichment_entries WHERE id=?', (row_id,)).fetchone()[0]
    replacement = {'authored': 'new' * 30}
    new_size = len(json.dumps(replacement, sort_keys=True, separators=(',', ':')).encode())
    required = used - old_size + new_size
    monkeypatch.setattr(storage, 'MAX_TOTAL', required if fits else required - 1)
    protected = {row[0] for row in before if type(row[0]) is str}
    if fits:
        result = store.publish('signals', guard, guard, service.project.revision, 'complete', replacement,
                               row_id, protect=protected)
        assert result.body == replacement
        assert all(row in rows(case) for row in before if row[0] != row_id)
        assert db.execute('SELECT SUM(LENGTH(CAST(body AS BLOB))) FROM enrichment_entries').fetchone()[0] == required
    else:
        with pytest.raises(EnrichmentError) as caught:
            store.publish('signals', guard, guard, service.project.revision, 'complete', replacement,
                           row_id, protect=protected)
        assert caught.value.code == 'PT-ENRICH-LIMIT' and caught.value.recoverable
        assert rows(case) == before


@pytest.mark.parametrize('operation', ['publish', 'prune', 'cap'])
def test_sqlite_write_errors_keep_existing_propagation_and_rows(case, operation):
    seeded(case)
    service, store, guard = case
    before = rows(case)
    service.store.connection.execute('PRAGMA query_only=ON')
    try:
        if operation == 'publish':
            with pytest.raises(sqlite3.OperationalError):
                publish_run(store, guard, guard, service.project.revision, record(case, 'write-refused'))
        elif operation == 'prune':
            assert store.prune_runs(keep=1) == 0
        else:
            with pytest.raises(EnrichmentError) as caught:
                store.make_room(1, guard)
            assert caught.value.code == 'PT-ENRICH-LIMIT' and caught.value.recoverable
    finally:
        service.store.connection.execute('PRAGMA query_only=OFF')
    assert rows(case) == before
    assert not service.store.connection.in_transaction


def test_unexpected_post_write_exception_still_propagates_with_committed_row(case, monkeypatch):
    seeded(case)
    service, store, guard = case

    def fail_after_commit(*args, **kwargs):
        assert not service.store.connection.in_transaction
        assert store.entry('engine-run', 'post-write') is not None
        raise RuntimeError('authored post-write failure')

    monkeypatch.setattr(store, 'prune_runs', fail_after_commit)
    with pytest.raises(RuntimeError, match='authored post-write failure'):
        publish_run(store, guard, guard, service.project.revision, record(case, 'post-write'))
    assert store.entry('engine-run', 'post-write') is not None
