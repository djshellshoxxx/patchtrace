"""SPEC-07h H1: enrichment row retention and the storage-cap fallback."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from patchtrace.enrichment import pipeline, storage
from patchtrace.enrichment.contracts import DEFAULT_WEIGHTS, EnrichmentError, RankingConfig
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.service import ProjectService

FUTURE = '9999-01-01T00:00:00+00:00'


@pytest.fixture
def service(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    yield svc
    if not svc.store.closed:
        svc.close()


@pytest.fixture
def current():
    return Guard('p', 'r', 'a' * 64, 'b' * 64)


def old_guard(current, n):
    return Guard(current.project_id, current.run_id, current.raw_sha256, f'{n:064x}')


def make_gen(store, current, n, *, stale=False, config='cfg', wil=None, size=50, default=False, protect=()):
    """Publish one full generation (signals, ranking, wil, pipeline) the way pipeline.publish does."""
    g = old_guard(current, n) if stale else current
    rid, wil_key = f'r{n}', wil or f'w{n}'
    for kind, key in (('signals', rid), ('ranking', rid), ('wil', wil_key)):
        store.publish(kind, g, current, 0, 'complete', {'pad': 'x' * size}, f'{kind}:{key}', protect=protect)
    store.publish('pipeline', g, current, 0, 'complete',
                  {'stage_ids': {'ranking': rid, 'wil': wil_key, 'signals': rid}, 'config_digest': config,
                   'default_profile': default}, f'pipeline:{rid}', protect=protect)
    return {f'signals:{rid}', f'ranking:{rid}', f'wil:{wil_key}', f'pipeline:{rid}'}


def ids(service, kinds=None):
    q = 'SELECT id FROM enrichment_entries'
    rows = service.store.connection.execute(q).fetchall()
    return {r[0] for r in rows if kinds is None or r[0].split(':')[0] in kinds}


def test_many_current_generations_are_bounded_and_default_survives(service, current):
    store = EnrichmentStore(service.store)
    first = make_gen(store, current, 0, default=True)
    for n in range(1, 13):
        make_gen(store, current, n)
    deleted = store.apply_retention(current, started=FUTURE)
    pipes = {e.id for e in store.entries('pipeline')}
    assert len(pipes) == storage.KEEP_CURRENT + 1 and deleted > 0  # newest 8 plus the live default profile
    assert first <= ids(service) and 'pipeline:r12' in pipes and 'pipeline:r1' not in pipes
    assert 'signals:r1' not in ids(service) and 'wil:w1' not in ids(service)  # whole generation removed


def test_stale_generations_keep_two_per_config(service, current):
    store = EnrichmentStore(service.store)
    for n in range(6):
        make_gen(store, current, n, stale=True, config='A')
    for n in range(10, 14):
        make_gen(store, current, n, stale=True, config='B')
    store.apply_retention(current, started=FUTURE)
    assert {e.id for e in store.entries('pipeline')} == {'pipeline:r4', 'pipeline:r5', 'pipeline:r12', 'pipeline:r13'}


def test_shared_wil_rows_are_reference_counted(service, current):
    store = EnrichmentStore(service.store)
    make_gen(store, current, 0, wil='shared')
    make_gen(store, current, 1, wil='shared')
    for n in range(2, 9):
        make_gen(store, current, n)
    assert len(store.entries('pipeline')) == 9
    store.apply_retention(current, started=FUTURE)
    rows = ids(service)
    assert 'pipeline:r0' not in rows and 'signals:r0' not in rows
    assert 'wil:shared' in rows and 'pipeline:r1' in rows  # still referenced by generation 1
    make_gen(store, current, 9)
    store.apply_retention(current, started=FUTURE)
    assert 'wil:shared' not in ids(service)


def test_secondary_matches_and_unknown_rows_are_never_evicted(service, current, monkeypatch):
    store = EnrichmentStore(service.store)
    for n in range(3):
        store.publish('secondary-matches', current, current, 0, 'complete', {'n': n}, f'secondary-matches:{n}')
    store.publish('cve-snapshot', current, current, 0, 'complete', {'n': 1}, 'cve-snapshot:1')
    for n in range(12):
        make_gen(store, current, n, stale=True)
    store.apply_retention(current, started=FUTURE)
    kept = ids(service)
    assert {f'secondary-matches:{n}' for n in range(3)} | {'cve-snapshot:1'} <= kept
    monkeypatch.setattr(storage, 'MAX_TOTAL', 600)
    with pytest.raises(EnrichmentError):
        store.make_room(10_000, current)  # cannot be met: nothing is deleted
    assert {f'secondary-matches:{n}' for n in range(3)} <= ids(service)


def test_read_only_store_deletes_nothing(service, current):
    store = EnrichmentStore(service.store)
    for n in range(12):
        make_gen(store, current, n)
    service.store.connection.execute("UPDATE enrichment_meta SET value='2' WHERE key='extension_version'")
    service.store.connection.commit()
    newer = EnrichmentStore(service.store)
    before = ids(service)
    assert newer.apply_retention(current, started=FUTURE) == 0 and ids(service) == before
    with pytest.raises(EnrichmentError):
        newer.make_room(1, current)
    assert ids(service) == before


def test_backup_created_once_verified_and_meta_written(service, current):
    store = EnrichmentStore(service.store)
    for n in range(10):
        make_gen(store, current, n)
    assert not list((service.root / 'backups').glob('project-pre-retention-*'))
    assert store.apply_retention(current, started=FUTURE) > 0
    backups = list((service.root / 'backups').glob('project-pre-retention-*.sqlite3'))
    assert len(backups) == 1
    copy = sqlite3.connect(backups[0])
    try:
        assert copy.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert copy.execute('SELECT COUNT(*) FROM enrichment_entries').fetchone()[0] == 40  # pre-deletion state
    finally:
        copy.close()
    meta = service.store.connection.execute(
        "SELECT value FROM enrichment_meta WHERE key='retention_version'").fetchone()
    assert meta == ('1',)
    make_gen(store, current, 10)
    make_gen(store, current, 11)
    assert store.apply_retention(current, started=FUTURE) > 0
    assert len(list((service.root / 'backups').glob('project-pre-retention-*.sqlite3'))) == 1


def test_failure_inside_the_transaction_rolls_back(service, current, monkeypatch):
    store = EnrichmentStore(service.store)
    for n in range(10):
        make_gen(store, current, n)
    before = ids(service)
    monkeypatch.setattr(storage, '_RETENTION_META_SQL', 'INSERT INTO no_such_table VALUES(1)')
    assert store.apply_retention(current, started=FUTURE) == 0
    assert ids(service) == before
    assert not service.store.connection.in_transaction


def test_orphans_only_reaped_when_older_than_the_publish_call(service, current):
    store = EnrichmentStore(service.store)
    make_gen(store, current, 0)
    store.publish('signals', current, current, 0, 'complete', {'x': 1}, 'signals:orphan')  # mid-publish set
    started = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    store.apply_retention(current, started=started)
    assert 'signals:orphan' in ids(service)
    store.apply_retention(current, started=FUTURE)
    assert 'signals:orphan' not in ids(service) and 'pipeline:r0' in ids(service)
    store.publish('signals', current, current, 0, 'complete', {'x': 1}, 'signals:orphan2')
    store.apply_retention(current)  # no `started`: orphans are never touched
    assert 'signals:orphan2' in ids(service)


def test_protected_ids_are_never_deleted(service, current):
    store = EnrichmentStore(service.store)
    mine = make_gen(store, current, 0, stale=True)
    for n in range(1, 6):
        make_gen(store, current, n, stale=True)
    store.apply_retention(current, protect=mine, started=FUTURE)
    assert mine <= ids(service)


def test_cap_fallback_frees_stale_then_older_current_generations(service, current, monkeypatch):
    store = EnrichmentStore(service.store)
    monkeypatch.setattr(storage, 'MAX_TOTAL', 2_000)
    stale_rows = set()
    for n in range(4):
        stale_rows |= make_gen(store, current, n, stale=True, size=100)
    live = make_gen(store, current, 50, default=True, size=100)
    assert sum(len(r) for r in ids(service)) > 0
    # About 1.9 KB is used; a new 600-byte generation needs room.
    make_gen(store, current, 60, size=100, protect={'signals:r60', 'ranking:r60', 'wil:w60', 'pipeline:r60'})
    rows = ids(service)
    assert {'signals:r60', 'ranking:r60', 'wil:w60', 'pipeline:r60'} <= rows
    assert live <= rows  # the live default-profile generation is untouched
    assert len(rows & stale_rows) < len(stale_rows)


def test_still_over_cap_raises_and_leaves_rows_untouched(service, current, monkeypatch):
    store = EnrichmentStore(service.store)
    monkeypatch.setattr(storage, 'MAX_TOTAL', 1_500)
    live = make_gen(store, current, 1, default=True, size=100)
    make_gen(store, current, 2, stale=True, size=100)
    before = ids(service)
    with pytest.raises(EnrichmentError) as exc:
        store.publish('signals', current, current, 0, 'complete', {'pad': 'x' * 1_400}, 'signals:big')
    assert exc.value.code == 'PT-ENRICH-LIMIT' and exc.value.recoverable and 'MiB' in exc.value.message
    assert ids(service) == before and live <= before


def test_v1_open_save_backup_with_retention_applied(service, current, tmp_path):
    store = EnrichmentStore(service.store)
    for n in range(12):
        make_gen(store, current, n)
    store.apply_retention(current, started=FUTURE)
    root = service.root
    service.close()
    reopened = ProjectService.open(root)
    try:
        assert reopened.store.connection.execute('PRAGMA user_version').fetchone()[0] == 1
        reopened.save()
        copy = reopened.backup(tmp_path / 'copy')
    finally:
        reopened.close()
    restored = ProjectService.open(copy)
    try:
        assert len(EnrichmentStore(restored.store).entries('pipeline')) == storage.KEEP_CURRENT
    finally:
        restored.close()


def test_real_pipeline_publish_applies_retention_and_default_stays_loadable(service):
    store = EnrichmentStore(service.store)
    default = pipeline.run(service.project)
    pipeline.publish(store, service.project, default)
    for n in range(1, 12):
        config = RankingConfig(weights={**DEFAULT_WEIGHTS, 'ERR': 5 + n})
        result = pipeline.run(service.project, pipeline.PipelineOptions(config=config))
        pipeline.publish(store, service.project, result)
    assert len(store.entries('pipeline')) <= storage.KEEP_CURRENT + 1
    ranking, sets, note = pipeline.load_default(store, service.project)
    assert ranking is not None and sets and not note
    assert ranking == default.ranking
