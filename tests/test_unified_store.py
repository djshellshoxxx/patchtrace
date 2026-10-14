"""SPEC-31 S0a store: result sidecars, pointer rows, cache misses, own retention and the additive-only guarantees
(old readers never see unified kinds; enrichment retention never deletes them). Synthetic sample projects only."""
from __future__ import annotations

import gzip
import hashlib
import json
import threading

import pytest

from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.sample import create_sample
from patchtrace.secondary import load_secondary
from patchtrace.secondary.store import current_sets
from patchtrace.unified import keys, store
from patchtrace.unified.contracts import ChangeFacts, SideRef, SourceRef, UnifiedMatch, UnifiedRun
from patchtrace.unified.limits import UnifiedError

FUTURE = '9999-01-01T00:00:00+00:00'
CH = tuple((c, 'equal') for c in ('C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8'))


@pytest.fixture
def case(tmp_path):
    svc = create_sample(tmp_path / 'p')
    yield svc
    if not svc.store.closed:
        svc.close()


def _ids(svc, kinds=None):
    rows = svc.store.connection.execute('SELECT id, kind FROM enrichment_entries').fetchall()
    return {i for i, k in rows if kinds is None or k in kinds}


def _rows(old, new, n=2):
    out, facts = [], []
    for i in range(n):
        rid = keys.row_id(old, new, [0x1000 + 16 * i], [0x2000 + 16 * i])
        out.append(UnifiedMatch(row_id=rid, older=(SideRef(rva=0x1000 + 16 * i, name=f'f{i}', kind='function'),),
                                newer=(SideRef(rva=0x2000 + 16 * i, name=f'f{i}', kind='function'),),
                                decision='matched', materiality='unchanged', atoms=()))
        facts.append(ChangeFacts(row_id=rid, verdict='unchanged', proof='UNCH/1', channels=CH, eh='absent'))
    return out, facts


def _stage(svc, *, config='c', n=2, created='2026-10-14T12:00:00+00:00', version='synthetic'):
    run = svc.project.runs[-1]
    old = next(a.sha256 for a in svc.project.artifacts if a.side == 'older')
    new = next(a.sha256 for a in svc.project.artifacts if a.side == 'newer')
    staged = store.new_staging_dir(svc.store.root, run.id)
    rows, facts = _rows(old, new, n)
    manifest = store.write_result(
        staged, older_sha256=old, newer_sha256=new, ghidriff_run_id=run.id, ghidriff_raw_sha256=run.raw_sha256,
        ir_older=None, ir_newer=None, sources=(SourceRef(source='ghidriff', entry_id=run.id,
                                                          file_sha256=run.raw_sha256, version=version),),
        manual_digest=keys.manual_digest([]), config_digest=hashlib.sha256(config.encode()).hexdigest(),
        status='complete', limitations=(), rows=rows, facts=facts, created_utc=created)
    guard = Guard(svc.project.id, run.id, run.raw_sha256, manifest.result_id)
    return staged, manifest, guard


def _publish(svc, **kw):
    staged, manifest, guard = _stage(svc, **kw)
    return store.publish_result(EnrichmentStore(svc.store), staged, guard=guard, current=guard, revision=1)


def test_write_verify_read_round_trip(case):
    staged, manifest, _ = _stage(case)
    assert store.verify_result_dir(staged) == manifest
    rows = list(store.read_rows(staged, manifest))
    assert [r.older[0].name for r in rows] == ['f0', 'f1'] and len(list(store.read_facts(staged, manifest))) == 2
    with open(staged / 'rows.jsonl.gz', 'rb') as f:
        assert f.read(10)[4:8] == b'\x00\x00\x00\x00'  # gzip mtime 0: no timestamp in the container
    assert keys.result_key(keys.result_key_inputs(manifest)) == manifest.result_id
    assert manifest.counts.decisions.matched == 2 and manifest.counts.materiality.unchanged == 2


def test_part_hash_mismatch_is_rejected(case):
    """02 s8 invalid example: a manifest whose part SHA-256 differs from the file."""
    staged, manifest, _ = _stage(case)
    rows = gzip.decompress((staged / 'rows.jsonl.gz').read_bytes()).replace(b'"f0"', b'"g0"')
    (staged / 'rows.jsonl.gz').write_bytes(gzip.compress(rows))
    with pytest.raises(UnifiedError) as info:
        store.verify_result_dir(staged)
    assert info.value.reason == 'part-hash-mismatch'


def test_write_refuses_wrong_row_ids_and_orphan_facts(case):
    staged, _, _ = _stage(case)
    rows, facts = _rows('a' * 64, 'b' * 64)
    with pytest.raises(UnifiedError):
        store.write_result(staged, older_sha256='c' * 64, newer_sha256='d' * 64, ghidriff_run_id='r',
                           ghidriff_raw_sha256='e' * 64, ir_older=None, ir_newer=None, sources=(),
                           manual_digest='f' * 64, config_digest='f' * 64, status='complete', limitations=(),
                           rows=rows, facts=facts)


def test_publish_moves_dir_and_writes_pointer_row(case):
    published = _publish(case)
    assert published.directory.name == published.manifest.result_id[:16]
    assert published.pointer.relative_dir.startswith(f'runs/{case.project.runs[-1].id}/unified/results/')
    loaded = store.load_result(EnrichmentStore(case.store), published.entry.guard)
    assert loaded.state == 'current' and loaded.manifest == published.manifest
    again = _publish(case)  # idempotent: same row id, same directory, staging removed
    assert again.entry.id == published.entry.id and again.directory == published.directory
    assert not [p for p in published.directory.parent.iterdir() if p.name.startswith('tmp-')]


def test_publish_refuses_guard_mismatch_and_wrong_thread_before_moving(case):
    staged, manifest, guard = _stage(case)
    enrichment = EnrichmentStore(case.store)
    bad = Guard(guard.project_id, guard.run_id, guard.raw_sha256, 'f' * 64)
    with pytest.raises(UnifiedError) as info:
        store.publish_result(enrichment, staged, guard=bad, current=bad, revision=1)
    assert info.value.reason == 'guard-mismatch' and staged.is_dir()
    errors = []
    thread = threading.Thread(target=lambda: errors.append(_catch(lambda: store.publish_result(
        enrichment, staged, guard=guard, current=guard, revision=1))))
    thread.start()
    thread.join()
    assert errors[0].reason == 'wrong-thread' and staged.is_dir()


def _catch(fn):
    try:
        fn()
    except UnifiedError as exc:
        return exc
    return None


def test_missing_or_tampered_sidecar_is_a_cache_miss_not_a_crash(case):
    published = _publish(case)
    enrichment = EnrichmentStore(case.store)
    (published.directory / 'manifest.json').write_bytes(b'{"contract":"unified-result/1"}\n')
    loaded = store.load_result(enrichment, published.entry.guard)
    assert loaded.state == 'invalid' and loaded.manifest is None
    assert store.cached_result(enrichment, published.manifest.result_id) is None
    store._rmtree(published.directory)
    assert store.load_result(enrichment, published.entry.guard).reason == 'dir-missing'


def test_corrupt_or_invalid_pointer_rows_are_cache_misses(case):
    published = _publish(case)
    db = case.store.connection
    db.execute("UPDATE enrichment_entries SET body_sha256='00' WHERE id=?", (published.entry.id,))
    db.commit()
    enrichment = EnrichmentStore(case.store)
    loaded = store.load_result(enrichment, published.entry.guard)
    assert loaded.state == 'none' and loaded.skipped == (published.entry.id,)
    assert store.cached_result(enrichment, published.manifest.result_id) is None


def test_stale_guard_is_reported_as_stale(case):
    published = _publish(case)
    moved = Guard(published.entry.guard.project_id, 'other-run', 'a' * 64, 'b' * 64)
    loaded = store.load_result(EnrichmentStore(case.store), moved)
    assert loaded.state == 'stale' and loaded.reason == 'guard-moved' and loaded.manifest is not None


def test_retention_keeps_l32_per_config_and_never_touches_other_kinds(case):
    enrichment = EnrichmentStore(case.store)
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)
    enrichment.publish('signals', g, g, 1, 'complete', {'items': []}, 'signals:x')
    # result_id hashes the inputs (not the rows): vary one input per result, keep one config_digest
    published = [_publish(case, version=f'v{i}', config='same') for i in range(5)]
    assert len({p.entry.id for p in published}) == 5
    kept = _ids(case, {'unified-result'})
    assert kept == {p.entry.id for p in published[-3:]}  # L-32 = 3 newest per config_digest
    assert 'signals:x' in _ids(case)
    assert not published[0].directory.exists() and published[-1].directory.exists()
    assert list((case.store.root / 'backups').glob('project-pre-unified-retention-*.sqlite3'))


def test_delete_own_refuses_foreign_kinds(case):
    enrichment = EnrichmentStore(case.store)
    with pytest.raises(UnifiedError) as info:
        store.delete_own(enrichment, ['signals:x'], kinds=('signals',))
    assert info.value.reason == 'foreign-kind'
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)
    enrichment.publish('signals', g, g, 1, 'complete', {}, 'signals:x')
    assert store.delete_own(enrichment, ['signals:x']) == 0 and 'signals:x' in _ids(case)


def test_run_rows_keep_newest_eight(case):
    enrichment = EnrichmentStore(case.store)
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)
    for i in range(10):
        started = f'2026-10-14T12:00:{i:02d}+00:00'
        run = UnifiedRun(run_id=keys.unified_run_id('c' * 64, started), result_id=None, status='failed',
                         error_code='PT-UNIFIED-EXTRACT', started_utc=started, duration_ms=1)
        store.publish_run(enrichment, run, guard=g, current=g, revision=1)
    _publish(case)
    assert len(_ids(case, {'unified-run'})) == store.RUN_KEEP


def test_unified_rows_survive_enrichment_retention(case):
    published = _publish(case)
    enrichment = EnrichmentStore(case.store)
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)
    run = UnifiedRun(run_id=keys.unified_run_id('c' * 64, FUTURE), result_id=published.manifest.result_id,
                     status='ok', started_utc='2026-10-14T12:00:00+00:00', duration_ms=1)
    store.publish_run(enrichment, run, guard=g, current=g, revision=1)
    for n in range(12):
        rid = f'r{n}'
        for kind in ('signals', 'ranking', 'wil'):
            enrichment.publish(kind, g, g, 0, 'complete', {'pad': 'x' * 64}, f'{kind}:{rid}')
        enrichment.publish('pipeline', g, g, 0, 'complete', {'stage_ids': {'ranking': rid, 'wil': rid},
                                                             'config_digest': 'c'}, f'pipeline:{rid}')
    unified = _ids(case, set(store.UNIFIED_KINDS))
    assert enrichment.apply_retention(g, started=FUTURE) > 0
    enrichment.prune_runs(keep=0)
    enrichment.make_room(1, g)
    assert _ids(case, set(store.UNIFIED_KINDS)) == unified == {published.entry.id, run.run_id}
    assert 'unified-run' not in storage.DERIVED_KINDS and 'unified-result' not in storage.DERIVED_KINDS


def test_old_reader_ignores_unified_kinds(case, monkeypatch):
    enrichment = EnrichmentStore(case.store)
    enrichment.ensure()
    before = (load_secondary(enrichment), current_sets(enrichment))
    _publish(case)
    meta = case.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
    assert meta.fetchone()[0] == '1'  # no extension_version bump: v1 clients keep full access
    old_kinds = frozenset(storage.KINDS) - {'unified-run', 'unified-result', 'advisory-source', 'advisory-facts',
                                             'tool-run', 'tool-evidence', 'patch-intent'}
    monkeypatch.setattr(storage, 'KINDS', old_kinds)  # a pre-SPEC-31 reader: queries by kind only
    old = EnrichmentStore(case.store)
    for kind in sorted(old_kinds):
        assert all(e.kind == kind for e in old.entries(kind))
    assert (load_secondary(old), current_sets(old)) == before
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)
    old.apply_retention(g, started=FUTURE)
    assert _ids(case, {'unified-result'})
    case.store.save(case.store.load())  # the v1 project contract still opens and saves with unified rows present
    assert json.loads(case.store.connection.execute(
        "SELECT body FROM enrichment_entries WHERE kind='unified-result'").fetchone()[0])['contract'] == \
        'unified-result-ptr/1'
