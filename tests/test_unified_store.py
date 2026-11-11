"""SPEC-31 S0a store: result sidecars, pointer rows, cache misses, own retention and the additive-only guarantees
(old readers never see unified kinds; enrichment retention never deletes them). Synthetic sample projects only."""
from __future__ import annotations

import dataclasses
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.sample import create_sample
from patchtrace.secondary import load_secondary
from patchtrace.secondary.store import current_sets
from patchtrace.unified import contracts as uc
from patchtrace.unified import keys, store
from patchtrace.unified.contracts import ChangeFacts, SideRef, SourceRef, UnifiedMatch, UnifiedRun
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError

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


def _stage(svc, *, config='c', n=2, created='2026-10-14T12:00:00+00:00', version='synthetic', swap=False,
           older=None, newer=None, run_id=None, raw=None, project_id=None):
    """A staged result of the sample project. `swap` is the other orientation of the project's pair; the other
    keywords forge one identity so the ownership checks have something to refuse."""
    run = svc.project.runs[-1]
    old = older or next(a.sha256 for a in svc.project.artifacts if a.side == 'older')
    new = newer or next(a.sha256 for a in svc.project.artifacts if a.side == 'newer')
    if swap:
        old, new = new, old
    run_id, raw = run_id or run.id, raw or run.raw_sha256
    staged = store.new_staging_dir(svc.store.root, run_id)
    rows, facts = _rows(old, new, n)
    manifest = store.write_result(
        staged, older_sha256=old, newer_sha256=new, ghidriff_run_id=run_id, ghidriff_raw_sha256=raw,
        ir_older=None, ir_newer=None, sources=(SourceRef(source='ghidriff', entry_id=run_id,
                                                          file_sha256=raw, version=version),),
        manual_digest=keys.manual_digest([]), config_digest=hashlib.sha256(config.encode()).hexdigest(),
        status='complete', limitations=(), rows=rows, facts=facts, created_utc=created)
    guard = Guard(project_id or svc.project.id, run_id, raw, manifest.result_id)
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


def test_the_part_reader_and_the_record_parser_are_public(case):
    """The read layer (`read_text.SidecarRecords`) shares the store's caps and strictness through public names."""
    staged, manifest, _ = _stage(case)
    lines = list(store.part_lines(staged / store.ROWS))
    assert len(lines) == 2 and all(line.endswith(b'\n') for line in lines)
    row = store.parse_line(lines[0], UnifiedMatch)
    assert row.older[0].name == 'f0' and row.row_id == keys.row_id(manifest.older_sha256, manifest.newer_sha256,
                                                                    [0x1000], [0x2000])
    with pytest.raises(UnifiedError) as bad:
        store.parse_line(b'{"contract":"unified-match/1"}\n', UnifiedMatch)
    assert bad.value.reason == 'record-invalid'
    with pytest.raises(UnifiedError) as framing:
        store.parse_line(lines[0].replace(b'\n', b'\r\n'), UnifiedMatch)
    assert framing.value.reason == 'line-framing'
    tight = dataclasses.replace(DEFAULT_LIMITS, l30_part_bytes=10, l30_dir_bytes=10)
    with pytest.raises(UnifiedError) as big:
        list(store.part_lines(staged / store.ROWS, tight))
    assert big.value.reason == 'part-too-large'


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
        'unified-result-ptr/2'


# --- S0a-FIX (audit C): pair-aware retention, deep verification, ownership, drift, paths, fallback, orphans ----------

ZERO_D = dict.fromkeys(uc.DECISIONS, 0)
ZERO_M = dict.fromkeys(uc.MATERIALITIES, 0)


def _pair(svc):
    return (next(a.sha256 for a in svc.project.artifacts if a.side == 'older'),
            next(a.sha256 for a in svc.project.artifacts if a.side == 'newer'))


def _counts(decision, materiality, n):
    return uc.Counts.of_tallies({**ZERO_D, decision: n}, {**ZERO_M, materiality: n})


def _rewrite_row(svc, row_id, body):
    """Replace a stored pointer body and its integrity hash, as a forged or older-format row would be."""
    text = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    db = svc.store.connection
    db.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
               (text, hashlib.sha256(text.encode()).hexdigest(), row_id))
    db.commit()


def _part_lines(directory, name):
    return gzip.decompress((directory / name).read_bytes()).splitlines(keepends=True)


def _recertify(staged, manifest, name, lines, **update):
    """Swap one part for raw lines and re-certify the manifest (hash, bytes, records): what a hostile or buggy
    worker delivers. The result id binds the inputs, not the parts, so it stays valid."""
    data = b''.join(lines)
    (staged / name).write_bytes(gzip.compress(data, mtime=0))
    part = uc.Part(name=name, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), records=len(lines))
    updated = manifest.model_copy(update={'parts': tuple(part if p.name == name else p for p in manifest.parts),
                                          **update})
    (staged / 'manifest.json').write_bytes(store.dump_line(updated))
    return updated


def _has_row(path, row_id):
    with closing(sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True)) as db:
        return db.execute('SELECT COUNT(*) FROM enrichment_entries WHERE id=?', (row_id,)).fetchone()[0] == 1


def test_publish_writes_the_v2_pointer_with_the_pair(case):
    published = _publish(case)
    old, new = _pair(case)
    assert type(published.pointer) is uc.UnifiedResultPointerV2
    assert (published.pointer.older_sha256, published.pointer.newer_sha256) == (old, new)
    loaded = store.load_result(EnrichmentStore(case.store), published.entry.guard)
    assert loaded.state == 'current' and loaded.pointer == published.pointer


def test_retention_is_per_pair_orientation_and_config(case):
    """F-01: grouping by config_digest alone let one pair's newest results evict every other pair's results."""
    swapped = _publish(case, swap=True, version='b1')          # the other orientation: oldest row, own group
    same = [_publish(case, version=f'a{i}') for i in range(4)]  # one more than L-32 = 3 for the project's pair
    kept = _ids(case, {'unified-result'})
    assert kept == {swapped.entry.id, *(p.entry.id for p in same[-3:])}
    assert swapped.directory.is_dir() and not same[0].directory.exists()
    bodies = [json.loads(b) for (b,) in case.store.connection.execute(
        "SELECT body FROM enrichment_entries WHERE kind='unified-result'")]
    old, new = _pair(case)
    assert {(b['older_sha256'], b['newer_sha256']) for b in bodies} == {(old, new), (new, old)}
    other_config = _publish(case, config='other', version='c1')  # another config of the same pair is its own group
    assert other_config.entry.id in _ids(case, {'unified-result'}) and swapped.entry.id in _ids(
        case, {'unified-result'})


def test_run_rows_are_kept_per_ghidriff_run(case):
    """F-01: the 8 newest unified-run rows were kept project-wide, so one busy run evicted every other run's."""
    enrichment = EnrichmentStore(case.store)
    guards = {name: Guard(case.project.id, name, 'a' * 64, 'b' * 64) for name in ('r1', 'r2')}

    def publish(name, i):
        started = f'2026-10-14T12:00:{i:02d}+00:00'
        run = UnifiedRun(run_id=keys.unified_run_id('c' * 64, started), result_id=None, status='failed',
                         error_code='PT-UNIFIED-EXTRACT', started_utc=started, duration_ms=1)
        store.publish_run(enrichment, run, guard=guards[name], current=guards[name], revision=1)
        return run.run_id
    quiet = [publish('r2', i) for i in range(3)]                 # the oldest rows belong to the other run
    busy = [publish('r1', 10 + i) for i in range(store.RUN_KEEP + 2)]
    assert store.apply_unified_retention(enrichment) == 2
    assert _ids(case, {'unified-run'}) == {*quiet, *busy[-store.RUN_KEEP:]}


def test_duplicate_json_keys_in_a_part_are_rejected(case):
    """F-02: the last key won and the first was silently dropped; only the manifest was parsed strictly."""
    staged, manifest, _ = _stage(case)
    lines = _part_lines(staged, 'rows.jsonl.gz')
    assert b'"decision":"matched"' in lines[0]
    lines[0] = lines[0].replace(b'"decision":"matched"', b'"decision":"older-only","decision":"matched"')
    updated = _recertify(staged, manifest, 'rows.jsonl.gz', lines)
    store.verify_result_dir(staged, deep=False)                  # the hashes are right
    for call in (lambda: store.verify_result_dir(staged), lambda: list(store.read_rows(staged, updated))):
        with pytest.raises(UnifiedError) as info:
            call()
        assert info.value.reason == 'record-invalid'


def _break_counts(staged, manifest):                             # the manifest does not describe the rows
    manifest = manifest.model_copy(update={'counts': _counts('unknown', 'unknown', 2)})
    (staged / 'manifest.json').write_bytes(store.dump_line(manifest))
    return 'counts-mismatch'


def _garbage_rows(staged, manifest):                             # hashes right, but not a single row inside
    _recertify(staged, manifest, 'rows.jsonl.gz', [b'{"garbage":1}\n', b'{"x":2}\n'],
               counts=_counts('unknown', 'unknown', 2))
    return 'record-invalid'


def _wrong_row_id(staged, manifest):
    lines = _part_lines(staged, 'rows.jsonl.gz')
    lines[0] = lines[0].replace(json.loads(lines[0])['row_id'].encode(), b'f' * 64)
    _recertify(staged, manifest, 'rows.jsonl.gz', lines)
    return 'row-id'


def _repeated_row(staged, manifest):
    lines = _part_lines(staged, 'rows.jsonl.gz')
    _recertify(staged, manifest, 'rows.jsonl.gz', [lines[0], lines[0]])
    return 'row-id'


def _fact_without_row(staged, manifest):
    lines = _part_lines(staged, 'facts.jsonl.gz')
    lines[0] = lines[0].replace(json.loads(lines[0])['row_id'].encode(), b'e' * 64)
    _recertify(staged, manifest, 'facts.jsonl.gz', lines)
    return 'facts-row'


def _fact_with_other_verdict(staged, manifest):
    lines = _part_lines(staged, 'facts.jsonl.gz')
    lines[0] = store.dump_line(ChangeFacts(row_id=json.loads(lines[0])['row_id'], verdict='review', channels=CH,
                                           eh='absent'))
    _recertify(staged, manifest, 'facts.jsonl.gz', lines)
    return 'facts-row'


def _repeated_fact(staged, manifest):
    lines = _part_lines(staged, 'facts.jsonl.gz')
    _recertify(staged, manifest, 'facts.jsonl.gz', [lines[0], lines[0]])
    return 'facts-row'


BREAKS = {'counts': _break_counts, 'garbage': _garbage_rows, 'row-id': _wrong_row_id, 'dup-row': _repeated_row,
          'orphan': _fact_without_row, 'verdict': _fact_with_other_verdict, 'dup-fact': _repeated_fact}


@pytest.mark.parametrize('name', sorted(BREAKS))
def test_verification_cross_checks_counts_rows_and_facts(case, name):
    """F-03: a staged directory comes from a worker process; matching hashes prove nothing about its content."""
    staged, manifest, _ = _stage(case)
    reason = BREAKS[name](staged, manifest)
    store.verify_result_dir(staged, deep=False)
    with pytest.raises(UnifiedError) as info:
        store.verify_result_dir(staged)
    assert info.value.reason == reason
    guard = Guard(case.project.id, manifest.ghidriff_run_id, manifest.ghidriff_raw_sha256, manifest.result_id)
    with pytest.raises(UnifiedError) as again:                   # publish takes this gate, and leaves the directory
        store.publish_result(EnrichmentStore(case.store), staged, guard=guard, current=guard, revision=1)
    assert again.value.reason == reason and staged.is_dir() and not _ids(case, {'unified-result'})


def test_crlf_framed_parts_are_rejected(case):
    """F-26: a CRLF checkout of a part verified and read once its manifest was recomputed."""
    staged, manifest, _ = _stage(case)
    updated = _recertify(staged, manifest, 'rows.jsonl.gz',
                         [line[:-1] + b'\r\n' for line in _part_lines(staged, 'rows.jsonl.gz')])
    for call in (lambda: store.verify_result_dir(staged), lambda: list(store.read_rows(staged, updated))):
        with pytest.raises(UnifiedError) as info:
            call()
        assert info.value.reason == 'line-framing'


def test_a_line_over_the_cap_is_refused_when_written(tmp_path):
    """F-07: the writer accepted a row the reader then refused, blaming the store instead of the producer."""
    with pytest.raises(UnifiedError) as info:
        store.write_part(tmp_path, 'rows.jsonl.gz', [{'x': 'a' * store.LINE_MAX_BYTES}])
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-LIMIT', 'line-too-long')
    assert store.write_part(tmp_path, 'rows.jsonl.gz', [{'x': 'a' * 1000}]).records == 1


def test_deeply_nested_json_is_a_record_error_not_a_crash(case):
    staged, manifest, _ = _stage(case)
    bomb = b'[' * 200_000 + b']' * 200_000 + b'\n'
    _recertify(staged, manifest, 'rows.jsonl.gz', [bomb, bomb], counts=_counts('unknown', 'unknown', 2))
    with pytest.raises(UnifiedError) as info:
        store.verify_result_dir(staged)
    assert info.value.reason == 'record-invalid'


def test_the_same_result_id_with_other_content_is_refused_not_dropped(case):
    """F-04: result ids bind the inputs, not the parts; a changed payload under an old id was silently discarded."""
    enrichment = EnrichmentStore(case.store)
    first = _publish(case, n=2)
    staged, manifest, guard = _stage(case, n=3)                  # same inputs, so the same id, but other rows
    assert manifest.result_id == first.manifest.result_id
    with pytest.raises(UnifiedError) as info:
        store.publish_result(enrichment, staged, guard=guard, current=guard, revision=1)
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-INTERNAL', 'result-drift')
    assert staged.is_dir()
    loaded = store.load_result(enrichment, first.entry.guard)
    assert loaded.state == 'current' and loaded.manifest == first.manifest


def test_republishing_equal_parts_keeps_the_existing_manifest(case):
    first = _publish(case, created='2026-10-14T12:00:00+00:00')
    again = _publish(case, created='2026-10-15T00:00:00+00:00')  # only created_utc differs: the same result
    assert again.directory == first.directory and again.manifest == first.manifest
    assert again.pointer.manifest_sha256 == first.pointer.manifest_sha256
    assert store.load_result(EnrichmentStore(case.store), first.entry.guard).state == 'current'


FORGERIES = {'artifact': (dict(older='a' * 64, newer='b' * 64), 'artifact-foreign'),
             'half': (dict(newer='b' * 64), 'artifact-foreign'),
             'run': (dict(run_id='no-such-run'), 'run-unknown'),
             'raw': (dict(raw='c' * 64), 'raw-mismatch'),
             'project': (dict(project_id='another-project'), 'foreign-project')}


@pytest.mark.parametrize('name', sorted(FORGERIES))
def test_publish_refuses_results_that_do_not_belong_to_the_project(case, name):
    """F-05: AGENTS.md asks for artifact and run ownership; only guard == manifest was compared."""
    over, reason = FORGERIES[name]
    staged, _manifest, guard = _stage(case, **over)
    with pytest.raises(UnifiedError) as info:
        store.publish_result(EnrichmentStore(case.store), staged, guard=guard, current=guard, revision=1)
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-INPUT', reason)
    assert staged.is_dir() and not _ids(case, {'unified-result'})


def test_publish_run_refuses_a_foreign_project_guard(case):
    foreign = Guard('another-project', 'r', 'a' * 64, 'b' * 64)
    run = UnifiedRun(run_id=keys.unified_run_id('c' * 64, FUTURE), result_id=None, status='failed',
                     error_code='PT-UNIFIED-EXTRACT', started_utc='2026-10-14T12:00:00+00:00', duration_ms=1)
    with pytest.raises(UnifiedError) as info:
        store.publish_run(EnrichmentStore(case.store), run, guard=foreign, current=foreign, revision=1)
    assert info.value.reason == 'foreign-project' and not _ids(case, {'unified-run'})


def test_load_result_refuses_a_pointer_that_disagrees_with_its_manifest(case):
    """F-05: nothing tied the row's status, counts or directory to the manifest it points at."""
    published = _publish(case)
    enrichment = EnrichmentStore(case.store)
    good = dict(published.entry.body)
    _rewrite_row(case, published.entry.id, {**good, 'status': 'partial'})
    loaded = store.load_result(enrichment, published.entry.guard)
    assert (loaded.state, loaded.reason) == ('invalid', 'pointer-mismatch')
    leaf = published.directory.name                              # a pointer into another run's directory, whose
    elsewhere = case.store.root / 'runs' / 'other-run' / 'unified' / 'results' / leaf  # bytes verify perfectly
    elsewhere.parent.mkdir(parents=True)
    shutil.copytree(published.directory, elsewhere)
    _rewrite_row(case, published.entry.id, {**good, 'relative_dir': f'runs/other-run/unified/results/{leaf}'})
    loaded = store.load_result(enrichment, published.entry.guard)
    assert (loaded.state, loaded.reason) == ('invalid', 'pointer-mismatch')
    assert store.cached_result(enrichment, published.manifest.result_id) is None


def test_cached_result_does_not_call_a_stale_row_current(case):
    staged, manifest, guard = _stage(case)
    moved = Guard(guard.project_id, guard.run_id, guard.raw_sha256, 'f' * 64)
    published = store.publish_result(EnrichmentStore(case.store), staged, guard=guard, current=moved, revision=1)
    assert published.entry.stale
    hit = store.cached_result(EnrichmentStore(case.store), manifest.result_id)
    assert (hit.state, hit.reason) == ('stale', 'guard-moved')


@pytest.mark.parametrize('run_id', ['r\n', '', 'a' * 129, '../x', 'CON', 'abc.', 'a/b', 'a b', 'ü', 'x\x00'],
                         ids=['lf', 'empty', 'long', 'dots', 'con', 'trail', 'slash', 'space', 'uml', 'nul'])
def test_result_paths_refuse_hostile_run_ids(run_id):
    """F-06: Python `$` accepted a trailing newline; device names and `abc.` alias other files on Windows."""
    with pytest.raises(UnifiedError) as info:
        store.result_relative_dir(run_id, 'a' * 64)
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-INPUT', 'bad-identity')


@pytest.mark.parametrize('result_id', ['../' + 'a' * 61, 'A' * 64, 'a' * 63, 'a' * 65, 'g' * 64, ' ' * 64,
                                       'a' * 63 + '\n', 7, None],
                         ids=['dots', 'upper', 'short', 'long', 'nonhex', 'blank', 'lf', 'int', 'none'])
def test_result_paths_refuse_non_hex_result_ids(result_id):
    with pytest.raises(UnifiedError) as info:
        store.result_relative_dir('run-1', result_id)
    assert info.value.reason == 'bad-identity'


def test_result_paths_accept_ordinary_identities():
    rid = hashlib.sha256(b'x').hexdigest()
    assert store.result_relative_dir('0f3a-4b2c.v2', rid) == f'runs/0f3a-4b2c.v2/unified/results/{rid[:16]}'
    assert store.result_relative_dir('console', rid).startswith('runs/console/')


def test_windows_path_budget_is_checked_wherever_it_is_tested():
    """F-06: runs/<run>/unified/results/<16> alone is up to 166 characters of Windows MAX_PATH."""
    relative = store.result_relative_dir('r' * 36, 'a' * 64)
    store._check_path_length(Path('C:/' + 'x' * 100), relative, windows=True)
    with pytest.raises(UnifiedError) as info:
        store._check_path_length(Path('C:/' + 'x' * 160), relative, windows=True)
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-INPUT', 'path-too-long')
    store._check_path_length(Path('/' + 'x' * 400), relative, windows=False)  # POSIX has no such limit


def test_a_corrupt_current_result_falls_back_to_an_intact_older_one(case):
    """F-17: a corrupt newest sidecar hid an intact older result (the docstring promises the newest stale one)."""
    enrichment = EnrichmentStore(case.store)
    first = _publish(case, version='v1')
    second = _publish(case, version='v2')
    (second.directory / 'rows.jsonl.gz').write_bytes(b'garbage')
    loaded = store.load_result(enrichment, second.entry.guard)
    assert loaded.state == 'stale' and loaded.pointer.result_id == first.manifest.result_id
    assert loaded.manifest == first.manifest
    (first.directory / 'rows.jsonl.gz').write_bytes(b'garbage')  # nothing intact: the current row's failure is shown
    gone = store.load_result(enrichment, second.entry.guard)
    assert gone.state == 'invalid' and gone.pointer.result_id == second.manifest.result_id


def test_a_reused_backup_must_hold_the_rows_about_to_be_deleted(case):
    """F-17: any trusted same-project backup was reused, even one taken before the rows that delete_own removes."""
    enrichment = EnrichmentStore(case.store)
    first = _publish(case, version='v1')
    taken = store.backup_once(enrichment)                        # holds only the first row
    second = _publish(case, version='v2')
    assert store.backup_once(enrichment) == taken                # nothing demanded: still trusted
    assert store.backup_once(enrichment, must_contain=[first.entry.id]) == taken
    fresh = store.backup_once(enrichment, must_contain=[second.entry.id])
    assert fresh != taken and _has_row(fresh, second.entry.id) and not _has_row(taken, second.entry.id)
    assert store.delete_own(enrichment, [second.entry.id]) == 1
    assert _has_row(store.backup_once(enrichment, must_contain=[second.entry.id]), second.entry.id)


@pytest.mark.parametrize('contract', ['unified-result/0', 'unified-result/', 'unified-result/abc',
                                      'unified-result/-1', 'other/2'], ids=['zero', 'bare', 'alpha', 'neg', 'family'])
def test_malformed_contract_spellings_are_invalid_not_newer(case, contract):
    """F-18: any `unified-result/...` prefix used to report 'produced by a newer PatchTrace'."""
    published = _publish(case)
    path = published.directory / 'manifest.json'
    doc = json.loads(path.read_text(encoding='utf-8'))
    path.write_bytes(store.dump_line({**doc, 'contract': contract}))
    with pytest.raises(UnifiedError) as info:
        store.read_manifest(published.directory)
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-STORE', 'manifest-invalid')


def test_a_newer_contract_is_stale_in_manifest_rows_facts_and_pointers(case):
    """F-18 / 02 s7.2: fail closed and read-only; rows and pointers of a higher /N were `record-invalid`."""
    staged, manifest, _ = _stage(case)
    doc = json.loads((staged / 'manifest.json').read_text(encoding='utf-8'))
    (staged / 'manifest.json').write_bytes(store.dump_line({**doc, 'contract': 'unified-result/2'}))
    with pytest.raises(UnifiedError) as info:
        store.read_manifest(staged)
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-STALE', 'newer-contract')
    (staged / 'manifest.json').write_bytes(store.dump_line(doc))
    for name, old, new in (('rows.jsonl.gz', b'unified-match/1', b'unified-match/2'),
                           ('facts.jsonl.gz', b'change-facts/1', b'change-facts/2')):
        original = _part_lines(staged, name)
        updated = _recertify(staged, manifest, name, [line.replace(old, new) for line in original])
        with pytest.raises(UnifiedError) as info:
            store.verify_result_dir(staged)
        assert (info.value.code, info.value.reason) == ('PT-UNIFIED-STALE', 'newer-contract')
        manifest = _recertify(staged, updated, name, original)
    published = _publish(case)
    enrichment = EnrichmentStore(case.store)
    _rewrite_row(case, published.entry.id, {**published.entry.body, 'contract': 'unified-result-ptr/3'})
    loaded = store.load_result(enrichment, published.entry.guard)
    assert (loaded.state, loaded.reason) == ('invalid', 'newer-contract') and loaded.skipped == (published.entry.id,)
    assert store.apply_unified_retention(enrichment) == 0 and published.entry.id in _ids(case, {'unified-result'})


def test_a_pointer_row_with_duplicate_json_keys_is_a_cache_miss(case):
    """F-02: `EnrichmentStore.entries` keeps the last duplicate key; the raw row text is checked here."""
    published = _publish(case)
    text = json.dumps(published.entry.body, sort_keys=True, separators=(',', ':'))
    assert '"status":"complete"' in text
    forged = text.replace('"status":"complete"', '"status":"partial","status":"complete"')
    db = case.store.connection
    db.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
               (forged, hashlib.sha256(forged.encode()).hexdigest(), published.entry.id))
    db.commit()
    enrichment = EnrichmentStore(case.store)
    loaded = store.load_result(enrichment, published.entry.guard)
    assert loaded.state == 'none' and loaded.skipped == (published.entry.id,)
    assert store.cached_result(enrichment, published.manifest.result_id) is None
    assert store.apply_unified_retention(enrichment) == 0 and published.entry.id in _ids(case, {'unified-result'})


def test_legacy_v1_pointer_rows_stay_readable_and_are_grouped_by_their_manifest(case):
    """The version-gated reader: rows written before S0a-FIX carry no pair."""
    first = _publish(case, version='v1')
    legacy = {k: v for k, v in first.entry.body.items() if k not in ('older_sha256', 'newer_sha256')}
    _rewrite_row(case, first.entry.id, {**legacy, 'contract': 'unified-result-ptr/1'})
    loaded = store.load_result(EnrichmentStore(case.store), first.entry.guard)
    assert loaded.state == 'current' and type(loaded.pointer) is uc.UnifiedResultPointer
    for i in range(3):                                           # with three newer rows of its pair it is the fourth
        _publish(case, version=f'v{i + 2}')
    kept = _ids(case, {'unified-result'})
    assert first.entry.id not in kept and len(kept) == 3 and not first.directory.exists()


def test_a_legacy_row_without_a_readable_manifest_is_never_evicted(case):
    first = _publish(case, version='v1')
    legacy = {k: v for k, v in first.entry.body.items() if k not in ('older_sha256', 'newer_sha256')}
    _rewrite_row(case, first.entry.id, {**legacy, 'contract': 'unified-result-ptr/1'})
    (first.directory / 'manifest.json').write_bytes(b'{}')       # the pair can no longer be read
    for i in range(4):
        _publish(case, version=f'v{i + 2}')
    assert first.entry.id in _ids(case, {'unified-result'}) and len(_ids(case, {'unified-result'})) == 4


def _age(path, seconds):
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


def test_publish_sweeps_the_orphans_a_crash_left_behind(case):
    """F-19: a crash after the directory move leaves a result directory without a row, a crash while staging a
    tmp-* directory; 02 s4 promised the next publish removes them, and nothing did."""
    first = _publish(case, version='v1')
    parent = first.directory.parent
    orphan_old, orphan_new = parent / ('0' * 16), parent / ('1' * 16)
    staging_old, staging_new = parent / ('tmp-' + '2' * 16), parent / ('tmp-' + '3' * 16)
    for directory in (orphan_old, orphan_new, staging_old, staging_new):
        directory.mkdir()
        (directory / 'rows.jsonl.gz').write_bytes(b'x')
    _age(orphan_old, 3600)                                       # past the 5 minute grace
    _age(orphan_new, 10)
    _age(staging_old, 3 * 86_400)                                # older than any worker may live (L-34 maximum)
    _age(staging_new, 3600)                                      # a long analysis may still be staging it
    second = _publish(case, version='v2')
    assert not orphan_old.exists() and not staging_old.exists()
    assert orphan_new.is_dir() and staging_new.is_dir()
    assert first.directory.is_dir() and second.directory.is_dir()  # directories of stored rows are never swept
    third = _publish(case, version='v3')                         # a corrupt row still protects its directory
    case.store.connection.execute("UPDATE enrichment_entries SET body_sha256='00' WHERE id=?", (third.entry.id,))
    case.store.connection.commit()
    _age(third.directory, 3600)
    _publish(case, version='v4')
    assert third.directory.is_dir()


def test_every_single_byte_change_of_a_published_result_is_detected(case, tmp_path):
    """F-20: bit-flip sweep over every byte a hash or the gzip CRC covers. The gzip MTIME/XFL/OS bytes (4..9) are
    outside every check by design: only decompressed content is hashed (02 s9.6). Corrupt deflate data used to
    raise zlib.error out of the verifier instead of a typed failure."""
    published = _publish(case)
    sha = published.pointer.manifest_sha256
    work = tmp_path / 'fuzz'
    shutil.copytree(published.directory, work)
    assert store.verify_result_dir(work, expected_manifest_sha256=sha) == published.manifest
    for name in ('manifest.json', 'rows.jsonl.gz', 'facts.jsonl.gz'):
        original = (published.directory / name).read_bytes()
        for index in range(len(original)):
            if name.endswith('.gz') and 4 <= index < 10:
                continue
            mutated = bytearray(original)
            mutated[index] ^= 0xFF
            (work / name).write_bytes(bytes(mutated))
            with pytest.raises(UnifiedError):
                store.verify_result_dir(work, expected_manifest_sha256=sha)
        (work / name).write_bytes(original)


def test_gzip_padding_tolerance_is_documented_and_trailing_garbage_is_refused(case, tmp_path):
    """F-20: only decompressed content is hashed (02 s9.6), so trailing zero padding, which every gzip reader
    ignores, cannot change a record and is tolerated; any other trailing byte is an error."""
    published = _publish(case)
    work = tmp_path / 'tail'
    shutil.copytree(published.directory, work)
    path = work / 'facts.jsonl.gz'
    original = path.read_bytes()
    path.write_bytes(original + b'\x00\x00\x00')
    assert store.verify_result_dir(work) == published.manifest
    path.write_bytes(original + b'\x01junk')
    with pytest.raises(UnifiedError) as info:
        store.verify_result_dir(work)
    assert info.value.reason == 'part-unreadable'


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(name=st.sampled_from(['rows.jsonl.gz', 'facts.jsonl.gz']), cut=st.integers(min_value=0, max_value=10_000))
def test_a_truncated_part_is_a_typed_failure(case, tmp_path, name, cut):
    published = _publish(case, version='truncated')
    work = tmp_path / 'cut'
    if not work.exists():
        shutil.copytree(published.directory, work)
    original = (published.directory / name).read_bytes()
    (work / name).write_bytes(original[:cut % len(original)])
    try:
        with pytest.raises(UnifiedError):
            store.verify_result_dir(work)
    finally:
        (work / name).write_bytes(original)

# --- UE-R3: optional C parts must pass deep verification before publication ----------------------------------------

@pytest.mark.parametrize('document', [
    {'side': 'wrong', 'rva': 0x1000, 'status': 'ok', 'code': 'int f;'},
    {'side': 'older', 'rva': -1, 'status': 'ok', 'code': 'int f;'},
    {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': None},
    {'side': 'older', 'rva': 0x1000, 'status': 'failed', 'code': 'int f;'},
    {'side': 'older', 'rva': 0x7777, 'status': 'ok', 'code': 'int ghost;'},
    {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': 'int f;', 'extra': True},
], ids=['side', 'negative-rva', 'null-ok', 'code-on-failure', 'foreign-rva', 'extra'])
def test_decomp_part_rejects_invalid_but_rehashed_records(case, document):
    staged, _manifest, _ = _stage(case)
    part = store.write_part(staged, store.DECOMP, [document])
    store.add_part(staged, part)
    with pytest.raises(UnifiedError, match='decompile'):
        store.verify_result_dir(staged)


def test_decomp_part_rejects_duplicate_records_even_when_hashes_are_correct(case):
    staged, _manifest, _ = _stage(case)
    row = {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': 'int f;'}
    store.add_part(staged, store.write_part(staged, store.DECOMP, [row, row]))
    with pytest.raises(UnifiedError, match='decompile'):
        store.verify_result_dir(staged)


def test_decomp_part_accepts_owned_rvas_and_preserves_the_result_key(case):
    staged, before, _guard = _stage(case)
    part = store.write_part(staged, store.DECOMP, [
        {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': 'int f;'},
        {'side': 'newer', 'rva': 0x2000, 'status': 'ok', 'code': 'int f() { return 1; }'},
    ])
    after = store.add_part(staged, part)
    assert store.verify_result_dir(staged) == after
    assert after.result_id == before.result_id


@pytest.mark.parametrize('code', [0, False, [], {}, ''])
def test_decomp_failed_record_requires_null(case, code):
    staged, _manifest, _ = _stage(case)
    row = {'side': 'older', 'rva': 0x1000, 'status': 'failed', 'code': code}
    store.add_part(staged, store.write_part(staged, store.DECOMP, [row]))
    with pytest.raises(UnifiedError, match='decompile'):
        store.verify_result_dir(staged)


@pytest.mark.parametrize('failure', ['install', 'pointer'])
def test_failed_upgrade_preserves_committed_result(case, monkeypatch, failure):
    first = _publish(case)
    staged, _manifest, guard = _stage(case, n=3)
    enrichment = EnrichmentStore(case.store)
    replace = store._replace

    def fail_install(source, target):
        if source == staged:
            raise OSError('injected install failure')
        replace(source, target)

    def fail_publish(*args, **kwargs):
        raise storage.EnrichmentError('PT-ENRICH-STORAGE', 'injected pointer failure')

    if failure == 'install':
        monkeypatch.setattr(store, '_replace', fail_install)
    else:
        monkeypatch.setattr(enrichment, 'publish', fail_publish)
    with pytest.raises((OSError, UnifiedError)):
        store.publish_result(enrichment, staged, guard=guard, current=guard, revision=1, upgrade=True)
    loaded = store.load_result(enrichment, first.entry.guard)
    assert loaded.state == 'current' and loaded.manifest == first.manifest
    assert first.directory.is_dir()


@pytest.mark.parametrize('replacement_installed', [False, True])
def test_interrupted_upgrade_recovers_exact_committed_manifest(case, replacement_installed):
    first = _publish(case)
    previous = first.directory.with_name(f'prev-{first.manifest.result_id[:16]}-'
                                         f'{first.pointer.manifest_sha256[:16]}')
    first.directory.rename(previous)
    if replacement_installed:
        staged, _manifest, _guard = _stage(case, n=3)
        staged.rename(first.directory)
    enrichment = EnrichmentStore(case.store)
    loaded = store.load_result(enrichment, first.entry.guard)
    assert loaded.state == 'current' and loaded.manifest == first.manifest
    assert loaded.directory == previous
    assert store.cached_result(enrichment, first.manifest.result_id).manifest == first.manifest
    _age(previous, 3600)
    store.sweep_orphans(enrichment, first.manifest.ghidriff_run_id)
    assert previous.is_dir()


def test_interrupted_upgrade_recovery_refuses_tampered_previous_directory(case):
    first = _publish(case)
    previous = first.directory.with_name(f'prev-{first.manifest.result_id[:16]}-'
                                         f'{first.pointer.manifest_sha256[:16]}')
    first.directory.rename(previous)
    (previous / store.ROWS).write_bytes(b'not the committed data')
    loaded = store.load_result(EnrichmentStore(case.store), first.entry.guard)
    assert loaded.state == 'invalid'


@pytest.mark.parametrize('code', ['', '\ud800', 'x' * 21, '\n' * 3])
def test_decomp_success_requires_bounded_nonempty_utf8(case, code):
    staged, _manifest, _ = _stage(case)
    row = {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': code}
    manifest = store.add_part(staged, store.write_part(staged, store.DECOMP, [{**row, 'code': 'valid'}]))
    _recertify(staged, manifest, store.DECOMP, [json.dumps(row).encode('ascii') + b'\n'])
    limits = dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_chars=20, l29_pseudo_lines=3)
    with pytest.raises(UnifiedError, match='decompile'):
        store.verify_result_dir(staged, limits=limits)


def test_previous_generation_is_swept_only_after_pointer_stops_referencing_it(case):
    first = _publish(case)
    previous = first.directory.with_name(f'prev-{first.manifest.result_id[:16]}-'
                                         f'{first.pointer.manifest_sha256[:16]}')
    first.directory.rename(previous)
    staged, _manifest, guard = _stage(case, n=3)
    staged.rename(first.directory)  # interrupted after installation, before pointer commit
    _age(previous, 3600)
    enrichment = EnrichmentStore(case.store)
    staged, _manifest, _guard = _stage(case, n=3)
    second = store.publish_result(enrichment, staged, guard=guard, current=guard, revision=1, upgrade=True)
    assert second.manifest.counts.total() == 3
    assert not previous.exists()
    assert store.load_result(enrichment, guard).manifest == second.manifest


def test_failed_rollback_preserves_a_readable_committed_generation(case, monkeypatch):
    first = _publish(case)
    staged, _manifest, guard = _stage(case, n=3)
    enrichment = EnrichmentStore(case.store)
    replace = store._replace

    def fail_install_and_restore(source, target):
        if target == first.directory:
            raise OSError('injected install and rollback failure')
        replace(source, target)

    monkeypatch.setattr(store, '_replace', fail_install_and_restore)
    with pytest.raises(OSError):
        store.publish_result(enrichment, staged, guard=guard, current=guard, revision=1, upgrade=True)
    loaded = store.load_result(enrichment, guard)
    assert loaded.state == 'current' and loaded.manifest == first.manifest


def test_orphan_sweep_preserves_previous_generations_when_pointer_is_corrupt(case):
    first = _publish(case)
    previous = first.directory.with_name(f'prev-{first.manifest.result_id[:16]}-'
                                         f'{first.pointer.manifest_sha256[:16]}')
    first.directory.rename(previous)
    _age(previous, 3600)
    case.store.connection.execute('UPDATE enrichment_entries SET body_sha256=? WHERE id=?',
                                  ('0' * 64, first.entry.id))
    case.store.connection.commit()
    store.sweep_orphans(EnrichmentStore(case.store), first.manifest.ghidriff_run_id)
    assert previous.is_dir()
