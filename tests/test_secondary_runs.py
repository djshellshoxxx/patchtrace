"""SPEC-28 §4.1/§5.1: EngineRun records, cache key and cache validation."""
from __future__ import annotations

import json

import pytest
from test_secondary_store import _set, case  # noqa: F401  (case is a fixture)

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary.runs import (
    EngineRun,
    argv_digest,
    as_v2,
    cache_key,
    new_run_id,
    sanitize_stderr,
)
from patchtrace.secondary.store import find_cached, publish_engine_set, publish_run
from patchtrace.service import ProjectService

OLD, NEW = 'a' * 64, 'b' * 64
BASE = ('rz-diff', '0.9.1', 'd' * 64, OLD, NEW, 'older->newer')


def run_for(key, status='ok', match_set_id=None, output=None):
    return EngineRun(run_id=new_run_id(key, 't'), engine='rz-diff', engine_version='0.9.1',
                     executable_path_sha256=None, argv_digest='d' * 64, older_sha256=OLD, newer_sha256=NEW,
                     orientation='older->newer', cache_key=key, status=status, error_code=None, returncode=0,
                     started_utc='t', duration_ms=1, stderr_tail='', output_sha256=output,
                     match_set_id=match_set_id)


@pytest.mark.parametrize('index,value', [(0, 'bindiff'), (1, '0.9.2'), (2, 'e' * 64), (3, 'c' * 64),
                                         (4, 'c' * 64), (5, 'newer->older')])
def test_cache_key_changes_with_each_component(index, value):
    changed = list(BASE)
    changed[index] = value
    assert cache_key(*changed) != cache_key(*BASE)
    assert cache_key(*BASE) == cache_key(*BASE)


def test_cache_key_stable_when_project_moved_but_not_when_flags_change():
    one = argv_digest(['/opt/a/rz-diff', '-C', '/p1/old.sys', '/p1/new.sys'], '/p1/old.sys', '/p1/new.sys')
    moved = argv_digest(['/usr/bin/rz-diff', '-C', '/p2/old.sys', '/p2/new.sys'], '/p2/old.sys', '/p2/new.sys')
    flags = argv_digest(['/opt/a/rz-diff', '-X', '/p1/old.sys', '/p1/new.sys'], '/p1/old.sys', '/p1/new.sys')
    assert one == moved != flags


def test_engine_run_schema_roundtrip_and_strictness():
    run = run_for('f' * 64)
    assert EngineRun.model_validate_json(run.model_dump_json()) == run
    payload = run.model_dump(mode='json')
    for bad in ({**payload, 'extra': 1}, {**payload, 'status': 'weird'}, {**payload, 'duration_ms': -1},
                {**payload, 'stderr_tail': 'x' * 70_000}, {**payload, 'superseded_by': 'x'}):
        with pytest.raises(ValueError):
            EngineRun.model_validate_json(json.dumps(bad))


def test_sanitize_stderr_strips_controls_and_caps():
    assert sanitize_stderr('a\x1b[0m\tb\n\x00') == 'a?[0m\tb\n?'
    assert len(sanitize_stderr('x' * 100_000)) == 65_536


def _store(root, fn):
    service = ProjectService.open(root)
    try:
        return fn(EnrichmentStore(service.store))
    finally:
        service.close()


def test_cache_hit_revalidates_and_misses_on_tampered_set(case):  # noqa: F811
    root, sides, run, revision, pid = case
    ms = as_v2(_set(sides['older'], sides['newer'], '1' * 64))
    key = 'f' * 64
    guard = Guard(pid, run.id, run.raw_sha256, ms.file_sha256)
    record = run_for(key, match_set_id=ms.entry_id, output=ms.file_sha256)

    def seed(store):
        publish_engine_set(store, guard, guard, revision, ms)
        publish_run(store, guard, guard, revision, record)

    _store(root, seed)
    assert _store(root, lambda s: find_cached(s, key, sides['older'], sides['newer'])) == ms
    assert _store(root, lambda s: find_cached(s, 'e' * 64, sides['older'], sides['newer'])) is None
    assert _store(root, lambda s: find_cached(s, key, 'c' * 64, sides['newer'])) is None
    # A re-run with different output replaces the set row; the older run record no longer validates.
    other = as_v2(_set(sides['older'], sides['newer'], '2' * 64))
    _store(root, lambda s: publish_engine_set(s, guard, guard, revision, other))
    assert _store(root, lambda s: find_cached(s, key, sides['older'], sides['newer'])) is None


def test_engine_run_kind_is_stored_and_ignored_by_secondary_readers(case):  # noqa: F811
    from patchtrace.secondary import load_secondary
    root, sides, run, revision, pid = case
    guard = Guard(pid, run.id, run.raw_sha256, 'f' * 64)
    _store(root, lambda s: publish_run(s, guard, guard, revision, run_for('f' * 64, 'failed')))
    assert _store(root, load_secondary) == []
    [entry] = _store(root, lambda s: s.entries('engine-run'))
    assert entry.body['contract'] == 'engine-run/1'
