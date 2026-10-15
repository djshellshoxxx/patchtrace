"""CAP-4: raw-first capa cache. Hermetic; a hit never spawns, anything unreadable is a miss."""
from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from patchtrace.enrichment.cache import CacheConfig, DerivedCache
from patchtrace.intelligence.tools import capa_cache, process
from patchtrace.intelligence.tools.common import ToolManifest, cache_key

SHA = 'a' * 64
LIMIT = 1 << 20
MANIFEST = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                        rules_source='embedded', supported=True)
OPTIONS = {'argv': 'capa/2'}
RAW = b'{"meta": {}, "rules": {}}'


@pytest.fixture
def cache(tmp_path: Path) -> DerivedCache:
    return DerivedCache(CacheConfig(root=tmp_path / 'cache'))


def spawner(raw: bytes | None):
    calls: list[int] = []

    def spawn() -> bytes | None:
        calls.append(1)
        return raw
    return spawn, calls


def entry_payload(cache: DerivedCache) -> Path:
    return next(p for p in cache.config.root.rglob('*')
                if p.is_file() and p.name != 'manifest.json' and capa_cache.STAGE in p.parts)


def test_miss_runs_then_hit_does_not_spawn(cache):
    spawn, calls = spawner(RAW)
    first = capa_cache.fetch_or_run(cache, SHA, MANIFEST, OPTIONS, spawn, max_bytes=LIMIT)
    second = capa_cache.fetch_or_run(cache, SHA, MANIFEST, OPTIONS, spawn, max_bytes=LIMIT)
    assert (first.raw, first.hit) == (RAW, False)
    assert (second.raw, second.hit) == (RAW, True)
    assert len(calls) == 1


def test_stored_raw_round_trips_exactly(cache):
    assert capa_cache.store(cache, SHA, MANIFEST, OPTIONS, RAW)
    assert capa_cache.lookup(cache, SHA, MANIFEST, OPTIONS, LIMIT) == RAW


def test_no_cache_just_runs():
    spawn, calls = spawner(RAW)
    result = capa_cache.fetch_or_run(None, SHA, MANIFEST, OPTIONS, spawn, max_bytes=LIMIT)
    assert (result.raw, result.hit, len(calls)) == (RAW, False, 1)


def test_failed_run_is_not_cached(cache):
    spawn, _ = spawner(None)
    assert capa_cache.fetch_or_run(cache, SHA, MANIFEST, OPTIONS, spawn, max_bytes=LIMIT).raw is None
    assert capa_cache.lookup(cache, SHA, MANIFEST, OPTIONS, LIMIT) is None


@pytest.mark.parametrize('damage', ['flip', 'truncate', 'empty'], ids=['flip', 'truncate', 'empty'])
def test_corrupt_entry_is_a_miss_and_reruns(cache, damage):
    capa_cache.store(cache, SHA, MANIFEST, OPTIONS, RAW)
    path = entry_payload(cache)
    data = path.read_bytes()
    path.write_bytes({'flip': bytes([data[0] ^ 1]) + data[1:], 'truncate': data[:-3], 'empty': b''}[damage])
    spawn, calls = spawner(RAW)
    result = capa_cache.fetch_or_run(cache, SHA, MANIFEST, OPTIONS, spawn, max_bytes=LIMIT)
    assert (result.raw, result.hit, len(calls)) == (RAW, False, 1)


@pytest.mark.parametrize('payload', [b'not zlib', zlib.compress(b'x' * 5000), zlib.compress(RAW) + b'tail',
                                     zlib.compress(b'  ')], ids=['garbage', 'bomb', 'trailing', 'blank'])
def test_valid_cache_entry_with_bad_stream_is_a_miss(cache, payload):
    assert cache.put(capa_cache.STAGE, cache_key(SHA, MANIFEST, OPTIONS), payload, {})
    assert capa_cache.lookup(cache, SHA, MANIFEST, OPTIONS, 4096) is None


@pytest.mark.parametrize('change', ['sha', 'version', 'rules', 'options'], ids=['sha', 'version', 'rules', 'options'])
def test_key_changes_are_misses(cache, change):
    capa_cache.store(cache, SHA, MANIFEST, OPTIONS, RAW)
    sha, manifest, options = SHA, MANIFEST, OPTIONS
    if change == 'sha':
        sha = 'b' * 64
    elif change == 'version':
        manifest = MANIFEST.model_copy(update={'version': '9.5.0'})
    elif change == 'rules':
        manifest = MANIFEST.model_copy(update={'rules_source': 'custom', 'rules_sha256': 'c' * 64})
    else:
        options = {'argv': 'capa/3'}
    assert capa_cache.lookup(cache, sha, manifest, options, LIMIT) is None


def test_disabled_cache_is_a_soft_miss(tmp_path):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache', no_cache=True))
    spawn, _ = spawner(RAW)
    result = capa_cache.fetch_or_run(cache, SHA, MANIFEST, OPTIONS, spawn, max_bytes=LIMIT)
    assert result.raw == RAW and not result.hit


def test_capa_cache_dir_is_private(cache, tmp_path):
    capa_cache.store(cache, SHA, MANIFEST, OPTIONS, RAW)
    scratch = process.make_scratch('capa', tmp_path / 'scratch')
    try:
        env = process.tool_env(Path(__file__), scratch)
        assert not any(str(cache.config.root) in value for value in env.values())
    finally:
        process.remove_tree(scratch)
