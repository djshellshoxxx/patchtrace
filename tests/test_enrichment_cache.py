"""B4 cache tests (SPEC-07 §9). All payloads are synthetic bytes, not real Ghidriff output."""
from __future__ import annotations

import builtins
import dataclasses
import errno
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from patchtrace.enrichment import cache as cache_mod
from patchtrace.enrichment.cache import CacheConfig, DerivedCache, RuntimeFingerprint
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.identity import stage_id

A = 'a' * 64
B = 'b' * 64
KEY = stage_id('signals', 1, {'diff': A})
PAYLOAD = b'synthetic-payload'


def fp(**changes) -> RuntimeFingerprint:
    base = dict(engine='ghidriff', ghidriff_revision='0.7.0', ghidra_version='11.1.2',
                pyghidra_version='2.0.1', python_version='3.12.4', java_version='21.0.3',
                platform_arch='x86_64', loader_options='d1', analysis_options='d2',
                adapter_version='1', symbol_policy='offline', symbol_input_digest='d3')
    base.update(changes)
    return RuntimeFingerprint(**base)


@pytest.fixture
def cache(tmp_path) -> DerivedCache:
    return DerivedCache(CacheConfig(root=tmp_path / 'cache'))


def entry_dir(c: DerivedCache, stage: str, key: str) -> Path:
    return c.config.root / 'v1' / stage / key[:2] / key


def staging_dirs(c: DerivedCache) -> list[Path]:
    base = c.config.root / 'v1'
    return [p for p in base.iterdir() if p.name.startswith('.staging-')] if base.exists() else []


# ---- config / keys -------------------------------------------------------

def test_no_cache_with_refresh_is_config_error(tmp_path):
    with pytest.raises(EnrichmentError) as info:
        CacheConfig(root=tmp_path, no_cache=True, refresh_stages=frozenset({'signals'}))
    assert info.value.code == 'PT-ENRICH-CONFIG'


def test_invalid_arguments_raise_config(cache):
    for stage, key in (('Bad', KEY), ('signals', 'XYZ'), ('../x', KEY), ('quarantine', KEY),
                       ('signals', KEY.upper())):
        with pytest.raises(EnrichmentError) as info:
            cache.put(stage, key, PAYLOAD, {})
        assert info.value.code == 'PT-ENRICH-CONFIG'
        with pytest.raises(EnrichmentError):
            cache.get(stage, key)
    with pytest.raises(EnrichmentError):
        cache.put('signals', KEY, 'text', {})
    with pytest.raises(EnrichmentError):
        cache.put('signals', KEY, PAYLOAD, {'a': 1})


def test_roundtrip_and_layout(cache):
    assert cache.get('signals', KEY) is None
    assert cache.put('signals', KEY, PAYLOAD, {'diff': A})
    assert cache.get('signals', KEY) == PAYLOAD
    entry = entry_dir(cache, 'signals', KEY)
    assert sorted(p.name for p in entry.iterdir()) == ['manifest.json', 'payload']
    manifest = json.loads((entry / 'manifest.json').read_text())
    assert manifest['key'] == KEY and manifest['stage'] == 'signals' and manifest['size'] == len(PAYLOAD)
    assert not staging_dirs(cache)
    assert not list(entry.parent.glob('*.lock'))


def test_swapped_pair_misses(cache):
    f = fp()
    assert f.raw_key(A, B) != f.raw_key(B, A)
    assert cache.put_raw(f, A, B, PAYLOAD)
    assert cache.get_raw(f, A, B) == PAYLOAD
    assert cache.get_raw(f, B, A) is None


@pytest.mark.parametrize('name', [f.name for f in dataclasses.fields(RuntimeFingerprint)])
def test_each_fingerprint_field_change_misses(cache, name):
    f = fp()
    assert cache.put_raw(f, A, B, PAYLOAD)
    changed = fp(**{name: getattr(f, name) + '-x'})
    assert changed.raw_key(A, B) != f.raw_key(A, B)
    assert cache.get_raw(changed, A, B) is None


@pytest.mark.parametrize('change', [{'ghidra_version': 'unknown'}, {'java_version': ''},
                                    {'pyghidra_version': 'UNKNOWN'}, {'symbol_policy': 'online'}])
def test_ineligible_fingerprints_refuse_raw(cache, change):
    eligible = fp()
    bad = fp(**change)
    assert eligible.eligible() == (True, 'eligible')
    assert bad.eligible()[0] is False
    assert cache.put_raw(bad, A, B, PAYLOAD) is False
    assert not cache.config.root.exists()
    # Even if an entry exists at that key (planted via the derived path), get_raw refuses.
    cache.put('raw', bad.raw_key(A, B), PAYLOAD, {})
    assert cache.get_raw(bad, A, B) is None


def test_raw_size_bound(tmp_path):
    c = DerivedCache(CacheConfig(root=tmp_path, raw_max_bytes=8))
    assert c.put_raw(fp(), A, B, b'x' * 9) is False
    assert c.put_raw(fp(), A, B, b'x' * 8)


def test_targeted_invalidation_at_key_level(cache):
    signals_key = stage_id('signals', 1, {'pairings': A})
    rank1 = stage_id('ranking', 1, {'signals': signals_key, 'config': 'c' * 64})
    rank2 = stage_id('ranking', 1, {'signals': signals_key, 'config': 'd' * 64})
    assert rank1 != rank2
    assert cache.put('signals', signals_key, b'sig', {'pairings': A})
    assert cache.put('ranking', rank1, b'r1', {})
    assert cache.get('ranking', rank2) is None
    assert cache.get('signals', signals_key) == b'sig'


# ---- concurrency ---------------------------------------------------------

def test_two_writers_same_key(cache, monkeypatch):
    inside, release = threading.Event(), threading.Event()
    real = cache_mod._write_payload

    def slow(path, data):
        real(path, data)
        inside.set()
        assert release.wait(10)

    monkeypatch.setattr(cache_mod, '_write_payload', slow)
    results = {}
    t = threading.Thread(target=lambda: results.setdefault('a', cache.put('signals', KEY, PAYLOAD, {})))
    t.start()
    assert inside.wait(10)
    # While writer A is mid-publication: nothing partial is visible, B cannot admit.
    assert cache.get('signals', KEY) is None
    monkeypatch.setattr(cache_mod, '_write_payload', real)
    assert cache.put('signals', KEY, PAYLOAD, {}) is False
    release.set()
    t.join(10)
    assert results['a'] is True
    assert cache.get('signals', KEY) == PAYLOAD
    # A later writer with identical data reports success; with different data it fails.
    assert cache.put('signals', KEY, PAYLOAD, {}) is True
    assert cache.put('signals', KEY, b'other', {}) is False
    assert cache.get('signals', KEY) == PAYLOAD


def test_many_threads_same_key(cache):
    barrier = threading.Barrier(8)
    out = []

    def run():
        barrier.wait()
        out.append(cache.put('signals', KEY, PAYLOAD, {}))

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert any(out)
    assert cache.get('signals', KEY) == PAYLOAD
    assert not staging_dirs(cache)


def test_leased_reader_survives_prune(cache):
    k2 = stage_id('signals', 1, {'x': B})
    assert cache.put('signals', KEY, PAYLOAD, {})
    assert cache.put('signals', k2, PAYLOAD, {})
    with cache.lease('signals', KEY):
        result = cache.prune(0)
        assert result['skipped_leased'] == 1 and result['removed'] == 1
        assert cache.get('signals', KEY) == PAYLOAD
    assert cache.get('signals', k2) is None
    assert cache.prune(0)['removed'] == 1
    assert cache.get('signals', KEY) is None


def test_lru_evicts_least_recently_accessed(cache):
    keys = [stage_id('signals', 1, {'n': str(i)}) for i in range(3)]
    for i, k in enumerate(keys):
        assert cache.put('signals', k, PAYLOAD, {})
        os.utime(entry_dir(cache, 'signals', k) / 'manifest.json', ns=(10**18 + i, 10**18 + i))
    assert cache.get('signals', keys[0]) == PAYLOAD  # refreshes its clock
    one = cache.status()['bytes'] // 3
    cache.prune(one * 2)
    assert cache.get('signals', keys[1]) is None
    assert cache.get('signals', keys[0]) == PAYLOAD
    assert cache.get('signals', keys[2]) == PAYLOAD


def test_budget_enforced_on_put(tmp_path):
    c = DerivedCache(CacheConfig(root=tmp_path, budget_bytes=10))
    assert c.put('signals', KEY, b'x' * 11, {}) is False


# ---- crash / cancellation -----------------------------------------------

class SimulatedCrash(BaseException):
    pass


@pytest.mark.parametrize('point', ['payload', 'manifest', 'publish'])
def test_crash_at_each_promotion_point(cache, monkeypatch, point):
    def crash(*_args):
        raise SimulatedCrash()

    real_payload = cache_mod._write_payload
    if point == 'payload':  # after payload written, before manifest
        def after_payload(path, data):
            real_payload(path, data)
            raise SimulatedCrash()
        monkeypatch.setattr(cache_mod, '_write_payload', after_payload)
    elif point == 'manifest':  # before manifest
        monkeypatch.setattr(cache_mod, '_write_manifest', crash)
    else:  # after manifest, before replace
        monkeypatch.setattr(cache_mod, '_publish', crash)
    # A real crash runs no cleanup: emulate process death by disabling it and by
    # dropping in-process registries (a dead owner no longer holds anything).
    monkeypatch.setattr(cache_mod, '_discard_staging', lambda path: None)
    with pytest.raises(SimulatedCrash):
        cache.put('signals', KEY, PAYLOAD, {})
    cache_mod._HELD_LOCKS.clear()
    cache_mod._ACTIVE_STAGING.clear()
    monkeypatch.undo()
    assert cache.get('signals', KEY) is None
    assert len(staging_dirs(cache)) == 1
    assert cache.status()['entries'] == 0
    result = cache.verify()
    assert result['staging_removed'] == 1 and result['ok'] == 0
    assert not staging_dirs(cache)
    assert cache.put('signals', KEY, PAYLOAD, {})
    assert cache.get('signals', KEY) == PAYLOAD


def test_prune_also_cleans_orphan_staging(cache, monkeypatch):
    monkeypatch.setattr(cache_mod, '_publish', lambda *a: (_ for _ in ()).throw(SimulatedCrash()))
    monkeypatch.setattr(cache_mod, '_discard_staging', lambda path: None)
    with pytest.raises(SimulatedCrash):
        cache.put('signals', KEY, PAYLOAD, {})
    cache_mod._ACTIVE_STAGING.clear()
    monkeypatch.undo()
    assert cache.prune()['staging_removed'] == 1
    assert not staging_dirs(cache)


def test_cancellation_cleans_up_and_releases_lock(cache, monkeypatch):
    def cancelled(path, data):
        raise KeyboardInterrupt

    monkeypatch.setattr(cache_mod, '_write_manifest', cancelled)
    with pytest.raises(KeyboardInterrupt):
        cache.put('signals', KEY, PAYLOAD, {})
    monkeypatch.undo()
    assert not staging_dirs(cache)
    assert not list(entry_dir(cache, 'signals', KEY).parent.glob('*.lock'))
    assert cache.get('signals', KEY) is None
    assert cache.put('signals', KEY, PAYLOAD, {})


def test_windows_style_rename_failure_returns_false(cache, monkeypatch):
    def locked(*_a):
        raise PermissionError(13, 'file in use by another process')

    monkeypatch.setattr(cache_mod, '_publish', locked)
    assert cache.put('signals', KEY, PAYLOAD, {}) is False
    assert not staging_dirs(cache)
    assert cache.get('signals', KEY) is None


# ---- corruption ----------------------------------------------------------

def _quarantine_count(c):
    q = c.config.root / 'v1' / 'quarantine'
    return len(list(q.iterdir())) if q.exists() else 0


@pytest.mark.parametrize('damage', ['payload-flip', 'payload-truncate', 'manifest-garbage',
                                    'manifest-wrong-key', 'manifest-missing', 'manifest-extra'])
def test_corrupt_entries_quarantined(cache, damage):
    assert cache.put('signals', KEY, PAYLOAD, {})
    entry = entry_dir(cache, 'signals', KEY)
    manifest = json.loads((entry / 'manifest.json').read_text())
    if damage == 'payload-flip':
        (entry / 'payload').write_bytes(b'Synthetic-payload')
    elif damage == 'payload-truncate':
        (entry / 'payload').write_bytes(PAYLOAD[:-1])
    elif damage == 'manifest-garbage':
        (entry / 'manifest.json').write_bytes(b'{not json')
    elif damage == 'manifest-wrong-key':
        manifest['key'] = 'f' * 64
        (entry / 'manifest.json').write_text(json.dumps(manifest))
    elif damage == 'manifest-missing':
        (entry / 'manifest.json').unlink()
    else:
        manifest['bonus'] = 1
        (entry / 'manifest.json').write_text(json.dumps(manifest))
    assert cache.get('signals', KEY) is None
    assert not entry.exists()
    assert _quarantine_count(cache) == 1
    assert cache.put('signals', KEY, PAYLOAD, {})


def test_verify_counts(cache):
    k2 = stage_id('signals', 1, {'x': B})
    assert cache.put('signals', KEY, PAYLOAD, {})
    assert cache.put('signals', k2, PAYLOAD, {})
    (entry_dir(cache, 'signals', k2) / 'payload').write_bytes(b'tampered')
    result = cache.verify()
    assert (result['ok'], result['corrupt'], result['quarantined']) == (1, 1, 1)
    assert cache.status()['entries'] == 1


# ---- filesystem failures -------------------------------------------------

def test_disk_full_put_returns_false(cache, monkeypatch):
    def full(_fd):
        raise OSError(errno.ENOSPC, 'No space left on device')

    monkeypatch.setattr(cache_mod.os, 'fsync', full)
    assert cache.put('signals', KEY, PAYLOAD, {}) is False
    monkeypatch.undo()
    assert not staging_dirs(cache)
    assert cache.get('signals', KEY) is None


def test_permission_error_put_returns_false(cache, monkeypatch):
    def denied(*_a, **_k):
        raise PermissionError(13, 'denied')

    monkeypatch.setattr(cache_mod.os, 'mkdir', denied)
    assert cache.put('signals', KEY, PAYLOAD, {}) is False


@pytest.mark.skipif(os.name == 'nt' or os.geteuid() == 0, reason='chmod not enforced')
def test_readonly_root_put_returns_false(tmp_path):
    root = tmp_path / 'ro'
    root.mkdir()
    root.chmod(0o500)
    try:
        assert DerivedCache(CacheConfig(root=root)).put('signals', KEY, PAYLOAD, {}) is False
    finally:
        root.chmod(0o700)


def test_root_is_a_file_put_returns_false(tmp_path):
    root = tmp_path / 'file'
    root.write_bytes(b'')
    c = DerivedCache(CacheConfig(root=root))
    assert c.put('signals', KEY, PAYLOAD, {}) is False
    assert c.get('signals', KEY) is None


@pytest.mark.skipif(not hasattr(os, 'symlink'), reason='no symlinks')
def test_symlink_escape_refused(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'precious').write_bytes(b'keep')
    c = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    (tmp_path / 'cache' / 'v1').mkdir(parents=True)
    try:
        try:
            os.symlink(outside, tmp_path / 'cache' / 'v1' / 'signals', target_is_directory=True)
        except OSError:
            pytest.skip('symlink creation not permitted')
    except OSError:
        pytest.skip('symlink creation not permitted')
    assert c.put('signals', KEY, PAYLOAD, {}) is False
    assert c.get('signals', KEY) is None
    c.prune(0)
    c.verify()
    assert sorted(p.name for p in outside.iterdir()) == ['precious']


@pytest.mark.skipif(not hasattr(os, 'symlink'), reason='no symlinks')
def test_symlinked_entry_payload_is_not_served(cache, tmp_path):
    assert cache.put('signals', KEY, PAYLOAD, {})
    entry = entry_dir(cache, 'signals', KEY)
    secret = tmp_path / 'secret'
    secret.write_bytes(PAYLOAD)
    (entry / 'payload').unlink()
    try:
        os.symlink(secret, entry / 'payload')
    except OSError:
        pytest.skip('symlink creation not permitted')
    assert cache.get('signals', KEY) is None
    assert secret.read_bytes() == PAYLOAD


# ---- stale locks ---------------------------------------------------------

def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, '-c', 'pass'])
    proc.wait()
    return proc.pid


def _plant_lock(c, owner):
    lock = entry_dir(c, 'signals', KEY).parent / f'{KEY}.lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps(owner))
    return lock


def test_stale_lock_with_dead_pid_recovered(cache):
    _plant_lock(cache, {'pid': _dead_pid(), 'host': socket.gethostname(), 'nonce': 'n1'})
    assert cache.put('signals', KEY, PAYLOAD, {})
    assert cache.get('signals', KEY) == PAYLOAD


def test_live_pid_lock_not_stolen(cache):
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    try:
        lock = _plant_lock(cache, {'pid': proc.pid, 'host': socket.gethostname(), 'nonce': 'n2'})
        assert cache.put('signals', KEY, PAYLOAD, {}) is False
        assert cache.verify()['locks_recovered'] == 0
        assert lock.exists()
    finally:
        proc.kill()
        proc.wait()


@pytest.mark.parametrize('owner', [{'pid': 1, 'host': 'another-host', 'nonce': 'n'}, 'garbage'])
def test_foreign_host_or_unreadable_lock_not_stolen(cache, owner):
    if owner != 'garbage':
        owner['pid'] = _dead_pid()
        _plant_lock(cache, owner)
    else:
        lock = entry_dir(cache, 'signals', KEY).parent / f'{KEY}.lock'
        lock.parent.mkdir(parents=True)
        lock.write_text('garbage')
    assert cache.put('signals', KEY, PAYLOAD, {}) is False


# ---- no_cache / refresh --------------------------------------------------

def test_no_cache_touches_nothing(tmp_path, monkeypatch):
    c = DerivedCache(CacheConfig(root=tmp_path / 'never', no_cache=True))

    def boom(*_a, **_k):
        raise AssertionError('filesystem access under no_cache')

    for name in ('open', 'stat', 'lstat', 'mkdir', 'replace', 'rename', 'unlink', 'utime',
                 'scandir', 'listdir', 'fsync'):
        monkeypatch.setattr(cache_mod.os, name, boom)
    monkeypatch.setattr(builtins, 'open', boom)
    assert c.put('signals', KEY, PAYLOAD, {}) is False
    assert c.get('signals', KEY) is None
    assert c.put_raw(fp(), A, B, PAYLOAD) is False
    assert c.get_raw(fp(), A, B) is None
    with c.lease('signals', KEY):
        pass
    assert c.status()['enabled'] is False
    assert c.verify()['ok'] == 0
    assert c.prune(0)['removed'] == 0
    monkeypatch.undo()
    assert not (tmp_path / 'never').exists()


def test_refresh_bypasses_reads_only_for_selected_stages(tmp_path):
    root = tmp_path / 'c'
    normal = DerivedCache(CacheConfig(root=root))
    rk = stage_id('ranking', 1, {'s': KEY})
    assert normal.put('signals', KEY, PAYLOAD, {})
    assert normal.put('ranking', rk, b'r', {})
    refreshed = DerivedCache(CacheConfig(root=root, refresh_stages=frozenset({'signals'})))
    assert refreshed.get('signals', KEY) is None
    assert refreshed.get('ranking', rk) == b'r'
    # Refresh still writes; the existing identical entry counts as admitted.
    assert refreshed.put('signals', KEY, PAYLOAD, {})
    assert normal.get('signals', KEY) == PAYLOAD


def test_status_reports_usage(cache):
    assert cache.status()['entries'] == 0
    assert cache.put('signals', KEY, PAYLOAD, {})
    s = cache.status()
    assert s['entries'] == 1 and s['by_stage']['signals']['entries'] == 1 and s['bytes'] > len(PAYLOAD)


def test_cache_module_has_no_forbidden_imports():
    source = Path(cache_mod.__file__).read_text()
    for name in ('PySide6', 'subprocess', 'ssl', 'http.client', 'urllib.request'):
        assert f'import {name}' not in source and f'from {name}' not in source
