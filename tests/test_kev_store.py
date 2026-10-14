"""kev/1 snapshot store: atomic install order, never-older current, damaged-file fallback, retry, explicit prune."""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

import pytest

from patchtrace.kev.contracts import KevError
from patchtrace.kev.parse import parse_catalog
from patchtrace.kev.store import KevStore, default_kev_dir

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
SET_AT = '2099-03-02T00:00:00Z'


def make(version: str, released: str, cves: tuple[str, ...] = ('CVE-2099-10001',)) -> tuple[bytes, object]:
    data = json.loads((FIXTURES / 'kev-synthetic-2099.json').read_text(encoding='utf-8'))
    template = data['vulnerabilities'][0]
    data['catalogVersion'], data['dateReleased'] = version, released
    data['vulnerabilities'] = [{**template, 'cveID': cve} for cve in cves]
    data['count'] = len(cves)
    raw = json.dumps(data).encode('utf-8')
    return raw, parse_catalog(raw, source='local-import', retrieved_at='2099-03-02T00:00:00Z', file_name='k.json')


@pytest.fixture
def store(tmp_path):
    return KevStore(tmp_path / 'kev', sleep=lambda _s: None)


def test_install_then_load_roundtrip(store):
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    result = store.install(cat, raw, SET_AT)
    assert result.current_changed
    loaded = store.load_current()
    assert loaded.catalog == cat
    assert loaded.note is None
    pointer = json.loads((store.root / 'current.json').read_text(encoding='utf-8'))
    assert pointer == {'snapshot_id': cat.meta.snapshot_id, 'raw_sha256': cat.meta.raw_sha256,
                       'date_released': cat.meta.date_released, 'set_at': SET_AT}
    assert gzip.decompress((store.root / 'snapshots' / f'{cat.meta.raw_sha256}.json.gz').read_bytes()) == raw


def test_empty_store_has_no_current(store):
    assert store.load_current() is None
    assert store.list_snapshots() == []


@pytest.mark.parametrize('fail_at', [1, 2, 3], ids=['snapshot', 'meta', 'pointer'])
def test_install_crash_points_keep_previous_current(tmp_path, fail_at):
    calls = []

    def flaky(src, dst):
        calls.append(dst)
        if len(calls) == fail_at + 3:  # the first install uses calls 1-3
            raise OSError('disk gone')
        os.replace(src, dst)

    store = KevStore(tmp_path / 'kev', replace=flaky, sleep=lambda _s: None)
    raw1, old = make('v1', '2099-03-01T12:00:00Z')
    store.install(old, raw1, SET_AT)
    raw2, new = make('v2', '2099-03-05T12:00:00Z', ('CVE-2099-10001', 'CVE-2099-10002'))
    with pytest.raises(KevError) as info:
        store.install(new, raw2, SET_AT)
    assert info.value.code == 'PT-KEV-STORAGE'
    assert store.load_current().catalog == old
    assert not [p for p in store.root.rglob('*') if p.name.startswith('.partial-')]


def test_older_mirror_never_replaces_newer_current(store):
    raw_new, new = make('v2', '2099-03-05T12:00:00Z')
    raw_old, old = make('v1', '2099-03-01T12:00:00Z', ('CVE-2099-10002',))
    store.install(new, raw_new, SET_AT)
    result = store.install(old, raw_old, SET_AT)
    assert not result.current_changed
    assert 'older' in result.note
    assert store.load_current().catalog == new
    assert [m.snapshot_id for m in store.list_snapshots()] == [new.meta.snapshot_id]


def test_reinstall_same_snapshot_is_idempotent(store):
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    store.install(cat, raw, SET_AT)
    again = store.install(cat, raw, SET_AT)
    assert not again.current_changed
    assert len(store.list_snapshots()) == 1


@pytest.mark.parametrize('damage', ['pointer-garbage', 'snapshot-bytes', 'meta-missing', 'pointer-missing'],
                         ids=['pointer', 'snapshot', 'meta', 'nopointer'])
def test_damaged_current_falls_back_and_says_so(store, damage):
    raw1, old = make('v1', '2099-03-01T12:00:00Z')
    raw2, new = make('v2', '2099-03-05T12:00:00Z', ('CVE-2099-10001', 'CVE-2099-10002'))
    store.install(old, raw1, SET_AT)
    store.install(new, raw2, SET_AT)
    if damage == 'pointer-garbage':
        (store.root / 'current.json').write_text('{nope', encoding='utf-8')
    elif damage == 'pointer-missing':
        (store.root / 'current.json').unlink()
    elif damage == 'snapshot-bytes':
        (store.root / 'snapshots' / f'{new.meta.raw_sha256}.json.gz').write_bytes(gzip.compress(b'{}'))
    else:
        (store.root / 'meta' / f'{new.meta.snapshot_id}.json').unlink()
    loaded = store.load_current()
    expected = old if damage in ('snapshot-bytes', 'meta-missing') else new
    assert loaded.catalog == expected
    assert loaded.note
    if damage in ('snapshot-bytes', 'meta-missing'):
        assert 'v1' in loaded.note


def test_all_damaged_reports_none(store):
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    store.install(cat, raw, SET_AT)
    (store.root / 'snapshots' / f'{cat.meta.raw_sha256}.json.gz').write_bytes(b'not gzip')
    assert store.load_current() is None


def test_decompression_is_capped(store):
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    store.install(cat, raw, SET_AT)
    bomb = gzip.compress(b'0' * (16 * 1024 * 1024 + 10))
    (store.root / 'snapshots' / f'{cat.meta.raw_sha256}.json.gz').write_bytes(bomb)
    assert store.load_current() is None


def test_replace_retries_on_permission_error(tmp_path):
    failures = {'left': 2}
    waits = []

    def sharing_violation(src, dst):
        if failures['left'] and str(dst).endswith('current.json'):
            failures['left'] -= 1
            raise PermissionError('sharing violation')
        os.replace(src, dst)

    store = KevStore(tmp_path / 'kev', replace=sharing_violation, sleep=waits.append)
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    store.install(cat, raw, SET_AT)
    assert store.load_current().catalog == cat
    assert len(waits) == 2


def test_replace_gives_up_after_three_permission_errors(tmp_path):
    def locked(src, dst):
        raise PermissionError('locked')

    store = KevStore(tmp_path / 'kev', replace=locked, sleep=lambda _s: None)
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    with pytest.raises(KevError) as info:
        store.install(cat, raw, SET_AT)
    assert info.value.code == 'PT-KEV-STORAGE'


def test_prune_only_when_asked(store):
    ids = []
    for day in (1, 2, 3, 4):
        raw, cat = make(f'v{day}', f'2099-03-0{day}T12:00:00Z', (f'CVE-2099-1000{day}',))
        store.install(cat, raw, SET_AT)
        ids.append(cat.meta.snapshot_id)
    with pytest.raises(KevError) as info:
        store.prune(2, confirmed=False)
    assert info.value.code == 'PT-KEV-INPUT'
    assert len(store.list_snapshots()) == 4
    removed = store.prune(2, confirmed=True)
    assert sorted(removed) == sorted(ids[:2])
    assert [m.snapshot_id for m in store.list_snapshots()] == [ids[3], ids[2]]
    assert store.load_current().catalog.meta.snapshot_id == ids[3]
    assert len(list((store.root / 'snapshots').iterdir())) == 2


def test_prune_requires_keep_at_least_one(store):
    with pytest.raises(KevError):
        store.prune(0, confirmed=True)


def test_previous_and_load_by_id(store):
    raw1, old = make('v1', '2099-03-01T12:00:00Z')
    raw2, new = make('v2', '2099-03-05T12:00:00Z', ('CVE-2099-10002',))
    store.install(old, raw1, SET_AT)
    assert store.previous() is None
    store.install(new, raw2, SET_AT)
    assert store.previous().meta.snapshot_id == old.meta.snapshot_id
    assert store.load(new.meta.snapshot_id) == new
    with pytest.raises(KevError) as info:
        store.load('0' * 64)
    assert info.value.code == 'PT-KEV-NOTFOUND'


def test_size_warning_above_threshold(store, monkeypatch):
    raw, cat = make('v1', '2099-03-01T12:00:00Z')
    store.install(cat, raw, SET_AT)
    assert store.size_warning() is None
    monkeypatch.setattr('patchtrace.kev.store.WARN_BYTES', 10)
    assert '256 MiB' in store.size_warning()


@pytest.mark.parametrize('env,expected', [
    ({'LOCALAPPDATA': 'C:/L'}, Path('C:/L') / 'PatchTrace' / 'kev'),
    ({'XDG_DATA_HOME': '/x'}, Path('/x') / 'PatchTrace' / 'kev'),
], ids=['windows', 'xdg'])
def test_default_dir(env, expected):
    assert default_kev_dir(env, home=Path('/h')) == expected
