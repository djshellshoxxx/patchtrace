"""kev/1 snapshot store: content-addressed files, a pointer replaced last, safe fallback, deletion only by prune."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import tempfile
import tracemalloc
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from kev_helpers import SYNTHETIC, document, entry, fixture_bytes, parse_bytes, render, socket_guard

from patchtrace.kev import limits, store
from patchtrace.kev.contracts import KevCatalogMeta, KevCurrent, KevError
from patchtrace.kev.store import KevStore, default_kev_dir

NOW = '2099-03-02T08:00:00Z'
LATER = '2099-03-03T08:00:00Z'
NO_POINTER = 'No catalog is marked as in use; the newest valid catalog is used.'
UNREADABLE = 'The catalog marked as in use could not be read; the newest valid catalog is used.'
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)


class SimulatedCrash(BaseException):
    """Process death: nothing after it runs, no cleanup included."""


def catalog_bytes(day: int = 1, entries: int = 10) -> bytes:
    """A valid synthetic catalog released on 2098-02-<day>; other days or entry counts make other bytes."""
    rows = [entry(n) for n in range(1, entries + 1)]
    return render(document(rows, dateReleased=f'2098-02-{day:02d}T12:00:00Z', catalogVersion=f'2098.02.{day:02d}'))


def installed(kev_store: KevStore, day: int, entries: int = 10, *, now: str = NOW, accept_shrink: bool = False):
    raw = catalog_bytes(day, entries)
    return kev_store.install(raw, parse_bytes(raw), now=now, accept_shrink=accept_shrink), raw


def files(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}


def raw_hash(root: Path, snapshot_id: str) -> str:
    return KevCatalogMeta.model_validate_json((root / 'meta' / f'{snapshot_id}.json').read_bytes()).raw_sha256


def point_at(root: Path, snapshot_id: str) -> None:
    """Make ``snapshot_id`` the catalog in use by hand, as a person repairing a store could."""
    meta = KevStore(root).read_meta(snapshot_id)
    pointer = KevCurrent(snapshot_id=snapshot_id, raw_sha256=meta.raw_sha256, date_released=meta.date_released,
                         set_at=LATER)
    (root / 'current.json').write_text(pointer.model_dump_json(), encoding='utf-8')


@pytest.fixture
def kev_store(tmp_path):
    return KevStore(tmp_path / 'kev', sleep=lambda seconds: None)


# --- install and load ---------------------------------------------------------------------------------------

def test_install_then_load_roundtrip(kev_store, tmp_path):
    raw = fixture_bytes(SYNTHETIC)
    catalog = parse_bytes(raw, name=SYNTHETIC)
    result = kev_store.install(raw, catalog, now=NOW)
    assert (result.outcome, result.snapshot_id, result.current_id) == ('installed', catalog.meta.snapshot_id,
                                                                       catalog.meta.snapshot_id)
    root = tmp_path / 'kev'
    assert files(root) == {f'snapshots/{catalog.meta.raw_sha256}.json.gz', f'meta/{catalog.meta.snapshot_id}.json',
                           'current.json'}
    assert gzip.decompress((root / 'snapshots' / f'{catalog.meta.raw_sha256}.json.gz').read_bytes()) == raw
    pointer = KevCurrent.model_validate_json((root / 'current.json').read_bytes())
    assert (pointer.snapshot_id, pointer.raw_sha256, pointer.date_released, pointer.set_at) == (
        catalog.meta.snapshot_id, catalog.meta.raw_sha256, catalog.meta.date_released, NOW)
    loaded = KevStore(root).load_current()
    assert loaded.notes == () and loaded.catalog.meta == catalog.meta
    assert [item.model_dump() for item in loaded.catalog.entries] == [item.model_dump() for item in catalog.entries]
    assert KevStore(root).load(catalog.meta.snapshot_id).meta == catalog.meta
    assert KevStore(root).read_meta(catalog.meta.snapshot_id) == catalog.meta


def test_the_catalog_in_use_is_read_without_listing_every_snapshot(tmp_path, monkeypatch):
    root, old, new = two_snapshots(tmp_path)
    monkeypatch.setattr(KevStore, 'list_snapshots', lambda self: pytest.fail('the happy path lists no snapshots'))
    loaded = KevStore(root).load_current()
    assert loaded.catalog.meta.snapshot_id == new.snapshot_id and loaded.notes == ()


def test_an_empty_store_has_no_catalog_and_reading_creates_nothing(tmp_path):
    empty = KevStore(tmp_path / 'never-created')
    assert empty.load_current() is None and empty.list_snapshots() == ()
    status = empty.status()
    assert (status.current, status.snapshots, status.bytes, status.notes, status.warning) == (None, 0, 0, (), None)
    assert not (tmp_path / 'never-created').exists()
    with pytest.raises(KevError) as caught:
        empty.load('a' * 64)
    assert caught.value.code == 'PT-KEV-NOTFOUND'


def test_install_writes_the_snapshot_then_the_meta_then_the_pointer(tmp_path, monkeypatch):
    order, real_publish = [], store._publish

    def spy(directory, name, data, sleep):
        order.append(name)
        return real_publish(directory, name, data, sleep)

    monkeypatch.setattr(store, '_publish', spy)
    result, raw = installed(KevStore(tmp_path / 'kev'), 1)
    assert order == [f'{hashlib.sha256(raw).hexdigest()}.json.gz', f'{result.snapshot_id}.json', 'current.json']


def test_installing_the_same_catalog_again_changes_nothing(kev_store, tmp_path):
    first, raw = installed(kev_store, 1)
    root = tmp_path / 'kev'
    before = {name: (root / name).read_bytes() for name in files(root)}
    again = kev_store.install(raw, parse_bytes(raw), now=LATER)
    assert again.outcome == 'unchanged' and again.current_id == first.current_id
    assert {name: (root / name).read_bytes() for name in files(root)} == before


def test_snapshot_files_are_deterministic_and_named_by_their_hash(tmp_path):
    raw = catalog_bytes(3)
    for name in ('one', 'two'):
        KevStore(tmp_path / name).install(raw, parse_bytes(raw), now=NOW)
    sha = hashlib.sha256(raw).hexdigest()
    first = (tmp_path / 'one' / 'snapshots' / f'{sha}.json.gz').read_bytes()
    assert first == (tmp_path / 'two' / 'snapshots' / f'{sha}.json.gz').read_bytes()
    assert first[:4] == b'\x1f\x8b\x08\x00' and first[4:8] == b'\x00\x00\x00\x00'      # no file name, no timestamp


def test_install_refuses_bytes_that_the_catalog_does_not_describe(kev_store, tmp_path):
    raw = catalog_bytes(1)
    with pytest.raises(KevError) as caught:
        kev_store.install(raw + b'\n', parse_bytes(raw), now=NOW)
    assert caught.value.code == 'PT-KEV-INPUT'
    with pytest.raises(KevError) as bad_clock:
        kev_store.install(raw, parse_bytes(raw), now='yesterday')
    assert bad_clock.value.code == 'PT-KEV-INPUT'
    assert not (tmp_path / 'kev').exists()


def test_store_paths_stay_short_on_windows(kev_store, tmp_path):
    installed(kev_store, 1)
    installed(kev_store, 2)
    assert max(len(name) for name in files(tmp_path / 'kev')) < 120
    assert len(store.tmp_name('snapshots/' + 'a' * 64 + '.json.gz')) < 120


# --- crash points -------------------------------------------------------------------------------------------

@pytest.mark.parametrize('point', ['before-snapshot', 'before-meta', 'before-pointer', 'replace-snapshot',
                                   'replace-meta', 'replace-pointer'])
def test_install_crash_points_keep_previous_current(tmp_path, monkeypatch, point):
    root = tmp_path / 'kev'
    old_raw = catalog_bytes(1)
    old = parse_bytes(old_raw)
    KevStore(root).install(old_raw, old, now=NOW)
    new_raw = catalog_bytes(2)
    new = parse_bytes(new_raw)
    real_publish, real_replace, calls = store._publish, os.replace, {'publish': 0, 'replace': 0}
    publish_at = {'before-snapshot': 1, 'before-meta': 2, 'before-pointer': 3}.get(point)
    replace_at = {'replace-snapshot': 1, 'replace-meta': 2, 'replace-pointer': 3}.get(point)

    def publish(*args, **kwargs):
        calls['publish'] += 1
        if calls['publish'] == publish_at:
            raise SimulatedCrash()
        return real_publish(*args, **kwargs)

    def replace(source, target):
        calls['replace'] += 1
        if calls['replace'] == replace_at:
            raise SimulatedCrash()
        return real_replace(source, target)

    monkeypatch.setattr(store, '_publish', publish)
    monkeypatch.setattr(os, 'replace', replace)
    monkeypatch.setattr(store, '_discard', lambda path: None)                  # a dead process cleans nothing up
    with pytest.raises(SimulatedCrash):
        KevStore(root).install(new_raw, new, now=LATER)
    monkeypatch.undo()
    reopened = KevStore(root)
    loaded = reopened.load_current()
    assert loaded.catalog.meta == old.meta and loaded.notes == ()              # the previous catalog is still current
    assert KevCurrent.model_validate_json((root / 'current.json').read_bytes()).snapshot_id == old.meta.snapshot_id
    listed = {meta.snapshot_id for meta in reopened.list_snapshots()}
    assert (new.meta.snapshot_id in listed) == (point in ('before-pointer', 'replace-pointer'))   # only whole pairs
    again = reopened.install(new_raw, new, now=LATER)                          # the install can simply be repeated
    assert again.outcome == 'installed' and reopened.load_current().catalog.meta == new.meta


def test_a_crash_before_the_first_pointer_leaves_a_usable_fully_written_snapshot(tmp_path, monkeypatch):
    root = tmp_path / 'kev'
    raw = catalog_bytes(1)
    real_publish, calls = store._publish, {'n': 0}

    def publish(*args, **kwargs):
        calls['n'] += 1
        if calls['n'] == 3:
            raise SimulatedCrash()
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(store, '_publish', publish)
    with pytest.raises(SimulatedCrash):
        KevStore(root).install(raw, parse_bytes(raw), now=NOW)
    monkeypatch.undo()
    loaded = KevStore(root).load_current()
    assert loaded.catalog.meta.raw_sha256 == hashlib.sha256(raw).hexdigest() and loaded.notes == (NO_POINTER,)


def test_a_crash_during_the_very_first_install_leaves_no_catalog_and_no_false_alarm(tmp_path, monkeypatch):
    root = tmp_path / 'kev'
    raw = catalog_bytes(1)

    def crash(source, target):
        raise SimulatedCrash()

    monkeypatch.setattr(os, 'replace', crash)
    monkeypatch.setattr(store, '_discard', lambda path: None)
    with pytest.raises(SimulatedCrash):
        KevStore(root).install(raw, parse_bytes(raw), now=NOW)
    monkeypatch.undo()
    assert [name for name in files(root)] and all(name.endswith('.tmp') for name in files(root))
    kev = KevStore(root)
    status = kev.status()
    assert kev.load_current() is None and status.current is None and status.notes == () and status.snapshots == 0
    assert kev.prune(keep=1, yes=True).removed_files == 1 and files(root) == set()     # prune cleans the leftover
    assert installed(kev, 1)[0].outcome == 'installed'


def test_replace_retries_on_permission_error(tmp_path, monkeypatch):
    slept, real_replace, failures = [], os.replace, {'left': 2}

    def flaky(source, target):
        if failures['left'] > 0:
            failures['left'] -= 1
            raise PermissionError('antivirus holds the file')
        return real_replace(source, target)

    monkeypatch.setattr(os, 'replace', flaky)
    patient = KevStore(tmp_path / 'kev', sleep=slept.append)
    result, _ = installed(patient, 1)
    assert result.outcome == 'installed' and len(slept) == 2 and slept == sorted(slept) and slept[0] > 0
    assert not [name for name in files(tmp_path / 'kev') if name.endswith('.tmp')]
    assert patient.load_current().catalog.meta.catalog_version == '2098.02.01'


def test_replace_gives_up_after_three_attempts_and_keeps_the_previous_current(tmp_path, monkeypatch):
    root = tmp_path / 'kev'
    old, _ = installed(KevStore(root), 1)

    def locked(source, target):
        raise PermissionError('locked')

    monkeypatch.setattr(os, 'replace', locked)
    slept = []
    with pytest.raises(KevError) as caught:
        installed(KevStore(root, sleep=slept.append), 2)
    monkeypatch.undo()
    assert caught.value.code == 'PT-KEV-STORAGE' and len(slept) == limits.REPLACE_ATTEMPTS - 1
    assert not [name for name in files(root) if name.endswith('.tmp')]
    assert KevStore(root).load_current().catalog.meta.snapshot_id == old.snapshot_id


def test_an_unwritable_folder_is_a_typed_storage_error(tmp_path):
    blocker = tmp_path / 'file-not-folder'
    blocker.write_text('x', encoding='utf-8')
    with pytest.raises(KevError) as caught:
        installed(KevStore(blocker / 'kev'), 1)
    assert caught.value.code == 'PT-KEV-STORAGE'


# --- release order and shrink guard -------------------------------------------------------------------------

def test_older_mirror_never_replaces_newer_current(kev_store, tmp_path):
    newer, _ = installed(kev_store, 9)
    older, _ = installed(kev_store, 3, now=LATER)
    assert (older.outcome, older.current_id) == ('kept-newer', newer.snapshot_id)
    assert older.snapshot_id != newer.snapshot_id
    assert kev_store.load_current().catalog.meta.snapshot_id == newer.snapshot_id
    assert [meta.catalog_version for meta in kev_store.list_snapshots()] == ['2098.02.09', '2098.02.03']   # both kept
    pointer = KevCurrent.model_validate_json((tmp_path / 'kev' / 'current.json').read_bytes())
    assert pointer.snapshot_id == newer.snapshot_id


def test_a_newer_release_replaces_current_and_an_equal_one_does_too(kev_store):
    installed(kev_store, 3)
    second, _ = installed(kev_store, 5)
    assert second.outcome == 'installed' and kev_store.load_current().catalog.meta.snapshot_id == second.snapshot_id
    raw = render(document([entry(n) for n in range(1, 11)], dateReleased='2098-02-05T12:00:00Z',
                          catalogVersion='2098.02.05', extra='same release, other bytes'))
    same_release = kev_store.install(raw, parse_bytes(raw), now=LATER)
    assert same_release.outcome == 'installed' and same_release.snapshot_id != second.snapshot_id
    assert kev_store.load_current().catalog.meta.snapshot_id == same_release.snapshot_id


def test_a_much_smaller_catalog_needs_an_explicit_accept(kev_store, tmp_path):
    big, _ = installed(kev_store, 1, entries=100)
    before = files(tmp_path / 'kev')
    with pytest.raises(KevError) as caught:
        installed(kev_store, 2, entries=89)
    assert caught.value.code == 'PT-KEV-SHRINK' and '11' in caught.value.message
    assert files(tmp_path / 'kev') == before and kev_store.load_current().catalog.meta.snapshot_id == big.snapshot_id
    exactly_ninety, _ = installed(kev_store, 3, entries=90)                     # 90 of 100 is the boundary: allowed
    assert exactly_ninety.outcome == 'installed'
    smaller, _ = installed(kev_store, 4, entries=10, accept_shrink=True)
    assert smaller.outcome == 'installed' and kev_store.load_current().catalog.meta.entry_count == 10


def test_release_order_is_judged_against_the_catalog_in_use_not_the_newest_stored(kev_store, tmp_path):
    root = tmp_path / 'kev'
    in_use, _ = installed(kev_store, 5)
    newest, _ = installed(kev_store, 9)
    point_at(root, in_use.snapshot_id)                                          # in use: 5, stored and newer: 9
    between, _ = installed(kev_store, 7)
    assert (between.outcome, between.current_id) == ('installed', between.snapshot_id)
    older, _ = installed(kev_store, 3)
    assert older.outcome == 'kept-newer' and older.current_id == between.snapshot_id
    assert newest.snapshot_id != between.snapshot_id


def test_the_shrink_guard_does_not_apply_to_a_kept_older_release(kev_store):
    installed(kev_store, 9, entries=100)
    older, _ = installed(kev_store, 3, entries=5)
    assert older.outcome == 'kept-newer'


# --- damage -------------------------------------------------------------------------------------------------

def two_snapshots(tmp_path):
    root = tmp_path / 'kev'
    kev = KevStore(root)
    old, _ = installed(kev, 1)
    new, _ = installed(kev, 2)
    return root, old, new


def test_damaged_current_falls_back_and_says_so(tmp_path):
    root, old, new = two_snapshots(tmp_path)
    (root / 'current.json').write_text('{ not json', encoding='utf-8')
    loaded = KevStore(root).load_current()
    assert loaded.catalog.meta.snapshot_id == new.snapshot_id                   # the newest valid one
    assert loaded.notes == ('The record of the catalog in use is damaged; the newest valid catalog is used.',)
    assert KevStore(root).status().notes == loaded.notes
    installed(KevStore(root), 2)                                                # installing again repairs the pointer
    assert KevStore(root).load_current().notes == ()


def test_a_pointer_to_nowhere_and_a_missing_pointer_fall_back_with_a_note(tmp_path):
    root, old, new = two_snapshots(tmp_path)
    pointer = json.loads((root / 'current.json').read_text(encoding='utf-8'))
    pointer['snapshot_id'] = 'f' * 64
    (root / 'current.json').write_text(json.dumps(pointer), encoding='utf-8')
    assert KevStore(root).load_current().notes == (UNREADABLE,)
    (root / 'current.json').unlink()
    assert KevStore(root).load_current().notes == (NO_POINTER,)


def test_a_pointer_that_disagrees_with_its_catalog_falls_back_to_the_newest_valid_one(tmp_path):
    root, old, new = two_snapshots(tmp_path)
    pointer = json.loads((root / 'current.json').read_text(encoding='utf-8'))
    pointer['raw_sha256'] = hashlib.sha256(b'something else').hexdigest()
    (root / 'current.json').write_text(json.dumps(pointer), encoding='utf-8')
    loaded = KevStore(root).load_current()
    assert loaded.catalog.meta.snapshot_id == new.snapshot_id and loaded.notes == (UNREADABLE,)   # not the older one
    pointer['snapshot_id'] = old.snapshot_id
    pointer['raw_sha256'] = raw_hash(root, new.snapshot_id)                   # names the old snapshot, the new hash
    (root / 'current.json').write_text(json.dumps(pointer), encoding='utf-8')
    assert KevStore(root).load_current().catalog.meta.snapshot_id == new.snapshot_id


@pytest.mark.parametrize('damage', ['snapshot-deleted', 'snapshot-garbage', 'snapshot-other-catalog',
                                    'snapshot-truncated', 'meta-deleted', 'meta-invalid', 'meta-lies'])
def test_a_damaged_current_snapshot_falls_back_to_the_previous_one(tmp_path, damage):
    root, old, new = two_snapshots(tmp_path)
    snapshot = root / 'snapshots' / f'{raw_hash(root, new.snapshot_id)}.json.gz'
    meta = root / 'meta' / f'{new.snapshot_id}.json'
    if damage == 'snapshot-deleted':
        snapshot.unlink()
    elif damage == 'snapshot-garbage':
        snapshot.write_bytes(b'not gzip at all')
    elif damage == 'snapshot-other-catalog':
        snapshot.write_bytes(gzip.compress(catalog_bytes(7)))
    elif damage == 'snapshot-truncated':
        snapshot.write_bytes(snapshot.read_bytes()[:30])
    elif damage == 'meta-deleted':
        meta.unlink()
    elif damage == 'meta-invalid':                                           # counts that do not add up
        meta.write_text(meta.read_text(encoding='utf-8').replace('"count": 10', '"count": 11'), encoding='utf-8')
    else:                                                                    # valid, but not what the bytes say
        meta.write_text(meta.read_text(encoding='utf-8').replace('2098.02.02', '2098.02.99'), encoding='utf-8')
    loaded = KevStore(root).load_current()
    assert loaded.catalog.meta.snapshot_id == old.snapshot_id and loaded.notes == (UNREADABLE,)
    with pytest.raises(KevError):
        KevStore(root).load(new.snapshot_id)
    if damage in ('snapshot-deleted', 'meta-deleted', 'meta-invalid'):        # what cannot be loaded is not listed
        assert [item.snapshot_id for item in KevStore(root).list_snapshots()] == [old.snapshot_id]


def test_a_snapshot_that_failed_to_load_is_not_tried_again_in_the_fallback(tmp_path, monkeypatch):
    root, old, new = two_snapshots(tmp_path)
    (root / 'snapshots' / f'{raw_hash(root, new.snapshot_id)}.json.gz').write_bytes(b'garbage')
    calls, real_load = [], KevStore.load

    def spy(self, snapshot_id):
        calls.append(snapshot_id)
        return real_load(self, snapshot_id)

    monkeypatch.setattr(KevStore, 'load', spy)
    assert KevStore(root).load_current().catalog.meta.snapshot_id == old.snapshot_id
    assert calls.count(new.snapshot_id) == 1 and calls.count(old.snapshot_id) == 1


def test_a_stored_file_with_the_wrong_hash_is_rejected_before_it_is_parsed(tmp_path, monkeypatch):
    root, old, new = two_snapshots(tmp_path)
    (root / 'snapshots' / f'{raw_hash(root, new.snapshot_id)}.json.gz').write_bytes(gzip.compress(catalog_bytes(7)))
    parsed = []
    real_parse = store.parse_catalog
    monkeypatch.setattr(store, 'parse_catalog', lambda raw, **kwargs: parsed.append(1) or real_parse(raw, **kwargs))
    with pytest.raises(KevError) as caught:
        KevStore(root).load(new.snapshot_id)
    assert caught.value.code == 'PT-KEV-STORAGE' and not parsed             # a hostile blob is never parsed


def test_when_nothing_valid_is_left_there_is_no_catalog_and_the_status_says_why(tmp_path):
    root, old, new = two_snapshots(tmp_path)
    for path in (root / 'snapshots').iterdir():
        path.write_bytes(b'garbage')
    kev = KevStore(root)
    assert kev.load_current() is None
    status = kev.status()
    assert status.current is None and status.notes == ('Stored catalogs exist, but none of them could be read.',)


def test_a_gzip_bomb_is_refused_without_inflating_it(tmp_path):
    root, old, new = two_snapshots(tmp_path)
    bomb = root / 'snapshots' / f'{raw_hash(root, new.snapshot_id)}.json.gz'
    with gzip.GzipFile(bomb, 'wb', compresslevel=9, mtime=0) as stream:
        for _ in range(64):
            stream.write(b'\0' * limits.MIB)                                    # 64 MiB of zeros in about 64 KiB
    assert bomb.stat().st_size < 200_000
    tracemalloc.start()
    try:
        loaded = KevStore(root).load_current()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert loaded.catalog.meta.snapshot_id == old.snapshot_id
    assert peak < 40 * limits.MIB, f'{peak / limits.MIB:.1f} MiB'              # cut at the 16 MiB limit, not inflated


@pytest.mark.parametrize('bad', ['../../etc/passwd', 'a' * 63, 'A' * 64, '', 'a' * 64 + '/x', None],
                         ids=['traversal', 'short', 'upper-case', 'empty', 'suffix', 'none'])
def test_foreign_ids_never_become_paths(kev_store, bad):
    for call in (kev_store.load, kev_store.read_meta):
        with pytest.raises(KevError) as caught:
            call(bad)
        assert caught.value.code == 'PT-KEV-INPUT'


# --- deletion only by prune ---------------------------------------------------------------------------------

def test_prune_only_when_asked(kev_store, tmp_path):
    root = tmp_path / 'kev'
    for day in (1, 2, 3):
        installed(kev_store, day)
    before = files(root)
    assert len(before) == 7                                                # three snapshots, three metas, a pointer
    kev_store.load_current(), kev_store.list_snapshots(), kev_store.status()
    installed(kev_store, 3)
    assert files(root) == before                                                # nothing but prune deletes
    for refused in ({'keep': 1}, {'keep': 1, 'yes': False}):
        with pytest.raises(KevError) as caught:
            kev_store.prune(**refused)
        assert caught.value.code == 'PT-KEV-INPUT'
    assert files(root) == before
    result = kev_store.prune(keep=1, yes=True)
    assert len(result.removed) == 2 and result.removed_files == 4 and result.freed_bytes > 0
    assert [meta.catalog_version for meta in kev_store.list_snapshots()] == ['2098.02.03']
    assert len(files(root)) == 3 and kev_store.load_current().catalog.meta.catalog_version == '2098.02.03'


def test_prune_cleans_orphans_and_crash_leftovers_but_not_the_catalog_in_use(kev_store, tmp_path):
    root = tmp_path / 'kev'
    installed(kev_store, 9)
    installed(kev_store, 1)                                                     # older: stored, not current
    installed(kev_store, 5)
    (root / 'snapshots' / 'x.json.gz.abcdef123456.tmp').write_bytes(b'half a file')
    (root / 'meta' / ('e' * 64 + '.json.abcdef123456.tmp')).write_bytes(b'half a meta')
    (root / 'snapshots' / ('f' * 64 + '.json.gz')).write_bytes(b'a snapshot without a meta')
    result = kev_store.prune(keep=1, yes=True)
    assert len(result.removed) == 2 and result.removed_files == 2 * 2 + 3
    assert [meta.catalog_version for meta in kev_store.list_snapshots()] == ['2098.02.09']
    assert kev_store.load_current().catalog.meta.catalog_version == '2098.02.09'
    assert len(files(root)) == 3


def test_prune_keeps_the_catalog_in_use_even_when_it_is_not_among_the_newest(kev_store, tmp_path):
    root = tmp_path / 'kev'
    in_use, _ = installed(kev_store, 5)
    installed(kev_store, 9)
    installed(kev_store, 2)
    point_at(root, in_use.snapshot_id)
    result = kev_store.prune(keep=1, yes=True)
    assert len(result.removed) == 1
    assert [item.catalog_version for item in kev_store.list_snapshots()] == ['2098.02.09', '2098.02.05']
    assert kev_store.load_current().catalog.meta.snapshot_id == in_use.snapshot_id


@pytest.mark.parametrize('keep', [0, -1])
def test_prune_refuses_nonsense_counts(kev_store, keep):
    installed(kev_store, 1)
    with pytest.raises(KevError) as caught:
        kev_store.prune(keep=keep, yes=True)
    assert caught.value.code == 'PT-KEV-INPUT'


# --- status and location ------------------------------------------------------------------------------------

def test_status_reports_size_and_warns_above_the_limit(kev_store, tmp_path, monkeypatch):
    installed(kev_store, 1)
    installed(kev_store, 2)
    status = kev_store.status()
    assert status.snapshots == 2 and status.current.catalog_version == '2098.02.02' and status.warning is None
    assert status.bytes == sum(path.stat().st_size for path in (tmp_path / 'kev').rglob('*') if path.is_file())
    monkeypatch.setattr(limits, 'STORE_WARN_BYTES', status.bytes - 1)
    warned = kev_store.status().warning
    assert warned.startswith('The KEV catalog folder holds ') and 'kev prune' in warned and '--yes' in warned
    assert len(files(tmp_path / 'kev')) == 5                                    # a warning never deletes


def test_a_file_that_vanishes_while_the_status_is_added_up_counts_as_nothing(tmp_path):
    present = tmp_path / 'present.bin'
    present.write_bytes(b'x' * 10)
    assert store._total_size([present, tmp_path / 'pruned-meanwhile.bin']) == 10


@pytest.mark.parametrize(('env', 'expected'), [
    ({'LOCALAPPDATA': 'C:\\Users\\a\\AppData\\Local'}, Path('C:\\Users\\a\\AppData\\Local') / 'PatchTrace' / 'kev'),
    ({'XDG_DATA_HOME': '/data'}, Path('/data') / 'PatchTrace' / 'kev'),
    ({'LOCALAPPDATA': '/win', 'XDG_DATA_HOME': '/data'}, Path('/win') / 'PatchTrace' / 'kev'),
    ({}, Path.home() / '.local' / 'share' / 'PatchTrace' / 'kev')],
    ids=['windows', 'xdg', 'windows-wins', 'home-fallback'])
def test_default_kev_dir(env, expected):
    assert default_kev_dir(env) == expected


# --- interleavings keep current valid -----------------------------------------------------------------------

OPERATION = st.tuples(st.integers(1, 20), st.sampled_from([None, 'before-snapshot', 'before-meta', 'before-pointer']))


@given(st.lists(OPERATION, min_size=1, max_size=8))
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_store_interleavings_keep_current_valid_and_never_older(operations):
    root = Path(tempfile.mkdtemp(prefix='kev-store-'))
    real, released_before = store._publish, None
    try:
        for day, crash in operations:
            raw = catalog_bytes(day)
            catalog = parse_bytes(raw)
            wanted, calls = {'before-snapshot': 1, 'before-meta': 2, 'before-pointer': 3}.get(crash), {'n': 0}

            def publish(*args, _calls=calls, _wanted=wanted, **kwargs):
                _calls['n'] += 1
                if _calls['n'] == _wanted:
                    raise SimulatedCrash()
                return real(*args, **kwargs)

            store._publish = publish
            try:
                KevStore(root, sleep=lambda seconds: None).install(raw, catalog, now=NOW)
            except SimulatedCrash:
                pass
            finally:
                store._publish = real
            reader = KevStore(root)
            loaded = reader.load_current()
            if loaded is None:
                assert released_before is None                          # once there is a catalog, there stays one
                continue
            released = loaded.catalog.meta.date_released
            assert released_before is None or released >= released_before       # the catalog in use never gets older
            released_before = released
            assert loaded.catalog.meta.snapshot_id in {meta.snapshot_id for meta in reader.list_snapshots()}
            assert loaded.notes == (() if (root / 'current.json').exists() else (NO_POINTER,))
    finally:
        store._publish = real
        shutil.rmtree(root, ignore_errors=True)
