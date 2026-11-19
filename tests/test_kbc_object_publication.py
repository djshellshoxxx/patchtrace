"""Authored object bytes only: immutable publication must not follow or replace paths."""
from __future__ import annotations

import gzip
import hashlib
import os
import sqlite3
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture

from patchtrace.kbcorrelation import inventory_store
from patchtrace.kbcorrelation import store as store_module
from patchtrace.kbcorrelation.inventory_contracts import InventoryContext
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

RAW = b'File name,File version,File size,Architecture\r\nexample.dll,1.2.3.4,128,x64\r\n'
SHA = hashlib.sha256(RAW).hexdigest()


@pytest.fixture
def ws(tmp_path):
    with WorkspaceStore(tmp_path / 'workspace') as store:
        yield store


def _add(ws, kind):
    if kind == 'advisory':
        return ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
    return inventory_store.add_inventory(ws, RAW, InventoryContext(kb='KB5099001'), now='2099-02-01T00:00:00Z')


def _assert_no_imports(ws):
    assert ws.sources() == ()
    assert inventory_store.inventory_count(ws) == 0
    assert ws.db.execute('PRAGMA integrity_check').fetchone() == ('ok',)


@pytest.mark.parametrize('existing', [b'preserved damaged evidence', gzip.compress(b'different source')])
def test_existing_damaged_object_is_never_silently_replaced(ws, existing):
    path = ws.object_path(SHA)
    path.parent.mkdir(parents=True)
    path.write_bytes(existing)
    before = path.stat()
    with pytest.raises(KbcStoreError):
        ws.write_object(SHA, RAW)
    assert path.read_bytes() == existing and path.stat().st_ino == before.st_ino


def test_matching_existing_gzip_is_reused_without_recompression(ws):
    path = ws.object_path(SHA)
    path.parent.mkdir(parents=True)
    existing = gzip.compress(RAW, compresslevel=1, mtime=123456)
    path.write_bytes(existing)
    before = path.stat()
    ws.write_object(SHA, RAW)
    assert path.read_bytes() == existing
    assert (path.stat().st_ino, path.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


@pytest.mark.parametrize('matching', [False, True])
def test_concurrent_existing_object_wins_without_replacement(ws, monkeypatch, matching):
    path = ws.object_path(SHA)
    winner = gzip.compress(RAW, mtime=123) if matching else b'concurrent evidence'
    real_fsync, before = os.fsync, []

    def publish_winner(fd):
        real_fsync(fd)
        path.write_bytes(winner)
        before.append(path.stat())

    monkeypatch.setattr(os, 'fsync', publish_winner)
    if matching:
        ws.write_object(SHA, RAW)
    else:
        with pytest.raises(KbcStoreError):
            ws.write_object(SHA, RAW)
    assert before and path.read_bytes() == winner
    assert (path.stat().st_ino, path.stat().st_mtime_ns) == (before[0].st_ino, before[0].st_mtime_ns)


@pytest.mark.parametrize('kind', ['advisory', 'inventory'])
def test_parent_replacement_cannot_publish_foreign_bytes_or_admit_import(ws, tmp_path, monkeypatch, kind):
    real_fsync = os.fsync
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    attempted, originals = [], []

    def replace_parent(fd):
        real_fsync(fd)
        parents = list((ws.root / 'objects').iterdir())
        assert len(parents) == 1
        parent = parents[0]
        names = [p.name for p in parent.iterdir()]
        moved = tmp_path / 'moved-parent'
        try:
            parent.rename(moved)
        except PermissionError:
            assert os.name == 'nt'
            attempted.append(False)
            return
        attempted.append(True)
        parent.symlink_to(foreign, target_is_directory=True)
        for name in names:
            target = foreign / name
            target.write_bytes(b'foreign stage must survive')
            originals.append(target)
        if kind == 'inventory':
            target = foreign / (SHA + '.gz')
        else:
            target = foreign / (import_fixture('cvrf-2099-Feb.json').source.sha256 + '.gz')
        target.write_bytes(b'prior foreign destination')
        originals.append(target)

    monkeypatch.setattr(os, 'fsync', replace_parent)
    try:
        _add(ws, kind)
    except KbcStoreError:
        assert attempted == [True]
        _assert_no_imports(ws)
    else:
        assert attempted == [False], 'publication followed a substituted parent'
    for path in originals:
        expected = b'prior foreign destination' if path.suffix == '.gz' else b'foreign stage must survive'
        assert path.read_bytes() == expected


def test_cancelled_cleanup_never_deletes_replacement_stage(ws, tmp_path, monkeypatch):
    real_fsync = os.fsync
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    replacements = []

    def replace_then_cancel(fd):
        real_fsync(fd)
        parent = ws.object_path(SHA).parent
        names = [p.name for p in parent.iterdir()]
        try:
            parent.rename(tmp_path / 'owned-parent')
        except PermissionError:
            assert os.name == 'nt'
        else:
            parent.symlink_to(foreign, target_is_directory=True)
            for name in names:
                target = foreign / name
                target.write_bytes(b'foreign replacement')
                replacements.append(target)
        raise KeyboardInterrupt()

    monkeypatch.setattr(os, 'fsync', replace_then_cancel)
    with pytest.raises(KeyboardInterrupt):
        ws.write_object(SHA, RAW)
    for path in replacements:
        assert path.read_bytes() == b'foreign replacement'
    _assert_no_imports(ws)


@pytest.mark.parametrize('kind', ['advisory', 'inventory'])
def test_changed_staging_bytes_never_admit_an_import(ws, monkeypatch, kind):
    real_fsync = os.fsync

    def corrupt(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b'not the staged gzip')
        real_fsync(fd)

    monkeypatch.setattr(os, 'fsync', corrupt)
    with pytest.raises(KbcStoreError):
        _add(ws, kind)
    _assert_no_imports(ws)


def test_matching_symlink_object_is_not_adopted(ws, tmp_path):
    if os.name == 'nt':
        pytest.skip('symlink creation privilege is not assumed; Windows reparse tests cover the native lane')
    path = ws.object_path(SHA)
    path.parent.mkdir(parents=True)
    outside = tmp_path / 'outside.gz'
    outside.write_bytes(gzip.compress(RAW))
    path.symlink_to(outside)
    before = outside.read_bytes()
    with pytest.raises(KbcStoreError):
        ws.write_object(SHA, RAW)
    assert path.is_symlink() and outside.read_bytes() == before


def test_direct_object_write_respects_newer_readonly_store(ws):
    root = ws.root
    ws.close()
    connection = sqlite3.connect(root / 'kbc.sqlite3')
    connection.execute('PRAGMA user_version=2')
    connection.close()
    with WorkspaceStore(root) as readonly:
        with pytest.raises(KbcStoreError):
            readonly.write_object(SHA, RAW)
    assert not (root / 'objects').exists()


def test_source_digest_mismatch_creates_no_object(ws):
    with pytest.raises(KbcStoreError):
        ws.write_object(SHA, b'wrong')
    assert not (ws.root / 'objects').exists()


@pytest.mark.parametrize('kind', ['advisory', 'inventory'])
def test_replacing_workspace_root_after_open_cannot_redirect_an_import(ws, tmp_path, kind):
    root = ws.root
    moved = tmp_path / 'original-workspace'
    try:
        root.rename(moved)
    except PermissionError:
        assert os.name == 'nt'
        _add(ws, kind)  # a native sharing denial keeps the original root usable
        return
    root.mkdir()
    with pytest.raises(KbcStoreError):
        _add(ws, kind)
    assert list(root.iterdir()) == []
    root.rmdir()
    moved.rename(root)
    _assert_no_imports(ws)


def test_replacing_workspace_root_after_open_cannot_adopt_foreign_matching_bytes(ws, tmp_path):
    ws.write_object(SHA, RAW)
    root = ws.root
    try:
        root.rename(tmp_path / 'original-workspace')
    except PermissionError:
        assert os.name == 'nt'
        assert ws.read_object(SHA) == RAW
        return
    root.mkdir()
    foreign = ws.object_path(SHA)
    foreign.parent.mkdir(parents=True)
    encoded = gzip.compress(RAW, mtime=42)
    foreign.write_bytes(encoded)
    for action in (lambda: ws.read_object(SHA), lambda: ws.write_object(SHA, RAW)):
        with pytest.raises(KbcStoreError):
            action()
    assert foreign.read_bytes() == encoded


@pytest.mark.skipif(os.name != 'nt', reason='native Windows existing-object sharing acceptance')
def test_windows_existing_object_validation_holds_read_only_sharing(ws, tmp_path, monkeypatch):
    ws.write_object(SHA, RAW)
    path = ws.object_path(SHA)
    before = path.read_bytes()
    decode, calls = ws._decode_object, []

    def validate(compressed, sha, **options):
        with pytest.raises(PermissionError):
            path.write_bytes(b'foreign mutation')
        with pytest.raises(PermissionError):
            path.rename(tmp_path / 'displaced-object')
        with pytest.raises(PermissionError):
            path.parent.rename(tmp_path / 'displaced-parent')
        calls.append(True)
        return decode(compressed, sha, **options)

    monkeypatch.setattr(ws, '_decode_object', validate)
    ws.write_object(SHA, RAW)
    assert calls == [True] and path.read_bytes() == before


def test_existing_object_replacement_during_validation_is_not_adopted(ws, tmp_path, monkeypatch):
    ws.write_object(SHA, RAW)
    path = ws.object_path(SHA)
    before = path.read_bytes()
    decode, changed = ws._decode_object, []

    def validate(compressed, sha, **options):
        raw = decode(compressed, sha, **options)
        try:
            path.rename(tmp_path / 'original-object.gz')
        except PermissionError:
            assert os.name == 'nt'
            changed.append(False)
        else:
            path.write_bytes(before)
            changed.append(True)
        return raw

    monkeypatch.setattr(ws, '_decode_object', validate)
    try:
        ws.write_object(SHA, RAW)
    except KbcStoreError:
        assert changed == [True]
    else:
        assert changed == [False]
    assert path.read_bytes() == before


def test_existing_directory_is_preserved_without_import(ws):
    path = ws.object_path(SHA)
    path.mkdir(parents=True)
    marker = path / 'previous-evidence'
    marker.write_bytes(b'prior evidence')
    with pytest.raises(KbcStoreError):
        inventory_store.add_inventory(ws, RAW, InventoryContext(kb='KB5099001'), now='2099-02-01T00:00:00Z')
    _assert_no_imports(ws)
    assert marker.read_bytes() == b'prior evidence'


@pytest.mark.parametrize('version', [1, 2])
def test_selected_root_alias_retarget_cannot_split_database_and_objects(tmp_path, monkeypatch, version):
    selected, original, foreign = (tmp_path / name for name in ('selected', 'original', 'foreign'))
    with WorkspaceStore(original) as initial:
        initial.db.execute(f'PRAGMA user_version={version}')
    foreign.mkdir()
    try:
        selected.symlink_to(original, target_is_directory=True)
    except OSError as exc:
        if os.name == 'nt' and getattr(exc, 'winerror', None) == 1314:
            pytest.skip('Windows symlink creation privilege is unavailable')
        raise
    capture = store_module.directory_anchor

    def capture_then_retarget(path):
        anchor = capture(path)
        selected.unlink()
        selected.symlink_to(foreign, target_is_directory=True)
        return anchor

    monkeypatch.setattr(store_module, 'directory_anchor', capture_then_retarget)
    with WorkspaceStore(selected) as opened:
        database = Path(opened.db.execute('PRAGMA database_list').fetchone()[2])
        assert database.resolve() == original / 'kbc.sqlite3'
        assert opened.read_only == (version == 2)
        assert opened.object_path(SHA) == original / 'objects' / SHA[:2] / (SHA + '.gz')
        if not opened.read_only:
            opened.write_object(SHA, RAW)
            assert opened.read_object(SHA) == RAW
    assert list(foreign.iterdir()) == []
