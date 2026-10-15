"""Content-addressed snapshot store of KEV catalogs (KEV-integration-plan section 7). Pure file I/O, no network.

Layout under the store folder: ``snapshots/<raw sha256>.json.gz`` (the exact bytes CISA published, gzip without name
or time), ``meta/<snapshot id>.json`` (the ``KevCatalogMeta``: provenance and consent) and ``current.json`` (the
``KevCurrent`` pointer). An install writes the snapshot, then the meta, and replaces the pointer last, each through a
temporary file in the same folder, ``fsync`` and ``os.replace``, so a crash at any step leaves the previous catalog in
use and at worst an unreferenced file. A catalog older than the one in use is stored but never becomes current.
Reading verifies the stored bytes against their hash and re-parses them, so a damaged pointer or file falls back
to the newest valid snapshot and says so. Only ``prune`` deletes stored catalogs (and the leftovers of crashes).

Known limit: choosing the current catalog is check-then-replace without a lock, so two processes installing different
releases at the same instant could leave the older one current until the next install; both files stay valid.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import re
import secrets
import time
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from . import limits
from .contracts import KevCatalog, KevCatalogMeta, KevCurrent, KevError
from .parse import parse_catalog

STORAGE = 'PT-KEV-STORAGE'
CURRENT_FILE, SNAPSHOT_DIR, META_DIR = 'current.json', 'snapshots', 'meta'
SNAPSHOT_SUFFIX, TMP_SUFFIX = '.json.gz', '.tmp'
POINTER_CAP, META_CAP = 4 * limits.KIB, 64 * limits.KIB
_ID = re.compile(r'[0-9a-f]{64}')

NOTE_DAMAGED_POINTER = 'The record of the catalog in use is damaged; the newest valid catalog is used.'
NOTE_NO_POINTER = 'No catalog is marked as in use; the newest valid catalog is used.'
NOTE_UNREADABLE = 'The catalog marked as in use could not be read; the newest valid catalog is used.'
NOTE_NONE_READABLE = 'Stored catalogs exist, but none of them could be read.'


@dataclass(frozen=True, slots=True)
class InstallResult:
    """``installed``: now current. ``kept-newer``: stored, but the newer catalog in use was kept. ``unchanged``."""
    outcome: Literal['installed', 'kept-newer', 'unchanged']
    snapshot_id: str
    current_id: str


@dataclass(frozen=True, slots=True)
class Loaded:
    catalog: KevCatalog
    notes: tuple[str, ...]                 # non-empty only when the pointer or a file was damaged


@dataclass(frozen=True, slots=True)
class StoreStatus:
    current: KevCatalogMeta | None
    notes: tuple[str, ...]
    snapshots: int
    bytes: int
    warning: str | None


@dataclass(frozen=True, slots=True)
class PruneResult:
    removed: tuple[str, ...]               # snapshot ids
    removed_files: int
    freed_bytes: int


def default_kev_dir(env: Mapping[str, str] | None = None) -> Path:
    """``%LOCALAPPDATA%\\PatchTrace\\kev``, else ``$XDG_DATA_HOME/PatchTrace/kev``, else ``~/.local/share/...``."""
    env = os.environ if env is None else env
    if env.get('LOCALAPPDATA'):
        return Path(env['LOCALAPPDATA']) / 'PatchTrace' / 'kev'
    if env.get('XDG_DATA_HOME'):
        return Path(env['XDG_DATA_HOME']) / 'PatchTrace' / 'kev'
    return Path.home() / '.local' / 'share' / 'PatchTrace' / 'kev'


# --- files --------------------------------------------------------------------------------------------------

def tmp_name(name: str) -> str:
    return f'{name}.{secrets.token_hex(6)}{TMP_SUFFIX}'


def _discard(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass                                                      # a leftover is removed by the next prune


def _publish(directory: Path, name: str, data: bytes, sleep: Callable[[float], None]) -> None:
    """Write ``data`` as ``directory/name`` atomically; retry a Windows sharing violation a few times."""
    temporary = directory / tmp_name(name)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with open(temporary, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(1, limits.REPLACE_ATTEMPTS + 1):
            try:
                os.replace(temporary, directory / name)
                return
            except PermissionError:
                if attempt == limits.REPLACE_ATTEMPTS:
                    raise KevError(STORAGE, 'a catalog file is locked by another program') from None
                sleep(limits.REPLACE_BACKOFF_MS * attempt / 1000)
    except OSError:
        raise KevError(STORAGE, 'the catalog folder cannot be written') from None
    finally:
        _discard(temporary)


def _read_small(path: Path, cap: int) -> bytes | None:
    """The bytes of a small file, None when it is absent."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read(cap + 1)
    except FileNotFoundError:
        return None
    except OSError:
        raise KevError(STORAGE, 'a catalog file cannot be read') from None
    if len(data) > cap:
        raise KevError(STORAGE, 'a catalog file is larger than expected')
    return data


def _read_snapshot(path: Path) -> bytes:
    try:
        with gzip.open(path, 'rb') as handle:
            data = handle.read(limits.MAX_CATALOG_BYTES + 1)      # a bomb is cut here, not inflated
    except (OSError, EOFError, zlib.error):
        raise KevError(STORAGE, 'a stored catalog is damaged or missing') from None
    if len(data) > limits.MAX_CATALOG_BYTES:
        raise KevError(STORAGE, 'a stored catalog is larger than the limit')
    return data


def _remove(path: Path) -> int | None:
    """Delete one file; its size, or None when it was already gone."""
    try:
        size = path.stat().st_size
        path.unlink()
    except FileNotFoundError:
        return None
    except OSError:
        raise KevError(STORAGE, 'a stored catalog cannot be deleted') from None
    return size


def _total_size(paths) -> int:
    """The bytes of these files; one that vanished meanwhile (a prune in another process) counts as nothing."""
    total = 0
    for path in paths:
        try:
            total += path.stat().st_size
        except OSError:
            pass
    return total


def _check_id(snapshot_id: object) -> str:
    if type(snapshot_id) is not str or not _ID.fullmatch(snapshot_id):
        raise KevError('PT-KEV-INPUT', 'a snapshot id is 64 lower-case hexadecimal digits')
    return snapshot_id


# --- the store ----------------------------------------------------------------------------------------------

class KevStore:
    def __init__(self, root: Path | str, *, sleep: Callable[[float], None] = time.sleep):
        self._root = Path(root)
        self._sleep = sleep

    @property
    def root(self) -> Path:
        return self._root

    def _snapshot_path(self, raw_sha256: str) -> Path:
        return self._root / SNAPSHOT_DIR / f'{raw_sha256}{SNAPSHOT_SUFFIX}'

    # -- reading ----------------------------------------------------------------------------------------------------
    def read_meta(self, snapshot_id: str) -> KevCatalogMeta:
        _check_id(snapshot_id)
        data = _read_small(self._root / META_DIR / f'{snapshot_id}.json', META_CAP)
        if data is None:
            raise KevError('PT-KEV-NOTFOUND', 'no stored catalog has this id')
        try:
            meta = KevCatalogMeta.model_validate_json(data)
        except ValueError:
            raise KevError(STORAGE, 'the description of a stored catalog is damaged') from None
        if meta.snapshot_id != snapshot_id:
            raise KevError(STORAGE, 'the description of a stored catalog belongs to another one')
        return meta

    def load(self, snapshot_id: str) -> KevCatalog:
        """One stored catalog, checked against its hash and re-parsed from the bytes CISA published."""
        meta = self.read_meta(snapshot_id)
        raw = _read_snapshot(self._snapshot_path(meta.raw_sha256))
        if hashlib.sha256(raw).hexdigest() != meta.raw_sha256:
            raise KevError(STORAGE, 'a stored catalog does not match its hash')
        catalog = parse_catalog(raw, source=meta.source, retrieved_at=meta.retrieved_at, source_url=meta.source_url,
                                final_url=meta.final_url, consent=meta.consent, file_name=meta.file_name)
        if catalog.meta != meta:
            raise KevError(STORAGE, 'a stored catalog does not match its description')
        return catalog

    def list_snapshots(self) -> tuple[KevCatalogMeta, ...]:
        """The readable descriptions whose snapshot file exists, newest release first."""
        try:
            names = sorted(os.listdir(self._root / META_DIR))
        except OSError:
            return ()
        found = []
        for name in names:
            if name.endswith('.json') and _ID.fullmatch(name[:-5]):
                try:
                    meta = self.read_meta(name[:-5])
                except KevError:
                    continue
                if self._snapshot_path(meta.raw_sha256).is_file():
                    found.append(meta)
        return tuple(sorted(found, key=lambda m: (m.date_released, m.retrieved_at, m.snapshot_id), reverse=True))

    def _read_pointer(self) -> tuple[KevCurrent | None, bool]:
        """The pointer and whether the file exists but is damaged."""
        try:
            data = _read_small(self._root / CURRENT_FILE, POINTER_CAP)
        except KevError:
            return None, True
        if data is None:
            return None, False
        try:
            return KevCurrent.model_validate_json(data), False
        except ValueError:
            return None, True

    def _try_load(self, snapshot_id: str) -> KevCatalog | None:
        try:
            return self.load(snapshot_id)
        except KevError:
            return None

    def load_current(self) -> Loaded | None:
        """The catalog the pointer names, else the newest valid snapshot with a note that says why."""
        pointer, damaged = self._read_pointer()
        notes, failed = [], set()
        if pointer is not None:
            catalog = self._try_load(pointer.snapshot_id)
            if catalog is not None and catalog.meta.raw_sha256 == pointer.raw_sha256:
                return Loaded(catalog, ())                    # the usual case reads two files and lists nothing
            if catalog is None:
                failed.add(pointer.snapshot_id)
            notes.append(NOTE_UNREADABLE)
        listed = [meta.snapshot_id for meta in self.list_snapshots()]
        if pointer is None:
            if damaged:
                notes.append(NOTE_DAMAGED_POINTER)
            elif listed:
                notes.append(NOTE_NO_POINTER)
        for snapshot_id in listed:
            catalog = None if snapshot_id in failed else self._try_load(snapshot_id)
            if catalog is not None:
                return Loaded(catalog, tuple(notes))
        return None

    def _current_meta(self) -> KevCatalogMeta | None:
        """The description of the catalog in use, without parsing it (what install compares a new one with)."""
        pointer, _ = self._read_pointer()
        ids = ([pointer.snapshot_id] if pointer else []) + [meta.snapshot_id for meta in self.list_snapshots()]
        for snapshot_id in ids:
            try:
                meta = self.read_meta(snapshot_id)
            except KevError:
                continue
            if self._snapshot_path(meta.raw_sha256).is_file():
                return meta
        return None

    def status(self) -> StoreStatus:
        loaded = self.load_current()
        files = [path for path in self._root.rglob('*') if path.is_file()] if self._root.is_dir() else []
        total = _total_size(files)
        stored = any(not path.name.endswith(TMP_SUFFIX) for path in files)     # a leftover temporary is not a catalog
        notes = loaded.notes if loaded is not None else ((NOTE_NONE_READABLE,) if stored else ())
        warning = None
        if total > limits.STORE_WARN_BYTES:
            warning = (f'The KEV catalog folder holds {total / limits.MIB:.1f} MiB. "kev prune --keep N --yes" '
                       'removes the oldest catalogs.')
        return StoreStatus(None if loaded is None else loaded.catalog.meta, notes, len(self.list_snapshots()), total,
                           warning)

    # -- writing ----------------------------------------------------------------------------------------------------
    def install(self, raw: bytes, catalog: KevCatalog, *, now: str, accept_shrink: bool = False) -> InstallResult:
        """Store a parsed catalog and, unless an older release, make it the one in use. ``now`` is the UTC time
        written into the pointer. A catalog with under 90 percent of the entries in use needs ``accept_shrink``."""
        meta = catalog.meta
        if hashlib.sha256(raw).hexdigest() != meta.raw_sha256 or len(raw) != meta.raw_size:
            raise KevError('PT-KEV-INPUT', 'the catalog does not describe these bytes')
        try:
            pointer = KevCurrent(snapshot_id=meta.snapshot_id, raw_sha256=meta.raw_sha256,
                                 date_released=meta.date_released, set_at=now)
        except ValidationError:
            raise KevError('PT-KEV-INPUT', 'now must be a UTC time like 2099-03-02T08:00:00Z') from None
        in_use, _ = self._read_pointer()
        if in_use is not None and in_use.snapshot_id == meta.snapshot_id:
            try:
                self.load(meta.snapshot_id)
                return InstallResult('unchanged', meta.snapshot_id, meta.snapshot_id)
            except KevError:
                pass                                             # stored but damaged: write it again
        current = self._current_meta()
        older = current is not None and meta.date_released < current.date_released
        if current is not None and not older and not accept_shrink and (
                meta.entry_count * 100 < current.entry_count * limits.SHRINK_KEEP_PERCENT):
            raise KevError('PT-KEV-SHRINK', f'the new catalog has {current.entry_count - meta.entry_count} fewer '
                                            'entries than the one in use')
        _publish(self._root / SNAPSHOT_DIR, f'{meta.raw_sha256}{SNAPSHOT_SUFFIX}',
                 gzip.compress(raw, compresslevel=6, mtime=0), self._sleep)
        _publish(self._root / META_DIR, f'{meta.snapshot_id}.json', _json(meta), self._sleep)
        if older:
            return InstallResult('kept-newer', meta.snapshot_id, current.snapshot_id)
        _publish(self._root, CURRENT_FILE, _json(pointer), self._sleep)
        return InstallResult('installed', meta.snapshot_id, meta.snapshot_id)

    def prune(self, keep: int, *, yes: bool = False) -> PruneResult:
        """The only deletion: stored catalogs beyond the ``keep`` newest (the one in use always stays), snapshot files
        nothing refers to and the temporary files a crash left behind."""
        if not yes:
            raise KevError('PT-KEV-INPUT', 'pruning deletes stored catalogs; confirm it with --yes')
        if type(keep) is not int or keep < 1:
            raise KevError('PT-KEV-INPUT', 'keep must be a whole number, at least 1')
        metas = self.list_snapshots()
        pointer, _ = self._read_pointer()
        kept = {meta.snapshot_id for meta in metas[:keep]} | ({pointer.snapshot_id} if pointer else set())
        kept_hashes = {meta.raw_sha256 for meta in metas if meta.snapshot_id in kept}
        removed, files, freed = [], 0, 0

        def delete(path: Path) -> None:
            nonlocal files, freed
            size = _remove(path)
            if size is not None:
                files, freed = files + 1, freed + size

        for meta in metas:
            if meta.snapshot_id not in kept:
                removed.append(meta.snapshot_id)
                delete(self._root / META_DIR / f'{meta.snapshot_id}.json')
        snapshots = self._root / SNAPSHOT_DIR
        if snapshots.is_dir():
            for path in sorted(snapshots.glob(f'*{SNAPSHOT_SUFFIX}')):
                stem = path.name[:-len(SNAPSHOT_SUFFIX)]
                if _ID.fullmatch(stem) and stem not in kept_hashes:
                    delete(path)
        for directory in (self._root, snapshots, self._root / META_DIR):
            if directory.is_dir():
                for path in sorted(directory.glob(f'*{TMP_SUFFIX}')):
                    delete(path)
        return PruneResult(tuple(removed), files, freed)


def _json(record) -> bytes:
    return record.model_dump_json(indent=2).encode('utf-8') + b'\n'
