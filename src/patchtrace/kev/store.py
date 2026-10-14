"""On-disk KEV snapshot store (KEV-integration-plan section 7). No Qt, network or sqlite; outside the project and git.

Layout: ``snapshots/<raw_sha256>.json.gz`` (the decompressed bytes hash to the name), ``meta/<snapshot_id>.json`` and
``current.json``. An install writes snapshot, meta, then the pointer, each through a temporary file, fsync and
``os.replace`` (retried for Windows sharing violations), so a crash leaves the previous catalog current. Reads never
trust the pointer: the raw bytes are re-hashed and re-parsed, and damage falls back to the newest valid snapshot with
a note. The only deletion is ``prune``, which needs explicit confirmation.
"""
from __future__ import annotations

import gzip
import json
import os
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from . import limits
from .contracts import KevCatalog, KevCatalogMeta, KevError
from .parse import parse_catalog

WARN_BYTES = 256 * 1024 * 1024
REPLACE_ATTEMPTS = 3
REPLACE_WAIT_S = 0.05


def default_kev_dir(env: Mapping[str, str] | None = None, *, home: Path | None = None) -> Path:
    """``%LOCALAPPDATA%\\PatchTrace\\kev``, else ``$XDG_DATA_HOME/PatchTrace/kev``, else ``~/.local/share/...``."""
    env = os.environ if env is None else env
    if env.get('LOCALAPPDATA'):
        return Path(env['LOCALAPPDATA']) / 'PatchTrace' / 'kev'
    if env.get('XDG_DATA_HOME'):
        return Path(env['XDG_DATA_HOME']) / 'PatchTrace' / 'kev'
    return (home or Path.home()) / '.local' / 'share' / 'PatchTrace' / 'kev'


@dataclass(frozen=True)
class Installed:
    current_changed: bool
    note: str | None = None


@dataclass(frozen=True)
class Loaded:
    catalog: KevCatalog
    note: str | None = None


def _storage(message: str) -> KevError:
    return KevError('PT-KEV-STORAGE', message)


def _read_snapshot(path: Path) -> bytes:
    """Decompress with a hard cap, so a planted gzip bomb cannot exhaust memory."""
    with gzip.open(path, 'rb') as stream:
        raw = stream.read(limits.MAX_BYTES + 1)
    if len(raw) > limits.MAX_BYTES:
        raise ValueError('snapshot exceeds the size cap')
    return raw


class KevStore:
    def __init__(self, root: Path, *, replace: Callable[[Path, Path], None] = os.replace,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.root = Path(root)
        self._replace, self._sleep = replace, sleep

    # -- writing ------------------------------------------------------------------------
    def install(self, catalog: KevCatalog, raw: bytes, set_at: str) -> Installed:
        """Store ``raw`` and make it current unless the current catalog is newer (or the same snapshot)."""
        meta = catalog.meta
        current = self._pointer()
        if current is not None:
            if current['snapshot_id'] == meta.snapshot_id:
                return Installed(False, 'This catalog is already the one in use.')
            if current['date_released'] > meta.date_released:
                return Installed(False, f'The catalog {meta.catalog_version} is older than the one in use; '
                                        'the newer one was kept.')
        self._write(self.root / 'snapshots' / f'{meta.raw_sha256}.json.gz', gzip.compress(raw, mtime=0))
        self._write(self.root / 'meta' / f'{meta.snapshot_id}.json', meta.model_dump_json().encode('utf-8'))
        pointer = {'snapshot_id': meta.snapshot_id, 'raw_sha256': meta.raw_sha256,
                   'date_released': meta.date_released, 'set_at': set_at}
        self._write(self.root / 'current.json', json.dumps(pointer, sort_keys=True).encode('utf-8'))
        return Installed(True)

    def _write(self, target: Path, data: bytes) -> None:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix='.partial-', dir=target.parent)
        except OSError:
            raise _storage('the catalog folder cannot be written') from None
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            self._replace_retrying(Path(name), target)
        except OSError:
            raise _storage('the catalog folder cannot be written') from None
        finally:
            Path(name).unlink(missing_ok=True)

    def _replace_retrying(self, source: Path, target: Path) -> None:
        for attempt in range(1, REPLACE_ATTEMPTS + 1):
            try:
                self._replace(source, target)
                return
            except PermissionError:  # a Windows sharing violation: a scanner or indexer holds the file briefly
                if attempt == REPLACE_ATTEMPTS:
                    raise
                self._sleep(REPLACE_WAIT_S * attempt)

    # -- reading ------------------------------------------------------------------------
    def _pointer(self) -> dict | None:
        try:
            data = json.loads((self.root / 'current.json').read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return None
        keys = ('snapshot_id', 'raw_sha256', 'date_released', 'set_at')
        return data if isinstance(data, dict) and all(isinstance(data.get(k), str) for k in keys) else None

    def list_snapshots(self) -> list[KevCatalogMeta]:
        """Readable metadata, newest release first (ties by retrieval time, then id)."""
        metas = []
        for path in sorted((self.root / 'meta').glob('*.json')):
            try:
                metas.append(KevCatalogMeta.model_validate_json(path.read_bytes()))
            except (OSError, ValidationError):
                continue
        return sorted(metas, key=lambda m: (m.date_released, m.retrieved_at, m.snapshot_id), reverse=True)

    def _catalog(self, meta: KevCatalogMeta) -> KevCatalog:
        raw = _read_snapshot(self.root / 'snapshots' / f'{meta.raw_sha256}.json.gz')
        catalog = parse_catalog(raw, source=meta.source, retrieved_at=meta.retrieved_at, source_url=meta.source_url,
                                final_url=meta.final_url, consent=meta.consent, file_name=meta.file_name)
        if catalog.meta != meta:
            raise ValueError('stored metadata differs from the stored file')
        return catalog

    def load(self, snapshot_id: str) -> KevCatalog:
        for meta in self.list_snapshots():
            if meta.snapshot_id == snapshot_id:
                try:
                    return self._catalog(meta)
                except (OSError, ValueError, EOFError, KevError):
                    raise _storage('the stored catalog is damaged') from None
        raise KevError('PT-KEV-NOTFOUND', 'no stored catalog has that snapshot ID')

    def load_current(self) -> Loaded | None:
        """The catalog the pointer names, else the newest valid snapshot (with a note), else None."""
        snapshots = self.list_snapshots()
        pointer = self._pointer()
        wanted = pointer['snapshot_id'] if pointer else None
        for meta in snapshots:
            if wanted is not None and meta.snapshot_id != wanted:
                continue
            try:
                catalog = self._catalog(meta)
            except (OSError, ValueError, EOFError, KevError):
                continue
            return Loaded(catalog, None if wanted is not None else self._fallback_note(meta, 'the pointer is missing'))
        for meta in snapshots:
            try:
                catalog = self._catalog(meta)
            except (OSError, ValueError, EOFError, KevError):
                continue
            return Loaded(catalog, self._fallback_note(meta, 'the catalog in use was damaged'))
        return None

    @staticmethod
    def _fallback_note(meta: KevCatalogMeta, why: str) -> str:
        return f'Using the newest readable catalog {meta.catalog_version} ({meta.date_released[:10]}): {why}.'

    def previous(self) -> KevCatalog | None:
        """The readable snapshot just before the current one, for ``kev diff``."""
        current = self.load_current()
        if current is None:
            return None
        for meta in self.list_snapshots():
            if meta.snapshot_id == current.catalog.meta.snapshot_id:
                continue
            try:
                return self._catalog(meta)
            except (OSError, ValueError, EOFError, KevError):
                continue
        return None

    # -- housekeeping -------------------------------------------------------------------
    def size_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.root.rglob('*') if p.is_file())

    def size_warning(self) -> str | None:
        if self.size_bytes() > WARN_BYTES:
            return 'The KEV folder holds more than 256 MiB. Run kev prune --keep N --yes to remove old catalogs.'
        return None

    def prune(self, keep: int, *, confirmed: bool) -> list[str]:
        """Delete all but the ``keep`` newest snapshots (never the current one). Returns the removed snapshot IDs."""
        if not confirmed:
            raise KevError('PT-KEV-INPUT', 'prune deletes stored catalogs; pass --yes to confirm')
        if keep < 1:
            raise KevError('PT-KEV-INPUT', 'keep at least one catalog')
        pointer = self._pointer()
        removed = []
        for meta in self.list_snapshots()[keep:]:
            if pointer is not None and meta.snapshot_id == pointer['snapshot_id']:
                continue
            try:
                (self.root / 'snapshots' / f'{meta.raw_sha256}.json.gz').unlink(missing_ok=True)
                (self.root / 'meta' / f'{meta.snapshot_id}.json').unlink(missing_ok=True)
            except OSError:
                raise _storage('the catalog folder cannot be written') from None
            removed.append(meta.snapshot_id)
        return removed
