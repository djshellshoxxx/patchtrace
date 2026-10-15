"""B4 content-addressed derived-stage and raw-output cache (SPEC-07 §9).

Correctness beats hit rate: an entry is served only after its manifest parses
strictly, names the requested stage/key, and the payload matches the recorded size
and SHA-256. Anything else is a miss (and is quarantined when we can lock it).
Admission failures from the filesystem return False; they must never fail an
otherwise valid analysis. Only invalid *arguments* raise PT-ENRICH-CONFIG.

Publication protocol (per key, under an O_EXCL lock):
  private staging dir ``v1/.staging-<uuid>`` on the same volume -> payload (fsync)
  -> manifest.json last (fsync) -> ``os.replace(staging, entry)``.
A crash at any point leaves at most an orphaned staging dir and/or lock, never a
visible entry; ``verify``/``prune`` reclaim orphans whose owner is provably dead
(or is this process but not an active operation of it).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import threading
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .contracts import CacheManifest, EnrichmentError
from .identity import domain_id

GIB = 1024 ** 3
MIB = 1024 ** 2
LAYOUT = 'v1'
RAW_STAGE = 'raw'
_STAGE_RE = re.compile(r'^[a-z][a-z0-9-]{0,31}$')
_KEY_RE = re.compile(r'^[0-9a-f]{64}$')
_MANIFEST_MAX = 1 * MIB
_RESERVED = {'quarantine'}

# In-process registries. A lock/staging/lease file owned by *our* pid but absent
# from these sets is an orphan of an interrupted operation in this process and may be
# reclaimed; one present here belongs to a live operation (possibly another thread).
_REGISTRY_LOCK = threading.Lock()
_HELD_LOCKS: set[str] = set()
_ACTIVE_STAGING: set[str] = set()
_HELD_LEASES: set[str] = set()
_HELD_LEASE_KEYS: Counter[str] = Counter()  # 'stage/key' -> active in-process leases
_HOST = socket.gethostname()


def _config_error(message: str) -> EnrichmentError:
    return EnrichmentError('PT-ENRICH-CONFIG', message)


@dataclass(frozen=True)
class CacheConfig:
    root: Path
    budget_bytes: int = 20 * GIB
    raw_max_bytes: int = 100 * MIB
    no_cache: bool = False
    refresh_stages: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self):
        if not isinstance(self.root, Path):
            raise _config_error('cache root must be a Path')
        for name in ('budget_bytes', 'raw_max_bytes'):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise _config_error(f'{name} must be a positive integer')
        if type(self.no_cache) is not bool:
            raise _config_error('no_cache must be a bool')
        if not isinstance(self.refresh_stages, frozenset) or not all(
                isinstance(s, str) and _STAGE_RE.match(s) for s in self.refresh_stages):
            raise _config_error('refresh_stages must be a frozenset of stage names')
        if self.no_cache and self.refresh_stages:
            raise _config_error('no_cache and refresh are mutually exclusive')


_VERSION_FIELDS = ('engine', 'ghidriff_revision', 'ghidra_version', 'pyghidra_version',
                   'python_version', 'java_version', 'adapter_version')


@dataclass(frozen=True)
class RuntimeFingerprint:
    """Everything that can change Ghidriff raw output for a fixed input pair.

    Options and symbol inputs are passed as caller-computed canonical digests/strings
    so absolute paths never enter the key.
    """
    engine: str
    ghidriff_revision: str
    ghidra_version: str
    pyghidra_version: str
    python_version: str
    java_version: str
    platform_arch: str
    loader_options: str
    analysis_options: str
    adapter_version: str
    symbol_policy: str
    symbol_input_digest: str

    def as_dict(self) -> dict[str, str]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def eligible(self) -> tuple[bool, str]:
        for name, value in self.as_dict().items():
            if not isinstance(value, str) or not value.strip():
                return False, f'{name} is empty'
        for name in _VERSION_FIELDS:
            if getattr(self, name).strip().lower() == 'unknown':
                return False, f'{name} is unverified'
        if self.symbol_policy.strip().lower() == 'online':
            # Online symbol servers can change answers over time without any local
            # input changing, so the output is not a function of the key.
            return False, 'online symbol policy'
        return True, 'eligible'

    def raw_key(self, older_sha256: str, newer_sha256: str) -> str:
        for value in (older_sha256, newer_sha256):
            if not isinstance(value, str) or not _KEY_RE.match(value):
                raise _config_error('artifact hashes must be lowercase SHA-256 hex')
        # Ordered sides: reversing the pair is a different diff and a different key.
        return domain_id('raw-cache', 1, {'older_sha256': older_sha256, 'newer_sha256': newer_sha256,
                                          'fingerprint': self.as_dict()})


def _is_link_or_junction(path: Path) -> bool:
    """Symlinks, and on Windows junctions/mount points, which is_symlink() misses."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if hasattr(path, 'is_junction') and path.is_junction():
        return True
    return bool(getattr(st, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))


def _pid_alive(pid: int) -> bool:
    """True unless the pid is *provably* dead; uncertainty counts as alive."""
    if type(pid) is not int or pid <= 0:
        return True
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        # use_last_error captures GetLastError immediately after each call; calling
        # kernel32.GetLastError() separately can observe a value clobbered by ctypes itself.
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() != 87  # ERROR_INVALID_PARAMETER: no such pid
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # EPERM: exists under another user
    return True


def _read_owner(path: Path) -> dict | None:
    try:
        with open(path, 'rb') as handle:
            data = json.loads(handle.read(4096))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or type(data.get('pid')) is not int:
        return None
    if not isinstance(data.get('host'), str) or not isinstance(data.get('nonce'), str):
        return None
    return data


def _owner_dead(owner: dict | None, registry: set[str]) -> bool:
    """Provably not in use. Never decided by age: a slow writer is not a dead one."""
    if owner is None or owner['host'] != _HOST:
        return False
    if owner['pid'] == os.getpid():
        with _REGISTRY_LOCK:
            return owner['nonce'] not in registry
    return not _pid_alive(owner['pid'])


def _new_owner() -> dict:
    return {'pid': os.getpid(), 'host': _HOST, 'nonce': uuid.uuid4().hex}


def _check_args(stage: str, key: str) -> None:
    if not isinstance(stage, str) or not _STAGE_RE.fullmatch(stage) or stage in _RESERVED:
        raise _config_error('invalid cache stage name')
    if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
        raise _config_error('cache key must be lowercase SHA-256 hex')


class _Unsafe(Exception):
    """A link/junction or non-directory where the layout expects a plain directory."""


class DerivedCache:
    def __init__(self, config: CacheConfig):
        if not isinstance(config, CacheConfig):
            raise _config_error('config must be a CacheConfig')
        self.config = config
        # No filesystem access here: no_cache must perform zero reads/writes.
        self._base = config.root / LAYOUT

    # ---- paths -------------------------------------------------------------
    def _safe_dir(self, path: Path, create: bool) -> bool:
        """Walk root..path refusing links; optionally create. False if absent."""
        rel = path.relative_to(self.config.root)
        current = self.config.root
        for part in (None, *rel.parts):
            if part is not None:
                current = current / part
            if _is_link_or_junction(current):
                raise _Unsafe(str(current))
            try:
                st = os.stat(current)
            except FileNotFoundError:
                if not create:
                    return False
                with contextlib.suppress(FileExistsError):
                    os.mkdir(current)
                if _is_link_or_junction(current):
                    raise _Unsafe(str(current)) from None
                continue
            if not stat.S_ISDIR(st.st_mode):
                raise _Unsafe(str(current))
        return True

    def _shard(self, stage: str, key: str) -> Path:
        return self._base / stage / key[:2]

    def _entry(self, stage: str, key: str) -> Path:
        return self._shard(stage, key) / key

    def _lock_path(self, stage: str, key: str) -> Path:
        return self._shard(stage, key) / f'{key}.lock'

    # ---- locking -----------------------------------------------------------
    def _try_lock(self, stage: str, key: str) -> str | None:
        """O_EXCL per-key lock; returns our nonce or None if held by a live owner."""
        path = self._lock_path(stage, key)
        for _attempt in range(2):
            owner = _new_owner()
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
            except FileExistsError:
                if not self._recover(path, _HELD_LOCKS):
                    return None
                continue
            with _REGISTRY_LOCK:
                _HELD_LOCKS.add(owner['nonce'])
            try:
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(json.dumps(owner).encode())
            except OSError:
                self._unlock(stage, key, owner['nonce'])
                raise
            return owner['nonce']
        return None

    def _recover(self, path: Path, registry: set[str]) -> bool:
        owner = _read_owner(path)
        if not _owner_dead(owner, registry):
            return False
        # Rename-then-check so two recoverers cannot both delete and re-create.
        tomb = path.with_name(f'{path.name}.dead-{uuid.uuid4().hex}')
        try:
            os.rename(path, tomb)
        except OSError:
            return False
        again = _read_owner(tomb)
        with contextlib.suppress(OSError):
            os.unlink(tomb)
        return again is not None and again['nonce'] == owner['nonce']

    def _unlock(self, stage: str, key: str, nonce: str) -> None:
        path = self._lock_path(stage, key)
        owner = _read_owner(path)
        if owner is not None and owner['nonce'] == nonce:
            with contextlib.suppress(OSError):
                os.unlink(path)
        with _REGISTRY_LOCK:
            _HELD_LOCKS.discard(nonce)

    # ---- verification ------------------------------------------------------
    def _load(self, stage: str, key: str) -> tuple[CacheManifest, bytes] | None:
        """Verified (manifest, payload) or None. Raises _Corrupt for bad entries."""
        entry = self._entry(stage, key)
        if not self._safe_dir(entry, create=False):
            return None
        manifest_path, payload_path = entry / 'manifest.json', entry / 'payload'
        for p in (manifest_path, payload_path):
            if _is_link_or_junction(p):
                raise _Corrupt('link in entry')
        try:
            with open(manifest_path, 'rb') as handle:
                raw = handle.read(_MANIFEST_MAX + 1)
        except FileNotFoundError:
            # Directory without manifest is never complete (manifest is the marker).
            raise _Corrupt('missing manifest') from None
        if len(raw) > _MANIFEST_MAX:
            raise _Corrupt('manifest too large')
        try:
            manifest = CacheManifest.model_validate_json(raw)
        except ValidationError:
            raise _Corrupt('invalid manifest') from None
        if manifest.key != key or manifest.stage != stage:
            raise _Corrupt('manifest names another entry')
        if stage == RAW_STAGE and manifest.size > self.config.raw_max_bytes:
            raise _Corrupt('raw entry exceeds bound')
        if manifest.size > self.config.budget_bytes:  # put() never admits more, so this is damage
            raise _Corrupt('entry exceeds budget')
        try:
            with open(payload_path, 'rb') as handle:
                payload = handle.read(manifest.size + 1)
        except FileNotFoundError:
            raise _Corrupt('missing payload') from None
        # Hash exactly the bytes we return, so there is no verify/use gap.
        if len(payload) != manifest.size or hashlib.sha256(payload).hexdigest() != manifest.sha256:
            raise _Corrupt('payload mismatch')
        return manifest, payload

    def _quarantine(self, stage: str, key: str) -> bool:
        nonce = self._try_lock(stage, key)
        if nonce is None:
            return False
        try:
            # Re-verify under the lock: a writer may have replaced the corrupt entry with a
            # valid one between our failed read and acquiring the lock.
            try:
                if self._load(stage, key) is not None:
                    return False
            except _Corrupt:
                pass
            qdir = self._base / 'quarantine'
            self._safe_dir(qdir, create=True)
            os.replace(self._entry(stage, key), qdir / f'{stage}-{key}-{uuid.uuid4().hex}')
            return True
        except (OSError, _Unsafe):
            return False
        finally:
            self._unlock(stage, key, nonce)

    # ---- public API --------------------------------------------------------
    def get(self, stage: str, key: str) -> bytes | None:
        _check_args(stage, key)
        if self.config.no_cache or stage in self.config.refresh_stages:
            return None
        try:
            loaded = self._load(stage, key)
        except _Corrupt:
            self._quarantine(stage, key)
            return None
        except (OSError, _Unsafe):
            return None
        if loaded is None:
            return None
        with contextlib.suppress(OSError):
            # LRU clock: mtime of manifest.json (atime is unreliable under noatime).
            os.utime(self._entry(stage, key) / 'manifest.json')
        return loaded[1]

    def put(self, stage: str, key: str, payload: bytes, inputs: dict) -> bool:
        _check_args(stage, key)
        if not isinstance(payload, bytes):
            raise _config_error('payload must be bytes')
        if not isinstance(inputs, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in inputs.items()):
            raise _config_error('inputs must map str to str')
        if self.config.no_cache:
            return False
        if stage == RAW_STAGE and len(payload) > self.config.raw_max_bytes:
            return False
        try:
            return self._admit(stage, key, payload, inputs)
        except (OSError, _Unsafe):
            return False

    def _admit(self, stage: str, key: str, payload: bytes, inputs: dict) -> bool:
        digest = hashlib.sha256(payload).hexdigest()
        manifest = CacheManifest(key=key, stage=stage, size=len(payload), sha256=digest,
                                 inputs=dict(inputs), created=datetime.now(UTC).isoformat())
        manifest_bytes = manifest.model_dump_json().encode()
        need = len(payload) + len(manifest_bytes)
        if need > self.config.budget_bytes:
            return False
        self._safe_dir(self._shard(stage, key), create=True)
        nonce = self._try_lock(stage, key)
        if nonce is None:
            return False
        try:
            try:
                existing = self._load(stage, key)
            except _Corrupt:
                existing = None
                qdir = self._base / 'quarantine'
                self._safe_dir(qdir, create=True)
                os.replace(self._entry(stage, key), qdir / f'{stage}-{key}-{uuid.uuid4().hex}')
            if existing is not None:
                # Another writer won; equal content means the caller's data is cached.
                return existing[0].sha256 == digest
            if self._usage() + need > self.config.budget_bytes:
                self.prune(self.config.budget_bytes - need)
                if self._usage() + need > self.config.budget_bytes:
                    return False
            return self._stage_and_publish(stage, key, payload, manifest_bytes)
        finally:
            self._unlock(stage, key, nonce)

    def _stage_and_publish(self, stage: str, key: str, payload: bytes, manifest_bytes: bytes) -> bool:
        owner = _new_owner()
        staging = self._base / f'.staging-{uuid.uuid4().hex}'
        with _REGISTRY_LOCK:
            _ACTIVE_STAGING.add(owner['nonce'])
        published = False
        try:
            os.mkdir(staging, 0o700)
            _write_file(staging / 'owner.json', json.dumps(owner).encode())
            _write_payload(staging / 'payload', payload)
            _write_manifest(staging / 'manifest.json', manifest_bytes)
            try:
                _publish(staging, self._entry(stage, key))
            except OSError:
                # Windows AV/indexers hold handles and make rename fail; that is an
                # admission failure, not an analysis failure.
                return False
            published = True
            with contextlib.suppress(OSError):
                os.unlink(self._entry(stage, key) / 'owner.json')
            return True
        finally:
            if not published:
                _discard_staging(staging)
            with _REGISTRY_LOCK:
                _ACTIVE_STAGING.discard(owner['nonce'])

    @contextlib.contextmanager
    def lease(self, stage: str, key: str) -> Iterator[None]:
        """Protect an entry from eviction while a reader uses it (cross-process)."""
        _check_args(stage, key)
        if self.config.no_cache:
            yield
            return
        owner = _new_owner()
        path = self._shard(stage, key) / f'{key}.lease-{owner["nonce"]}'
        with _REGISTRY_LOCK:
            _HELD_LEASES.add(owner['nonce'])
            _HELD_LEASE_KEYS[f'{stage}/{key}'] += 1
        created = False
        try:
            try:
                self._safe_dir(path.parent, create=True)
                _write_file(path, json.dumps(owner).encode())
                created = True
            except (OSError, _Unsafe):
                pass  # in-process registry still protects against our own prune
            yield
        finally:
            if created:
                with contextlib.suppress(OSError):
                    os.unlink(path)
            with _REGISTRY_LOCK:
                _HELD_LEASES.discard(owner['nonce'])
                _HELD_LEASE_KEYS[f'{stage}/{key}'] -= 1
                if _HELD_LEASE_KEYS[f'{stage}/{key}'] <= 0:
                    del _HELD_LEASE_KEYS[f'{stage}/{key}']

    def put_raw(self, fp: RuntimeFingerprint, older: str, newer: str, payload: bytes) -> bool:
        if not fp.eligible()[0]:
            return False
        key = fp.raw_key(older, newer)
        inputs = {'older_sha256': older, 'newer_sha256': newer, **fp.as_dict()}
        return self.put(RAW_STAGE, key, payload, inputs)

    def get_raw(self, fp: RuntimeFingerprint, older: str, newer: str) -> bytes | None:
        if not fp.eligible()[0]:
            return None
        return self.get(RAW_STAGE, fp.raw_key(older, newer))

    # ---- maintenance -------------------------------------------------------
    def _entries(self) -> Iterator[tuple[str, str, Path]]:
        if not self._safe_dir(self._base, create=False):
            return
        for stage_dir in sorted(self._base.iterdir()):
            name = stage_dir.name
            if not _STAGE_RE.match(name) or name in _RESERVED or _is_link_or_junction(stage_dir):
                continue
            for shard in sorted(stage_dir.iterdir()):
                if _is_link_or_junction(shard) or not shard.is_dir():
                    continue
                for entry in sorted(shard.iterdir()):
                    if (_KEY_RE.match(entry.name) and entry.name[:2] == shard.name
                            and not _is_link_or_junction(entry) and entry.is_dir()):
                        yield name, entry.name, entry

    def _entry_bytes(self, entry: Path) -> int:
        total = 0
        for name in ('payload', 'manifest.json'):
            with contextlib.suppress(OSError):
                total += os.lstat(entry / name).st_size
        return total

    def _quarantine_items(self) -> list[tuple[int, Path, int]]:
        """(mtime, path, bytes) of quarantined entries; they count toward the budget and go first."""
        qdir = self._base / 'quarantine'
        try:
            if not self._safe_dir(qdir, create=False):
                return []
            return [(os.lstat(p).st_mtime_ns, p, self._entry_bytes(p))
                    for p in qdir.iterdir() if not _is_link_or_junction(p)]
        except (OSError, _Unsafe):
            return []

    def _usage(self) -> int:
        return (sum(self._entry_bytes(e) for _s, _k, e in self._entries())
                + sum(size for _m, _p, size in self._quarantine_items()))

    def _leased(self, stage: str, key: str) -> bool:
        shard = self._shard(stage, key)
        with _REGISTRY_LOCK:
            # A lease of this process whose file could not be written is still a lease.
            leased = f'{stage}/{key}' in _HELD_LEASE_KEYS
        for path in shard.glob(f'{key}.lease-*'):
            if _is_link_or_junction(path):
                continue
            if _owner_dead(_read_owner(path), _HELD_LEASES):
                with contextlib.suppress(OSError):
                    os.unlink(path)
            else:
                leased = True
        return leased

    def _clean_orphans(self) -> dict:
        removed = {'staging_removed': 0, 'locks_recovered': 0}
        if not self._safe_dir(self._base, create=False):
            return removed
        for path in self._base.iterdir():
            if path.name.startswith('.staging-') and not _is_link_or_junction(path) and path.is_dir():
                owner = _read_owner(path / 'owner.json')
                # A staging dir with no readable owner was interrupted before the owner
                # file landed; only reclaim it if it cannot belong to a live writer,
                # which we cannot prove, so leave it.
                if _owner_dead(owner, _ACTIVE_STAGING):
                    _discard_staging(path)
                    removed['staging_removed'] += 1
        for stage_dir in self._base.iterdir():
            if not _STAGE_RE.match(stage_dir.name) or _is_link_or_junction(stage_dir) or not stage_dir.is_dir():
                continue
            for shard in stage_dir.iterdir():
                if _is_link_or_junction(shard) or not shard.is_dir():
                    continue
                for lock in shard.glob('*.lock'):
                    if not _is_link_or_junction(lock) and self._recover(lock, _HELD_LOCKS):
                        removed['locks_recovered'] += 1
        return removed

    def _quarantined(self) -> int:
        qdir = self._base / 'quarantine'
        try:
            if not self._safe_dir(qdir, create=False):
                return 0
            return sum(1 for _ in qdir.iterdir())
        except (OSError, _Unsafe):
            return 0

    def status(self) -> dict:
        result = {'enabled': not self.config.no_cache, 'root': str(self.config.root),
                  'budget_bytes': self.config.budget_bytes, 'entries': 0, 'bytes': 0,
                  'by_stage': {}, 'quarantined': 0}
        if self.config.no_cache:
            return result
        try:
            for stage, _key, entry in self._entries():
                size = self._entry_bytes(entry)
                result['entries'] += 1
                result['bytes'] += size
                bucket = result['by_stage'].setdefault(stage, {'entries': 0, 'bytes': 0})
                bucket['entries'] += 1
                bucket['bytes'] += size
            result['quarantined'] = self._quarantined()
        except (OSError, _Unsafe) as exc:
            result['error'] = type(exc).__name__
        return result

    def verify(self) -> dict:
        result = {'ok': 0, 'corrupt': 0, 'quarantined': 0, 'staging_removed': 0, 'locks_recovered': 0}
        if self.config.no_cache:
            return result
        try:
            result.update(self._clean_orphans())
            for stage, key, _entry in list(self._entries()):
                try:
                    if self._load(stage, key) is not None:
                        result['ok'] += 1
                except _Corrupt:
                    result['corrupt'] += 1
                    self._quarantine(stage, key)
            result['quarantined'] = self._quarantined()
        except (OSError, _Unsafe) as exc:
            result['error'] = type(exc).__name__
        return result

    def prune(self, target_bytes: int | None = None) -> dict:
        target = self.config.budget_bytes if target_bytes is None else target_bytes
        if type(target) is not int or target < 0:
            raise _config_error('target_bytes must be a non-negative integer')
        result = {'removed': 0, 'freed_bytes': 0, 'skipped_leased': 0, 'skipped_locked': 0,
                  'bytes': 0, 'staging_removed': 0, 'locks_recovered': 0, 'quarantine_removed': 0}
        if self.config.no_cache:
            return result
        try:
            result.update(self._clean_orphans())
            candidates = []
            for stage, key, entry in self._entries():
                try:
                    clock = os.lstat(entry / 'manifest.json').st_mtime_ns
                except OSError:
                    clock = 0  # incomplete entries are the first to go
                candidates.append((clock, stage, key, entry, self._entry_bytes(entry)))
            quarantined = self._quarantine_items()
            total = sum(c[4] for c in candidates) + sum(size for _m, _p, size in quarantined)
            for _mtime, path, size in sorted(quarantined, key=lambda q: q[0]):
                if total <= target:
                    break
                _discard_staging(path)
                if not path.exists():
                    total -= size
                    result['quarantine_removed'] += 1
            for _clock, stage, key, entry, size in sorted(candidates):
                if total <= target:
                    break
                if self._leased(stage, key):
                    result['skipped_leased'] += 1
                    continue
                nonce = self._try_lock(stage, key)
                if nonce is None:
                    result['skipped_locked'] += 1
                    continue
                try:
                    if self._leased(stage, key):
                        result['skipped_leased'] += 1
                        continue
                    # Rename out of the layout first so a half-deleted entry is never visible.
                    trash = self._base / f'.staging-{uuid.uuid4().hex}'
                    os.replace(entry, trash)
                    # Claimed by a dead-on-exit owner record so a partially failed discard is
                    # reclaimed by a later verify/prune (staging dirs without one are kept).
                    with contextlib.suppress(OSError):
                        _write_file(trash / 'owner.json', json.dumps(_new_owner()).encode())
                    _discard_staging(trash)
                    total -= size
                    result['removed'] += 1
                    result['freed_bytes'] += size
                finally:
                    self._unlock(stage, key, nonce)
            result['bytes'] = total
        except (OSError, _Unsafe) as exc:
            result['error'] = type(exc).__name__
        return result


class _Corrupt(Exception):
    pass


def _write_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


# Separate seams so tests can simulate a crash at each promotion point.
def _write_payload(path: Path, data: bytes) -> None:
    _write_file(path, data)


def _write_manifest(path: Path, data: bytes) -> None:
    _write_file(path, data)


def _publish(staging: Path, entry: Path) -> None:
    os.replace(staging, entry)


def _discard_staging(path: Path) -> None:
    if _is_link_or_junction(path):
        with contextlib.suppress(OSError):
            os.unlink(path)
        return
    # rmtree does not follow links inside the tree (3.12 also handles junctions).
    shutil.rmtree(path, ignore_errors=True)


__all__ = ['CacheConfig', 'DerivedCache', 'RuntimeFingerprint', 'RAW_STAGE']
