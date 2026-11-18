"""Fetch before/after Windows binary pairs for accuracy cases (Winbindex metadata + Microsoft symbol server).

Pure functions (ref parsing, entry selection, URL building, manifest) are separate from network I/O; the fetcher is
injected so tests run offline. Never executes a fetched binary. Output is a pair manifest (`rq-pair-manifest/1`).
Exit codes: 0 ok (at least one case found), 1 every requested case missing, 2 blocked/usage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from tools.research_qualification.pathguard import PathGuardError, confine

IN_SCHEMA = 'rq-case-manifest/1'
OUT_SCHEMA = 'rq-pair-manifest/1'
INDEX_URL = 'https://winbindex.m417z.com/data/by_filename_compressed/{name}.json.gz'
SYMBOL_URL = 'https://msdl.microsoft.com/download/symbols/{name}/{stamp}/{name}'
ALLOWED_HOSTS = frozenset({'winbindex.m417z.com', 'msdl.microsoft.com'})
# msdl answers 302 to a signed Azure blob URL (observed live). Only redirect hops may use this suffix.
REDIRECT_HOST_SUFFIXES = ('.blob.core.windows.net',)
MAX_BINARY_BYTES = 200 * 1024 * 1024
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_INDEX_JSON_BYTES = 512 * 1024 * 1024
MAX_REDIRECTS = 3
TIMEOUT = 60
MACHINES = {'amd64': 0x8664, 'x86': 0x14C, 'arm64': 0xAA64}
_SAFE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
_VER = re.compile(r'\b(\d+\.\d+\.\d+\.\d+)\b')
_KB = re.compile(r'\b(KB\d{6,8})\b', re.I)
_MONTH = re.compile(r'\b(\d{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b')
_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']


class WinpairsError(RuntimeError):
    """A blocked or unsafe request (bad URL, oversize, bad manifest)."""


class PublicationBlocked(WinpairsError):
    """The platform cannot preserve open-file ownership for this publication."""


@dataclass
class Response:
    status: int
    body: bytes = b''
    location: str = ''


class Fetcher(Protocol):
    def __call__(self, url: str, max_bytes: int, timeout: float) -> Response: ...


# ---------------------------------------------------------------- pure functions
def check_url(url: str, redirect: bool = False) -> str:
    p = urllib.parse.urlsplit(url)
    host = (p.hostname or '').lower()
    ok = host in ALLOWED_HOSTS or (redirect and any(host.endswith(s) for s in REDIRECT_HOST_SUFFIXES))
    if p.scheme != 'https' or not ok or p.username or p.password or (p.port not in (None, 443)):
        raise WinpairsError(f'blocked URL (https and allowlisted host only): {p.scheme}://{host}')
    return url


def safe_name(name: str, what: str = 'name') -> str:
    if not _SAFE.match(name or ''):
        raise WinpairsError(f'unsafe {what}: {name!r}')
    return name


def index_url(name: str) -> str:
    return INDEX_URL.format(name=safe_name(name, 'file name').lower())


def symbol_url(name: str, timestamp: int, virtual_size: int) -> str:
    """`<FILE>/<TIMESTAMP %08X><SIZEOFIMAGE %x>/<FILE>`; the index key is the lower-cased file name as published."""
    safe_name(name, 'file name')
    if timestamp < 0 or virtual_size <= 0:
        raise WinpairsError('timestamp/virtualSize out of range')
    return SYMBOL_URL.format(name=name, stamp=f'{timestamp:08X}{virtual_size:x}')


def parse_ref(side: dict[str, Any]) -> dict[str, Any]:
    """Case side -> query. Explicit keys win (file, version, kb, sha256, month, machine); else mine the free-text ref."""
    ref = str(side.get('ref', ''))
    name = side.get('file') or (ref.split(',')[0].split()[0] if ref.strip() else '')
    q: dict[str, Any] = {'file': name}
    v = side.get('version') or (_VER.search(ref) or [None, None])[1]
    kb = side.get('kb') or (_KB.search(ref) or [None, None])[1]
    m = _MONTH.search(ref)
    month = side.get('month') or (f'{m[1]}-{_MONTHS.index(m[2]) + 1:02d}' if m else None)
    q.update(version=v, kb=kb.upper() if kb else None, sha256=(side.get('sha256') or '').lower() or None,
             month=month, machine=side.get('machine', 'amd64'))
    if q['machine'] not in MACHINES:
        raise WinpairsError(f'unknown machine {q["machine"]!r}')
    return q


def _vkey(v: str) -> tuple[int, ...]:
    m = _VER.search(v) if isinstance(v, str) else None
    return tuple(int(x) for x in m[1].split('.')) if m else ()


def _matches(entry: dict[str, Any], q: dict[str, Any]) -> bool:
    fi = entry.get('fileInfo') or {}
    if not isinstance(fi, dict):
        return False
    if not isinstance(fi.get('sha256'), str) or not _HEX64.fullmatch(fi['sha256']):
        return False  # missing identity can never become a verified acquisition
    if (type(fi.get('timestamp')) is not int or not 0 <= fi['timestamp'] <= 0xffffffff or
            type(fi.get('virtualSize')) is not int or not 0 < fi['virtualSize'] <= 0xffffffff):
        return False  # symbol-server key needs both
    if fi.get('size') is not None and (type(fi['size']) is not int or not 0 <= fi['size'] <= MAX_BINARY_BYTES):
        return False
    if fi.get('machineType') != MACHINES[q['machine']]:
        return False
    if q['sha256'] and fi.get('sha256', '').lower() != q['sha256']:
        return False
    if q['version'] and (not _vkey(q['version']) or _vkey(fi.get('version', '')) != _vkey(q['version'])):
        return False
    updates = [u for kbs in (entry.get('windowsVersions') or {}).values() for u in kbs.items()]
    if q['kb'] and not any(k.upper() == q['kb'] for k, _ in updates):
        return False
    if q['month'] and not any(str((u.get('updateInfo') or {}).get('releaseDate', '')).startswith(q['month'])
                              for _, u in updates):
        return False
    return True


def select_entry(index: dict[str, Any], q: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return only an unambiguous byte identity. KB/version/month constraints are not unique hash pins."""
    cands = [e['fileInfo'] for e in index.values() if isinstance(e, dict) and _matches(e, q)]
    if not cands:
        return None, 'no matching Winbindex entry with timestamp and virtualSize'
    if len({c['sha256'].lower() for c in cands}) > 1:
        return None, f'ambiguous: {len(cands)} candidates; pin an independently verified sha256 in the case'
    identities = {(c['timestamp'], c['virtualSize'], c.get('size'), _vkey(c.get('version')), c['machineType'])
                  for c in cands}
    if len(identities) > 1:
        return None, 'ambiguous: one sha256 has conflicting identity metadata'
    # Identical acquisition identities may recur under multiple index keys. Keep
    # presentation deterministic without choosing between different bytes.
    best = min(cands, key=lambda c: str(c.get('version', '')))
    return best, f'{len(cands)} candidate(s), one sha256 identity'


def side_record(name: str, fi: dict[str, Any] | None, reason: str) -> dict[str, Any]:
    if fi is None:
        return {'file': name, 'status': 'missing', 'reason': reason}
    return {'file': name, 'status': 'found', 'reason': reason, 'version': fi.get('version'),
            'timestamp': fi['timestamp'], 'virtual_size': fi['virtualSize'], 'expected_sha256': fi.get('sha256'),
            'expected_size': fi.get('size'), 'source_url': symbol_url(name, fi['timestamp'], fi['virtualSize'])}


def build_manifest(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {'schema': OUT_SCHEMA, 'cases': cases}


def case_status(older: dict[str, Any], newer: dict[str, Any]) -> str:
    return 'found' if older.get('status') == 'found' and newer.get('status') == 'found' else 'missing'


# ---------------------------------------------------------------- network I/O
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:
        return None


def urllib_fetcher(url: str, max_bytes: int, timeout: float) -> Response:
    """One hop, no auto-redirect, streamed with a hard byte cap. Callers allowlist-check every URL."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={'User-Agent': 'patchtrace-winpairs/1'})
    try:
        with opener.open(req, timeout=timeout) as r:
            return Response(r.status, _read_capped(r, max_bytes))
    except urllib.error.HTTPError as e:
        return Response(e.code, b'', e.headers.get('Location', '') or '')
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise WinpairsError(f'network error: {type(e).__name__}') from None


def _read_capped(r: Any, max_bytes: int) -> bytes:
    out, total = [], 0
    while chunk := r.read(1 << 20):
        total += len(chunk)
        if total > max_bytes:
            raise WinpairsError(f'response exceeds {max_bytes} byte cap')
        out.append(chunk)
    return b''.join(out)


def fetch_checked(fetch: Fetcher, url: str, max_bytes: int, timeout: float = TIMEOUT) -> bytes:
    """GET with https/host allowlist on every hop (manual redirects, max 3). Non-200 raises."""
    hop = check_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        resp = fetch(hop, max_bytes, timeout)
        if resp.status in (301, 302, 303, 307, 308) and resp.location:
            hop = check_url(urllib.parse.urljoin(hop, resp.location), redirect=True)
            continue
        if resp.status != 200:
            raise WinpairsError(f'HTTP {resp.status}')
        if len(resp.body) > max_bytes:
            raise WinpairsError(f'response exceeds {max_bytes} byte cap')
        return resp.body
    raise WinpairsError('too many redirects')


def load_index(fetch: Fetcher, name: str) -> dict[str, Any]:
    raw = fetch_checked(fetch, index_url(name), MAX_INDEX_BYTES)
    d = zlib.decompressobj(31)  # gzip, bounded against decompression bombs
    data = d.decompress(raw, MAX_INDEX_JSON_BYTES)
    if d.unconsumed_tail:
        raise WinpairsError('decompressed index too large')
    obj = json.loads(data)
    if not isinstance(obj, dict):
        raise WinpairsError('unexpected Winbindex index shape')
    return obj


def resolve_side(fetch: Fetcher, side: dict[str, Any], cache: dict[str, Any]) -> dict[str, Any]:
    try:
        q = parse_ref(side)
        name = safe_name(q['file'], 'file name')
        if name.lower() not in cache:
            cache[name.lower()] = load_index(fetch, name)
        fi, why = select_entry(cache[name.lower()], q)
        return side_record(name, fi, why)
    except (WinpairsError, ValueError, KeyError, OSError, zlib.error) as e:
        return {'file': str(side.get('file') or str(side.get('ref', '')).split(',')[0]), 'status': 'missing',
                'reason': f'{type(e).__name__}: {e}'[:200]}


def _check_destination(target: Path) -> None:
    """Refuse prior paths, including dangling links; publication also has an atomic no-clobber guard."""
    for parent in target.parents:
        if parent.is_symlink() or parent.is_junction():
            raise WinpairsError('an output parent is a link; use a new ordinary directory')
    try:
        target.lstat()
    except FileNotFoundError:
        return
    raise FileExistsError('destination already exists; prior evidence is preserved')


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _write_stage(fd: int, data: bytes) -> tuple[int, int]:
    """Keep the exact source open; verify the flushed bytes through that descriptor."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise PublicationBlocked('safe publication requires an ordinary staging file')
    with os.fdopen(fd, 'w+b', closefd=False) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(fd)
        handle.seek(0)
        digest = hashlib.file_digest(handle, 'sha256').digest()
    after = os.fstat(fd)
    if (_file_identity(before) != _file_identity(after) or after.st_size != len(data) or
            digest != hashlib.sha256(data).digest()):
        raise PublicationBlocked('safe publication staging identity or bytes changed')
    return _file_identity(after)


def _linux_directory(path: Path, *, create: bool) -> int:
    """Open root to leaf without following any parent link, creating only anchored children."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _check_linux_parent(path: Path, owned: int) -> None:
    try:
        observed = _linux_directory(path, create=False)
    except OSError:
        raise PublicationBlocked('safe publication parent changed or became a link') from None
    try:
        if _file_identity(os.fstat(observed)) != _file_identity(os.fstat(owned)):
            raise PublicationBlocked('safe publication parent changed')
    finally:
        os.close(observed)


def _publish_linux(target: Path, data: bytes) -> None:
    if not hasattr(os, 'O_TMPFILE'):
        raise PublicationBlocked('safe publication requires Linux anonymous staging support')
    with ExitStack() as stack:
        parent = _linux_directory(target.parent, create=True)
        stack.callback(os.close, parent)
        # There is no staging pathname to replace or to unlink on failure.
        fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=parent)
        stack.callback(os.close, fd)
        identity = _write_stage(fd, data)
        _check_linux_parent(target.parent, parent)
        # procfs names this process's owned descriptor, not a directory entry an
        # attacker can substitute. dst_dir_fd pins the original destination parent.
        os.link(f'/proc/self/fd/{fd}', target.name, dst_dir_fd=parent, follow_symlinks=True)
        if _file_identity(os.stat(target.name, dir_fd=parent, follow_symlinks=False)) != identity:
            raise PublicationBlocked('safe publication destination identity changed')
        _check_linux_parent(target.parent, parent)


class _WindowsPublication:
    """Rooted NT opens and information calls; never reopen a stage for cleanup.

    Sharing locks alone do not protect reparse attributes. Every child operation
    therefore uses RootDirectory and rejects reparse processing as well.
    """

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes as wt

        self.ct = ctypes
        self.wt = wt
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.nt = ctypes.WinDLL('ntdll')

        class UnicodeString(ctypes.Structure):
            _fields_ = [('Length', wt.USHORT), ('MaximumLength', wt.USHORT), ('Buffer', wt.LPWSTR)]

        class ObjectAttributes(ctypes.Structure):
            _fields_ = [('Length', wt.ULONG), ('RootDirectory', wt.HANDLE),
                        ('ObjectName', ctypes.POINTER(UnicodeString)), ('Attributes', wt.ULONG),
                        ('SecurityDescriptor', wt.LPVOID), ('SecurityQualityOfService', wt.LPVOID)]

        class IoStatus(ctypes.Structure):
            _fields_ = [('StatusOrPointer', wt.LPVOID), ('Information', ctypes.c_size_t)]

        class FileInfo(ctypes.Structure):
            _fields_ = [('Attributes', wt.DWORD), ('Creation', wt.FILETIME), ('Access', wt.FILETIME),
                        ('Write', wt.FILETIME), ('Volume', wt.DWORD), ('SizeHigh', wt.DWORD),
                        ('SizeLow', wt.DWORD), ('Links', wt.DWORD), ('IndexHigh', wt.DWORD),
                        ('IndexLow', wt.DWORD)]

        class RenameInfo(ctypes.Structure):
            _fields_ = [('ReplaceIfExists', wt.BOOLEAN), ('RootDirectory', wt.HANDLE),
                        ('FileNameLength', wt.DWORD), ('FileName', wt.WCHAR * 1)]

        self.UnicodeString, self.ObjectAttributes, self.IoStatus = UnicodeString, ObjectAttributes, IoStatus
        self.FileInfo, self.RenameInfo = FileInfo, RenameInfo
        self.kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
                                            wt.DWORD, wt.DWORD, wt.HANDLE]
        self.kernel.CreateFileW.restype = wt.HANDLE
        self.kernel.CloseHandle.argtypes = [wt.HANDLE]
        self.kernel.CloseHandle.restype = wt.BOOL
        self.kernel.GetFileInformationByHandle.argtypes = [wt.HANDLE, ctypes.POINTER(FileInfo)]
        self.kernel.GetFileInformationByHandle.restype = wt.BOOL
        self.nt.NtCreateFile.argtypes = [ctypes.POINTER(wt.HANDLE), wt.DWORD,
                                         ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatus),
                                         wt.LPVOID, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
                                         wt.LPVOID, wt.DWORD]
        self.nt.NtCreateFile.restype = wt.LONG
        self.nt.NtSetInformationFile.argtypes = [wt.HANDLE, ctypes.POINTER(IoStatus), wt.LPVOID,
                                                wt.ULONG, ctypes.c_int]
        self.nt.NtSetInformationFile.restype = wt.LONG
        self.nt.RtlNtStatusToDosError.argtypes = [wt.LONG]
        self.nt.RtlNtStatusToDosError.restype = wt.ULONG

    def error(self, code: int | None = None) -> None:
        code = self.ct.get_last_error() if code is None else code
        if code in (80, 183):  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
            raise FileExistsError('destination already exists; prior evidence is preserved')
        raise self.ct.WinError(code)

    def identity(self, handle: int, *, directory: bool = False) -> tuple[int, int, int]:
        info = self.FileInfo()
        if not self.kernel.GetFileInformationByHandle(handle, self.ct.byref(info)):
            self.error()
        if info.Attributes & 0x400 or (directory and not info.Attributes & 0x10):
            raise PublicationBlocked('safe publication requires ordinary, non-reparse directories/files')
        if not (info.IndexHigh or info.IndexLow):
            raise PublicationBlocked('safe publication file identity is unavailable')
        return info.Volume, info.IndexHigh, info.IndexLow

    def open_child(self, parent: int, name: str, *, directory: bool, create: bool) -> int:
        encoded = name.encode('utf-16-le')
        if len(encoded) > 65532:
            raise PublicationBlocked('safe publication component is too long')
        buffer = self.ct.create_unicode_buffer(name)
        text = self.UnicodeString(len(encoded), len(encoded) + 2, self.ct.cast(buffer, self.wt.LPWSTR))
        attrs = self.ObjectAttributes(self.ct.sizeof(self.ObjectAttributes), parent, self.ct.pointer(text),
                                      0x1040, None, None)  # OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        result, status = self.wt.HANDLE(), self.IoStatus()
        access = 0x1000A0 if directory else 0xC0110000  # traverse/attributes/sync; R/W, DELETE, sync
        disposition = (3 if create else 1) if directory else 2  # OPEN_IF / OPEN; CREATE, never overwrite
        options = 0x200020 | (1 if directory else 0x40)  # no reparse, sync; directory / ordinary file
        code = self.nt.NtCreateFile(self.ct.byref(result), access, self.ct.byref(attrs),
                                    self.ct.byref(status), None, 0x80, 1, disposition, options, None, 0)
        if code < 0:
            self.error(self.nt.RtlNtStatusToDosError(code))
        return result.value

    def directory(self, path: Path, stack: ExitStack, *, create: bool) -> int:
        # Only the volume/share root is opened by path. Every descendant is rooted
        # in its already held parent, including creation of missing directories.
        parent = self.kernel.CreateFileW(str(path.anchor), 0x1000A0, 1, None, 3, 0x2200000, None)
        if parent == self.ct.c_void_p(-1).value:
            self.error()
        stack.callback(self.kernel.CloseHandle, parent)
        self.identity(parent, directory=True)
        for component in path.parts[1:]:
            parent = self.open_child(parent, component, directory=True, create=create)
            stack.callback(self.kernel.CloseHandle, parent)
            self.identity(parent, directory=True)
        return parent

    def check_parent(self, path: Path, owned: int) -> None:
        try:
            with ExitStack() as stack:
                observed = self.directory(path, stack, create=False)
                if self.identity(observed, directory=True) != self.identity(owned, directory=True):
                    raise PublicationBlocked('safe publication parent changed')
        except OSError:
            raise PublicationBlocked('safe publication parent changed or became unavailable') from None

    def _set_information(self, source: int, buffer: Any, size: int, information_class: int) -> None:
        status = self.IoStatus()
        code = self.nt.NtSetInformationFile(source, self.ct.byref(status), buffer, size, information_class)
        if code < 0:
            self.error(self.nt.RtlNtStatusToDosError(code))
        if code != 0:
            # The owned source was opened synchronously and nonalertably. Never
            # credit STATUS_PENDING or an unexpected informational return as done.
            raise PublicationBlocked('safe publication information call did not complete synchronously')

    def rename(self, source: int, parent: int, name: str) -> None:
        encoded = name.encode('utf-16-le')
        buffer = self.ct.create_string_buffer(self.ct.sizeof(self.RenameInfo) + len(encoded))
        info = self.RenameInfo.from_buffer(buffer)
        info.ReplaceIfExists, info.RootDirectory, info.FileNameLength = False, parent, len(encoded)
        self.ct.memmove(self.ct.addressof(buffer) + self.RenameInfo.FileName.offset, encoded, len(encoded))
        self._set_information(source, buffer, len(buffer), 10)  # FileRenameInformation

    def discard(self, source: int) -> None:
        delete = self.wt.BOOLEAN(True)  # FILE_DISPOSITION_INFORMATION, exact held source
        self._set_information(source, self.ct.byref(delete), self.ct.sizeof(delete), 13)


def _publish_windows(target: Path, data: bytes) -> None:
    import msvcrt

    win = _WindowsPublication()
    with ExitStack() as stack:
        parent = win.directory(target.parent, stack, create=True)
        source = win.open_child(parent, f'.winpairs-{secrets.token_hex(16)}.tmp', directory=False, create=True)
        fd, published = None, False
        primary: BaseException | None = None
        try:
            identity = win.identity(source)
            fd = msvcrt.open_osfhandle(source, os.O_RDWR | os.O_BINARY)
            _write_stage(fd, data)
            win.check_parent(target.parent, parent)
            if win.identity(source) != identity:
                raise PublicationBlocked('safe publication staging identity changed')
            win.rename(source, parent, target.name)
            published = True
            win.check_parent(target.parent, parent)
            if win.identity(source) != identity:
                raise PublicationBlocked('safe publication destination identity changed')
        except BaseException as exc:
            primary = exc
            raise
        finally:
            failures: list[tuple[str, BaseException]] = []
            try:
                if not published:
                    win.discard(source)
            except BaseException as exc:
                failures.append(('discard', exc))
            try:
                if fd is None:
                    if not win.kernel.CloseHandle(source):
                        win.error()
                else:
                    os.close(fd)  # owns the Windows handle after open_osfhandle succeeds
            except BaseException as exc:
                failures.append(('close', exc))
            if failures:
                error = primary if primary is not None else failures[0][1]
                for operation, failure in failures:
                    if failure is not error:
                        error.add_note(f'Windows {operation} cleanup also failed: {type(failure).__name__}'[:160])
                if primary is None:
                    raise error


def _publish_bytes(target: Path, data: bytes) -> None:
    """Publish the exact owned source into its held parent, with no replacing fallback."""
    _check_destination(target)
    target = Path(os.path.abspath(target))
    try:
        if sys.platform.startswith('linux'):
            _publish_linux(target, data)
        elif os.name == 'nt':
            _publish_windows(target, data)
        else:
            raise PublicationBlocked('safe publication is unsupported on this platform')
    except FileExistsError:
        raise
    except (OSError, NotImplementedError, AttributeError) as e:
        code = getattr(e, 'winerror', None) or getattr(e, 'errno', None)
        detail = f' (OS error {code})' if code is not None else ''
        blocked = PublicationBlocked(f'safe publication unavailable: {type(e).__name__}{detail}')
        for note in getattr(e, '__notes__', ())[:2]:
            blocked.add_note(note[:160])
        raise blocked from None


def download_side(fetch: Fetcher, rec: dict[str, Any], dest: Path, rel: str) -> None:
    """Fill rec in place; refuse ambiguous identities and preserve every earlier or concurrent artifact."""
    if rec['status'] != 'found':
        return
    try:
        _check_destination(dest)
        exp = rec.get('expected_sha256')
        if not isinstance(exp, str) or not _HEX64.fullmatch(exp):
            raise WinpairsError('a valid expected sha256 is required before downloading')
        size = rec.get('expected_size')
        if size is not None and (type(size) is not int or not 0 <= size <= MAX_BINARY_BYTES):
            raise WinpairsError('invalid expected byte size')
        body = fetch_checked(fetch, rec['source_url'], MAX_BINARY_BYTES)
        got = hashlib.sha256(body).hexdigest()
        if got != exp.lower():
            raise WinpairsError('sha256 mismatch against Winbindex')
        if size is not None and len(body) != size:
            raise WinpairsError('byte size mismatch against Winbindex')
        _publish_bytes(dest, body)
        rec.update(sha256=got, size=len(body), path=rel, sha256_verified=True)
    except FileExistsError:
        rec.update(status='missing', reason='destination already exists; prior evidence is preserved')
    except PublicationBlocked as e:
        rec.update(status='missing', reason=f'BLOCKED: {e}'[:200])
    except WinpairsError as e:
        rec.update(status='missing', reason=f'download failed: {e}'[:200])
    except OSError as e:
        rec.update(status='missing', reason=f'artifact publication failed: {type(e).__name__}')


def run(cases: list[dict[str, Any]], fetch: Fetcher, out_dir: Path | None) -> dict[str, Any]:
    cache: dict[str, Any] = {}
    out = []
    for c in cases:
        cid = safe_name(str(c.get('id', '')), 'case id')
        recs = {k: resolve_side(fetch, c.get(k) or {}, cache) for k in ('older', 'newer')}
        if out_dir is not None:
            for k, rec in recs.items():
                if rec['status'] == 'found':
                    download_side(fetch, rec, out_dir / cid / k / rec['file'], f'{cid}/{k}/{rec["file"]}')
        status = case_status(recs['older'], recs['newer'])
        out.append({'id': cid, 'status': status, 'older': recs['older'], 'newer': recs['newer']})
    return build_manifest(out)


def exit_code(manifest: dict[str, Any]) -> int:
    cases = manifest['cases']
    if any(str(c.get(side, {}).get('reason', '')).startswith('BLOCKED:')
           for c in cases for side in ('older', 'newer')):
        return 2
    return 0 if any(c['status'] == 'found' for c in cases) else 1


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None, fetch: Fetcher = urllib_fetcher) -> int:
    ap = argparse.ArgumentParser(prog='winpairs', description=__doc__.split('\n')[0])
    ap.add_argument('--manifest', required=True, help='rq-case-manifest/1 JSON')
    ap.add_argument('--out-dir', required=True, help='directory for fetched binaries (never commit)')
    ap.add_argument('--pair-manifest', required=True, help='where to write the pair manifest JSON')
    ap.add_argument('--case', default='', help='comma-separated case ids (default: all)')
    ap.add_argument('--resolve-only', action='store_true', help='resolve metadata and URLs, download nothing')
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        mpath = confine(a.manifest, 'manifest')
        out_dir = confine(a.out_dir, 'out-dir')
        _check_destination(Path(a.pair_manifest).expanduser())
        pm = confine(a.pair_manifest, 'pair-manifest')
        data = json.loads(mpath.read_text(encoding='utf-8'))
        if data.get('schema') != IN_SCHEMA or not isinstance(data.get('cases'), list):
            raise WinpairsError(f'manifest schema must be {IN_SCHEMA}')
        want = [x for x in a.case.split(',') if x.strip()]
        want = [x.strip() for x in want]
        cases = [c for c in data['cases'] if not want or c.get('id') in want]
        unknown = set(want) - {c.get('id') for c in data['cases']}
        if unknown or not cases:
            raise WinpairsError(f'no such case id(s): {sorted(unknown)}' if unknown else 'no cases selected')
        manifest = run(cases, fetch, None if a.resolve_only else out_dir)
        _publish_bytes(pm, (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    except (PathGuardError, WinpairsError, OSError, ValueError) as e:
        print(f'winpairs: blocked: {e}', file=sys.stderr)
        return 2
    n = sum(c['status'] == 'found' for c in manifest['cases'])
    print(f'winpairs: {n}/{len(manifest["cases"])} case(s) found; manifest {pm.name}')
    return exit_code(manifest)


if __name__ == '__main__':
    raise SystemExit(main())
