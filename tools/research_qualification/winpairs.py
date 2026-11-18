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
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

# This source-checkout tool also runs without installing the desktop package.
from src.patchtrace import owned_publication as _owned
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


# Keep the research command's tested seams while sharing the production boundary.
_file_identity = _owned.file_identity
_write_stage = _owned.write_stage
_linux_directory = _owned.linux_directory
_check_linux_parent = _owned.check_linux_parent


class _WindowsPublication(_owned.WindowsPublication):
    blocked_error = PublicationBlocked


def _publish_linux(target: Path, data: bytes) -> None:
    _owned.publish_linux(target, data, stage_writer=_write_stage)


def _publish_windows(target: Path, data: bytes) -> None:
    _owned.publish_windows(target, data, windows_factory=_WindowsPublication,
                           stage_writer=_write_stage, os_api=os, prefix='.winpairs-')


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
    except _owned.OwnedPublicationError as e:
        raise PublicationBlocked(str(e)) from e
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
