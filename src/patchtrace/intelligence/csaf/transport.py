"""Consented, allow-listed HTTPS transport for the Microsoft CSAF directory (SPEC-28 section D).

Pattern of ``acquisition/transport.py`` and ``enrichment/intelligence.py``: opt-in consent naming exact hosts,
HTTPS on port 443 only, a fixed path allowlist, every redirect hop re-checked, bounded bodies, attempts, retry
waits and time, cooperative cancellation, and environment proxies ignored. Requests are GET with two fixed
headers; nothing about a project, a binary or the analyst is ever sent (the server learns only which public
files are read). An opt-in offline cache stores content-addressed bodies; ``offline`` mode never opens a socket.
"""
from __future__ import annotations

import email.utils
import hashlib
import http.client
import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from ...netutil import Cancelled, TooManyAbandoned, interruptible
from ..contracts import IntelError

CONSENTABLE_HOSTS = frozenset({'msrc.microsoft.com'})
PATH_PREFIXES = ('/csaf/', '/.well-known/csaf/')
CAPS = {'provider-metadata': 1024 * 1024, 'index': 16 * 1024 * 1024, 'document': 16 * 1024 * 1024,
        'hash': 4096}
ACCEPT = {'provider-metadata': 'application/json', 'document': 'application/json', 'index': 'text/plain',
          'hash': 'text/plain'}
CONNECT_TIMEOUT = 10.0
REQUEST_DEADLINE = 60.0
PLAN_DEADLINE = 300.0
MAX_ATTEMPTS = 3
MAX_REDIRECTS = 2
MAX_RETRY_AFTER = 60
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
USER_AGENT = 'PatchTrace'
_CHUNK = 65536


@dataclass(frozen=True)
class CsafConsent:
    """What the analyst agreed to: exact hosts (a subset of CONSENTABLE_HOSTS)."""
    hosts: frozenset[str]

    @classmethod
    def for_hosts(cls, hosts: Iterable[str]) -> CsafConsent:
        chosen = frozenset(h.strip().lower() for h in hosts if h.strip())
        if not chosen or not chosen <= CONSENTABLE_HOSTS:
            raise IntelError('PT-INTEL-CONFIG', f'consent must name only: {", ".join(sorted(CONSENTABLE_HOSTS))}')
        return cls(chosen)


def check_url(url: str, consent: CsafConsent | None = None) -> str:
    """Return the host of an allowlisted CSAF URL or raise PT-INTEL-CONFIG."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise IntelError('PT-INTEL-CONFIG', 'invalid URL refused') from None
    host = (parts.hostname or '').lower()
    path = parts.path
    if (parts.scheme != 'https' or host not in CONSENTABLE_HOSTS or port not in (None, 443)
            or parts.username is not None or parts.password is not None or '?' in url or '#' in url
            or not path.startswith(PATH_PREFIXES) or '%' in path or '\\' in path or '//' in path
            or any(segment in ('.', '..') for segment in path.split('/'))
            or any(ord(c) < 33 or ord(c) > 126 for c in url)):
        raise IntelError('PT-INTEL-CONFIG', 'URL outside the CSAF HTTPS allowlist refused')
    if consent is not None and host not in consent.hosts:
        raise IntelError('PT-INTEL-CONFIG', f'{host} is not covered by --consent-hosts')
    return host


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Every 3xx is surfaced so the allowlist check sees each hop instead of urllib following it.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Response:
    def __init__(self, raw):
        self._raw = raw
        self.status = getattr(raw, 'status', None) or raw.code
        self.headers = raw.headers

    def read(self, size: int) -> bytes:
        return self._raw.read(size)

    def close(self) -> None:
        self._raw.close()


def build_director() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores HTTPS_PROXY/ALL_PROXY: an environment proxy would otherwise observe which
    # advisories an analyst reads.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def urllib_open(url: str, headers: Mapping[str, str], timeout: float):
    request = urllib.request.Request(url, headers=dict(headers), method='GET')
    try:
        return _Response(build_director().open(request, timeout=timeout))
    except urllib.error.HTTPError as exc:
        return _Response(exc)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError('timed out') from None
        raise ConnectionError('connection failed') from None


def default_sleep(seconds: float, cancel: threading.Event | None) -> None:
    if cancel is None:
        time.sleep(seconds)
    else:
        cancel.wait(seconds)


def _stamp(now: datetime) -> str:
    return now.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _retry_after(value: str | None, now: datetime) -> float | None:
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit() and len(value) < 10:
        return float(int(value))
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return float(max(0, int((when - now).total_seconds()) + 1))


@dataclass(frozen=True)
class Fetched:
    url: str
    final_url: str
    body: bytes = field(repr=False)
    sha256: str
    retrieved_at: str
    from_cache: bool = False


class OfflineCache:
    """Opt-in, content-addressed body cache: ``<root>/bodies/<sha256>`` plus ``<root>/urls.json``.
    Entries are verified by hash on every read; anything unreadable or mismatched counts as absent."""
    MAX_MAP_BYTES = 8 * 1024 * 1024

    def __init__(self, root: Path):
        self.root = Path(root)

    def _map(self) -> dict:
        path = self.root / 'urls.json'
        try:
            if path.stat().st_size > self.MAX_MAP_BYTES:
                return {}
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, url: str) -> Fetched | None:
        entry = self._map().get(url)
        if not isinstance(entry, dict) or not isinstance(entry.get('sha256'), str):
            return None
        sha = entry['sha256']
        if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
            return None
        try:
            body = (self.root / 'bodies' / sha).read_bytes()
        except OSError:
            return None
        if hashlib.sha256(body).hexdigest() != sha:
            return None
        return Fetched(url=url, final_url=str(entry.get('final_url', url)), body=body, sha256=sha,
                       retrieved_at=str(entry.get('retrieved_at', '')), from_cache=True)

    def put(self, fetched: Fetched) -> None:
        bodies = self.root / 'bodies'
        bodies.mkdir(parents=True, exist_ok=True)
        target = bodies / fetched.sha256
        if not target.is_file():
            _atomic_write(target, fetched.body)
        mapping = self._map()
        mapping[fetched.url] = {'sha256': fetched.sha256, 'retrieved_at': fetched.retrieved_at,
                                'final_url': fetched.final_url}
        _atomic_write(self.root / 'urls.json', json.dumps(mapping, sort_keys=True, indent=1).encode('utf-8'))


def _atomic_write(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix='.partial-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


class _Retry(Exception):
    def __init__(self, wait: float | None):
        self.wait = wait


class CsafTransport:
    """GET bounded CSAF resources. ``consent`` is required unless ``offline`` (cache only, no sockets)."""

    def __init__(self, consent: CsafConsent | None, *, opener: Callable = urllib_open,
                 cancel: threading.Event | None = None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float, threading.Event | None], None] = default_sleep,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC), cache: OfflineCache | None = None,
                 offline: bool = False, announce: Callable[[str], None] | None = None,
                 plan_deadline: float = PLAN_DEADLINE):
        if offline and cache is None:
            raise IntelError('PT-INTEL-CONFIG', 'offline mode needs a cache directory')
        if not offline and consent is None:
            raise IntelError('PT-INTEL-CONFIG', 'network access needs explicit consent (--consent-hosts)')
        self.consent, self.opener, self.cancel = consent, opener, cancel
        self.clock, self.sleep, self.now = clock, sleep, now
        self.cache, self.offline, self.announce = cache, offline, announce
        self.deadline = clock() + plan_deadline
        self.requests: list[str] = []

    def _cancelled(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise IntelError('PT-INTEL-CANCEL', 'CSAF fetch cancelled', recoverable=True)

    def get(self, url: str, kind: str, *, allow_404: bool = False) -> Fetched | None:
        if kind not in CAPS:
            raise IntelError('PT-INTEL-INPUT', f'unknown resource kind {kind}')
        check_url(url, None if self.offline else self.consent)
        self._cancelled()
        if self.offline:
            cached = self.cache.get(url)
            if cached is None:
                if allow_404:
                    return None
                raise IntelError('PT-INTEL-NOTFOUND', f'{url} is not in the offline cache')
            return cached
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._cancelled()
            try:
                result = self._attempt(url, kind, allow_404)
            except _Retry as retry:
                if attempt == MAX_ATTEMPTS:
                    raise IntelError('PT-INTEL-NETWORK', 'server unavailable after retries', recoverable=True) \
                        from None
                wait = float(2 ** (attempt - 1)) if retry.wait is None else retry.wait
                if wait > MAX_RETRY_AFTER:
                    raise IntelError('PT-INTEL-NETWORK', 'server asked to retry later than 60 s',
                                     recoverable=True) from None
                if self.clock() + wait >= self.deadline:
                    raise IntelError('PT-INTEL-NETWORK', 'retry would exceed the fetch deadline',
                                     recoverable=True) from None
                self.sleep(wait, self.cancel)
                continue
            if result is not None and self.cache is not None:
                self.cache.put(result)
            return result
        raise AssertionError('unreachable')

    def _open(self, url: str, kind: str, timeout: float):
        headers = {'Accept': ACCEPT[kind], 'User-Agent': USER_AGENT}
        try:
            return interruptible(partial(self.opener, url, headers, timeout), self.cancel,
                                 cleanup=lambda r: r.close())
        except Cancelled:
            raise IntelError('PT-INTEL-CANCEL', 'CSAF fetch cancelled', recoverable=True) from None
        except TooManyAbandoned:
            raise IntelError('PT-INTEL-NETWORK', 'previous requests still closing', recoverable=True) from None
        except TimeoutError:
            raise _Retry(None) from None
        except (OSError, http.client.HTTPException):
            raise IntelError('PT-INTEL-NETWORK', 'connection failed', recoverable=True) from None

    def _attempt(self, url: str, kind: str, allow_404: bool) -> Fetched | None:
        request_deadline = min(self.clock() + REQUEST_DEADLINE, self.deadline)
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            check_url(current, self.consent)
            remaining = request_deadline - self.clock()
            if remaining <= 0:
                raise IntelError('PT-INTEL-NETWORK', 'request deadline exceeded', recoverable=True)
            if self.announce is not None:
                self.announce(f'GET {current}')
            self.requests.append(current)
            response = self._open(current, kind, min(CONNECT_TIMEOUT, remaining))
            try:
                status = response.status
                if status in REDIRECT_STATUS:
                    location = response.headers.get('Location')
                    if not location:
                        raise IntelError('PT-INTEL-PROVIDER', 'redirect without Location')
                    current = urllib.parse.urljoin(current, location)
                    continue
                if status in RETRYABLE_STATUS:
                    raise _Retry(_retry_after(response.headers.get('Retry-After'), self.now()))
                if status == 404:
                    if allow_404:
                        return None
                    raise IntelError('PT-INTEL-NOTFOUND', f'{current} returned HTTP 404')
                if status != 200:
                    raise IntelError('PT-INTEL-PROVIDER', f'{current} returned HTTP {status}')
                body = self._read(response, CAPS[kind], kind, request_deadline)
                return Fetched(url=url, final_url=current, body=body, sha256=hashlib.sha256(body).hexdigest(),
                               retrieved_at=_stamp(self.now()))
            finally:
                response.close()
        raise IntelError('PT-INTEL-NETWORK', f'more than {MAX_REDIRECTS} redirects refused')

    def _read(self, response, cap: int, kind: str, deadline: float) -> bytes:
        length = response.headers.get('Content-Length')
        digits = length.strip() if length is not None else ''
        if digits.isascii() and digits.isdigit() and (len(digits) > 12 or int(digits) > cap):
            raise IntelError('PT-INTEL-LIMIT', f'{kind} exceeds its {cap}-byte cap')
        data = bytearray()
        while True:
            self._cancelled()
            if self.clock() >= deadline:
                raise IntelError('PT-INTEL-NETWORK', 'request deadline exceeded while reading', recoverable=True)
            try:
                chunk = interruptible(partial(response.read, min(_CHUNK, cap + 1 - len(data))), self.cancel)
            except Cancelled:
                raise IntelError('PT-INTEL-CANCEL', 'CSAF fetch cancelled', recoverable=True) from None
            except TooManyAbandoned:
                raise IntelError('PT-INTEL-NETWORK', 'previous requests still closing', recoverable=True) from None
            except TimeoutError:
                raise _Retry(None) from None
            except (OSError, http.client.HTTPException):
                raise IntelError('PT-INTEL-NETWORK', 'connection failed while reading', recoverable=True) from None
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > cap:
                raise IntelError('PT-INTEL-LIMIT', f'{kind} exceeds its {cap}-byte cap')
