"""Consented HTTPS transport for acquisition (SPEC-08 §4). Mirrors enrichment/intelligence.py.

Nothing about the user's projects is sent: requests carry only the public file name,
timestamp and SizeOfImage in the URL plus fixed headers. Every hop is re-checked against
the allowlist; the Azure blob host is admitted only as the single redirect target of a
symbol-server download, and the signed blob URL is never returned or stored.
"""
from __future__ import annotations

import email.utils
import hashlib
import http.client
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .contracts import AcquisitionError, PlannedDownload
from .winbindex import MAX_COMPRESSED, metadata_url

METADATA_HOST = 'winbindex.m417z.com'
SYMBOL_HOST = 'msdl.microsoft.com'
BLOB_SUFFIX = '.blob.core.windows.net'
CONSENTABLE_HOSTS = frozenset({METADATA_HOST, SYMBOL_HOST})
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
DOWNLOAD_DEADLINE = 3600.0  # total seconds per download attempt; a slow-drip server cannot hold it open longer
TIMEOUT = 10.0
METADATA_DEADLINE = 120.0
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER = 60
MAX_CONCURRENT_PROBES = 4
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
HEADERS = (('User-Agent', 'PatchTrace'),)
_CHUNK = 64 * 1024  # small, so cancel and the deadline are noticed after at most one socket wait
SLICE = 0.5  # longest a blocking receive may go without re-checking cancel and the deadline


@dataclass(frozen=True)
class AcquisitionConsent:
    """What the user agreed to: exact hosts and exact URLs. Built only from a displayed plan."""
    hosts: frozenset[str]
    urls: frozenset[str]

    @classmethod
    def for_urls(cls, urls: Iterable[str]) -> AcquisitionConsent:
        urls = frozenset(urls)
        return cls(frozenset(urllib.parse.urlsplit(u).hostname or '' for u in urls), urls)


def _check(url: str, *, blob: bool = False) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise AcquisitionError('PT-ACQ-NETWORK', 'invalid URL refused') from None
    host = parts.hostname or ''
    # urlsplit strips tab/CR/LF and tolerates spaces; http.client would later raise with the signed URL in its text.
    if any(not '!' <= ch <= '~' for ch in url):
        raise AcquisitionError('PT-ACQ-NETWORK', 'invalid URL refused')
    allowed = (host.endswith(BLOB_SUFFIX) and len(host) > len(BLOB_SUFFIX)) if blob else host in CONSENTABLE_HOSTS
    if (parts.scheme != 'https' or not allowed or port not in (None, 443)
            or parts.username is not None or parts.password is not None):
        raise AcquisitionError('PT-ACQ-NETWORK', 'URL outside the HTTPS acquisition allowlist refused')
    return host


def _consented(url: str, consent: AcquisitionConsent) -> None:
    host = _check(url)
    if host not in consent.hosts or url not in consent.urls:
        raise AcquisitionError('PT-ACQ-CONFIG', 'request not covered by user consent')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Surface every 3xx so the allowlist check sees each hop instead of urllib following it.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _SlicedSocket:
    """Wraps a connected socket so every blocking receive wakes about every SLICE seconds.

    Closing or shutting a socket from another thread does not reliably wake a blocked recv on
    Windows, so the reader itself polls: each slice re-runs ``guard`` (which raises on cancel or
    deadline) and a silent peer is given up on after ``idle`` seconds, as one plain socket timeout
    would. The wrapper sits under http.client's buffered reader, which therefore never sees the
    intermediate timeouts and stays consistent.
    """

    def __init__(self, sock: socket.socket, guard: Callable[[], None], idle: float):
        self._sock, self._guard, self._idle = sock, guard, idle
        sock.settimeout(SLICE)

    def recv_into(self, buffer, *args):
        started = time.monotonic()
        while True:
            self._guard()
            try:
                return self._sock.recv_into(buffer, *args)
            except TimeoutError:
                if time.monotonic() - started >= self._idle:
                    raise

    def __getattr__(self, name: str):
        return getattr(self._sock, name)


class _Response:
    def __init__(self, raw, timeout: float = TIMEOUT):
        self._raw = raw
        self._timeout = timeout
        self.status = getattr(raw, 'status', None) or raw.code
        self.headers = raw.headers

    def read(self, size: int) -> bytes:
        # read1 returns what one socket read delivered instead of waiting for a full buffer.
        reader = getattr(self._raw, 'read1', self._raw.read)
        return reader(size)

    def guard_reads(self, guard: Callable[[], None]) -> None:
        """Make body reads call ``guard`` at least every SLICE seconds. Best effort: without a real socket
        underneath, the plain socket timeout still bounds each read."""
        io = getattr(getattr(self._raw, 'fp', None), 'raw', None)
        sock = getattr(io, '_sock', None)
        if sock is not None and not isinstance(sock, _SlicedSocket):
            io._sock = _SlicedSocket(sock, guard, self._timeout)

    def close(self) -> None:
        self._raw.close()


def urllib_open(method: str, url: str, headers: Mapping[str, str], timeout: float):
    """Default opener. ProxyHandler({}) ignores environment proxies, which would otherwise see
    which builds an analyst is fetching."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        return _Response(opener.open(urllib.request.Request(url, headers=dict(headers), method=method),
                                     timeout=timeout), timeout)
    except urllib.error.HTTPError as exc:
        return _Response(exc, timeout)
    except (ValueError, http.client.HTTPException):
        raise ConnectionError('invalid request') from None  # the message would echo the signed URL
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError('timed out') from None
        raise ConnectionError('connection failed') from None


def default_sleep(seconds: float, cancel: threading.Event | None) -> None:
    if cancel is None:
        time.sleep(seconds)
    else:
        cancel.wait(seconds)


def _cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise AcquisitionError('PT-ACQ-CANCEL', 'acquisition cancelled', recoverable=True)


def _retry_after(value: str | None, now: datetime) -> float | None:
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        try:
            return float(int(value))
        except (ValueError, OverflowError):  # absurdly long digit strings
            return None
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return float(max(0, int((when - now).total_seconds()) + 1))


def _stamp(now: datetime) -> str:
    return now.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


@dataclass
class Transport:
    opener: Callable = urllib_open
    cancel: threading.Event | None = None
    sleep: Callable[[float, threading.Event | None], None] = default_sleep
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = lambda: datetime.now(UTC)

    def _with_retries(self, action: Callable[[], object]):
        for attempt in range(1, MAX_ATTEMPTS + 1):
            _cancelled(self.cancel)
            try:
                return action()
            except _Retry as retry:
                if attempt == MAX_ATTEMPTS:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'server unavailable after retries',
                                           recoverable=True) from None
                wait = float(2 ** (attempt - 1)) if retry.wait is None else retry.wait
                if wait > MAX_RETRY_AFTER:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'server asked to retry later than 60 s',
                                           recoverable=True) from None
                self.sleep(wait, self.cancel)
        raise AssertionError('unreachable')

    def _open(self, method: str, url: str, timeout: float = TIMEOUT):
        try:
            return self.opener(method, url, dict(HEADERS), timeout)
        except TimeoutError:
            raise _Retry(None) from None
        except OSError:
            raise AcquisitionError('PT-ACQ-NETWORK', 'connection failed', recoverable=True) from None

    def _retryable(self, response) -> None:
        if response.status in RETRYABLE_STATUS:
            raise _Retry(_retry_after(response.headers.get('Retry-After'), self.now()))

    def _read(self, response, sink: Callable[[bytes], None], cap: int, what: str,
              deadline: float | None = None) -> None:
        length = response.headers.get('Content-Length')
        digits = length.strip() if length is not None else ''
        if digits.isascii() and digits.isdigit() and (len(digits) > 18 or int(digits) > cap):
            raise AcquisitionError('PT-ACQ-LIMIT', f'{what} exceeds its size cap')
        guard_reads = getattr(response, 'guard_reads', None)
        if guard_reads is not None:
            guard_reads(lambda: self._live(deadline))
        self._read_chunks(response, sink, cap, what, deadline)

    def _read_chunks(self, response, sink: Callable[[bytes], None], cap: int, what: str,
                     deadline: float | None) -> None:
        total = 0
        while True:
            self._live(deadline)
            try:
                chunk = response.read(min(_CHUNK, cap + 1 - total))
            except (OSError, ValueError, http.client.HTTPException) as exc:
                if isinstance(exc, TimeoutError):
                    raise _Retry(None) from None
                raise AcquisitionError('PT-ACQ-NETWORK', 'connection failed while reading',
                                       recoverable=True) from None
            if not chunk:
                return
            total += len(chunk)
            if total > cap:
                raise AcquisitionError('PT-ACQ-LIMIT', f'{what} exceeds its size cap')
            sink(chunk)

    def _live(self, deadline: float | None) -> None:
        _cancelled(self.cancel)
        if deadline is not None and self.clock() >= deadline:
            raise AcquisitionError('PT-ACQ-NETWORK', 'total timeout exceeded', recoverable=True)

    # -- Winbindex metadata -------------------------------------------------------------
    def fetch_metadata(self, file_name: str, consent: AcquisitionConsent) -> MetadataResponse:
        url = metadata_url(file_name)
        _consented(url, consent)
        deadline = self.clock() + METADATA_DEADLINE

        def attempt():
            response = self._open('GET', url)
            try:
                if response.status == 404:
                    raise AcquisitionError('PT-ACQ-NOTFOUND', f'Winbindex has no record for {file_name}')
                if response.status in REDIRECT_STATUS:
                    # Winbindex serves data directly; a redirect is unexpected and not followed.
                    raise AcquisitionError('PT-ACQ-PROVIDER', 'unexpected redirect from Winbindex')
                self._retryable(response)
                if response.status != 200:
                    raise AcquisitionError('PT-ACQ-PROVIDER', f'Winbindex returned HTTP {response.status}')
                data = bytearray()
                self._read(response, data.extend, MAX_COMPRESSED, 'Winbindex record', deadline)
                return MetadataResponse(bytes(data), url, _stamp(self.now()),
                                        _date(response.headers.get('Last-Modified')))
            finally:
                response.close()
        return self._with_retries(attempt)

    # -- candidate resolution -----------------------------------------------------------
    def probe(self, url: str, consent: AcquisitionConsent) -> bool:
        """HEAD a symbol-server URL: 302 valid, 404 invalid, anything else an error."""
        _consented(url, consent)
        if urllib.parse.urlsplit(url).hostname != SYMBOL_HOST:
            raise AcquisitionError('PT-ACQ-CONFIG', 'only symbol-server URLs are probed')

        def attempt():
            response = self._open('HEAD', url)
            try:
                if response.status == 302:
                    return True
                if response.status == 404:
                    return False
                self._retryable(response)
                raise AcquisitionError('PT-ACQ-PROVIDER', f'probe returned HTTP {response.status}')
            finally:
                response.close()
        return self._with_retries(attempt)

    def resolve(self, urls: Iterable[str], consent: AcquisitionConsent) -> str:
        """Return the single valid candidate URL. None valid means not on the server."""
        urls = tuple(urls)
        if not urls:
            raise AcquisitionError('PT-ACQ-NOTFOUND', 'no candidate SizeOfImage values to probe')
        for url in urls:
            _consented(url, consent)
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_PROBES) as pool:
            failed = threading.Event()

            def task(url: str) -> bool:
                if failed.is_set():  # a sibling already failed and its error is the one raised
                    return False
                try:
                    return self.probe(url, consent)
                except BaseException:
                    failed.set()
                    raise
            futures = [pool.submit(task, url) for url in urls]
            try:
                pending = set(futures)
                while pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        future.result()  # the first failure stops queued probes below
                results = [f.result() for f in futures]
            except BaseException:
                for future in futures:
                    future.cancel()
                raise
        valid = [u for u, ok in zip(urls, results, strict=True) if ok]
        if not valid:
            raise AcquisitionError('PT-ACQ-NOTFOUND', 'no candidate URL exists on the symbol server')
        if len(valid) > 1:
            raise AcquisitionError('PT-ACQ-PROVIDER', f'{len(valid)} candidate URLs answered; ambiguous')
        return valid[0]

    # -- download -----------------------------------------------------------------------
    def download(self, planned: PlannedDownload, consent: AcquisitionConsent, directory: Path,
                 progress: Callable[[int, int], None] | None = None) -> Downloaded:
        """Stream one planned file into `directory`, verifying size and SHA-256 against the plan.

        `progress(received, expected)` is observational only: it is called at 0 on every
        attempt (so a retry restarts the bar), after each ~1% of the planned size, and at
        completion. It never influences verification; a raising callback is not caught.
        """
        _consented(planned.url, consent)
        if urllib.parse.urlsplit(planned.url).hostname != SYMBOL_HOST:
            raise AcquisitionError('PT-ACQ-CONFIG', 'downloads come only from the symbol server')
        cap = min(MAX_DOWNLOAD_BYTES, planned.size)
        return self._with_retries(lambda: self._download_once(planned, Path(directory), cap, progress))

    def _download_once(self, planned: PlannedDownload, directory: Path, cap: int,
                       progress: Callable[[int, int], None] | None = None) -> Downloaded:
        url, redirect_host = planned.url, None
        response = self._open('GET', url)
        try:
            if response.status == 404:
                raise AcquisitionError('PT-ACQ-NOTFOUND', 'not on the symbol server')
            if response.status in REDIRECT_STATUS:
                location = response.headers.get('Location')
                if not location:
                    raise AcquisitionError('PT-ACQ-PROVIDER', 'redirect without Location')
                target = urllib.parse.urljoin(url, location)
                redirect_host = _check(target, blob=True)
                response.close()
                response = self._open('GET', target)
                if response.status in REDIRECT_STATUS:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'more than one redirect refused')
            self._retryable(response)
            if response.status != 200:
                raise AcquisitionError('PT-ACQ-PROVIDER', f'download returned HTTP {response.status}')
            fd, name = tempfile.mkstemp(prefix='.download-', dir=directory)
            path = Path(name)
            digest = hashlib.sha256()
            size = reported = 0
            step = max(planned.size // 100, 1)
            try:
                if progress:
                    progress(0, planned.size)
                with os.fdopen(fd, 'wb') as out:
                    def sink(chunk: bytes) -> None:
                        nonlocal size, reported
                        size += len(chunk)
                        digest.update(chunk)
                        out.write(chunk)
                        if progress and size - reported >= step:
                            reported = size
                            progress(size, planned.size)
                    self._read(response, sink, cap, 'download', self.clock() + DOWNLOAD_DEADLINE)
                    if progress and size != reported:
                        progress(size, planned.size)
                    out.flush()
                    os.fsync(out.fileno())
                if size != planned.size:
                    raise AcquisitionError('PT-ACQ-VERIFY', f'size {size} does not match the expected {planned.size}')
                if digest.hexdigest() != planned.sha256:
                    raise AcquisitionError('PT-ACQ-VERIFY', 'SHA-256 does not match the Winbindex record')
            except BaseException:
                path.unlink(missing_ok=True)
                raise
            return Downloaded(path, digest.hexdigest(), size, planned.url, redirect_host, _stamp(self.now()))
        finally:
            response.close()


class _Retry(Exception):
    def __init__(self, wait: float | None):
        self.wait = wait


def _date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return when.astimezone(UTC).date().isoformat() if when.tzinfo else None


@dataclass(frozen=True)
class MetadataResponse:
    body: bytes
    url: str
    retrieved_at: str
    last_modified: str | None

    @property
    def data_date(self) -> str:
        # The gzip has mtime=0, so the HTTP Last-Modified date is the best data date available;
        # fall back to the retrieval date and say so via `source`.
        return self.last_modified or self.retrieved_at[:10]


@dataclass(frozen=True)
class Downloaded:
    path: Path
    sha256: str
    size: int
    source_url: str
    redirect_host: str | None
    retrieved_at: str
