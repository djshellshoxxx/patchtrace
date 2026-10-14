"""Consented HTTPS transport for the CISA KEV catalog (KEV-integration-plan section 7). No Qt, no sqlite.

Pattern of ``intelligence/csaf/transport.py`` with the read hardening of ``acquisition/transport.py``: the consent is
built from one displayed ``KevPlan``; the request URL must be exactly the plan's fixed URL; redirects stay on the same
host (https, port 443, no userinfo, no query, at most two); environment proxies are ignored; the body is read in
64 KiB ``read1`` chunks under a 16 MiB cap and a deadline, and a watcher thread aborts a read that blocks on a silent
server once cancel or the deadline hits. One GET per fetch, two fixed headers, no conditional request. The result is
unparsed bytes: parsing and storing happen afterwards in ``service``.
"""
from __future__ import annotations

import email.utils
import hashlib
import http.client
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

from ..netutil import Cancelled, TooManyAbandoned, interruptible
from . import limits
from .contracts import KevError, KevPlan

ALLOWED_HOSTS = frozenset(url.split('/')[2] for url in limits.SOURCE_URLS.values())
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
USER_AGENT = 'PatchTrace'
ACCEPT = 'application/json'
_CHUNK = 64 * 1024  # small, so cancel and the deadline are noticed after at most one socket wait
WATCH_INTERVAL = 0.1


def _refuse(message: str = 'that address is outside the KEV download allowlist') -> KevError:
    return KevError('PT-KEV-CONSENT', message)


def _parts(url: str) -> tuple[urllib.parse.SplitResult, str]:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise _refuse() from None
    host = (parts.hostname or '').lower()
    if (parts.scheme != 'https' or host not in ALLOWED_HOSTS or port not in (None, 443) or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment or '?' in url or '#' in url
            or '\\' in url or any(ord(c) < 33 or ord(c) > 126 for c in url)):
        raise _refuse()
    return parts, host


def check_url(url: str) -> str:
    """The host of one of the two fixed catalog URLs; anything else raises PT-KEV-CONSENT."""
    _, host = _parts(url)
    if url not in limits.SOURCE_URLS.values():
        raise _refuse()
    return host


@dataclass(frozen=True)
class KevConsent:
    """What the analyst confirmed: the exact URL of one displayed plan. Nothing is remembered."""

    urls: frozenset[str]

    @classmethod
    def from_plan(cls, plan: KevPlan) -> KevConsent:
        check_url(plan.url)
        return cls(frozenset({plan.url}))

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset(url.split('/')[2] for url in self.urls)

    def check_redirect(self, url: str) -> None:
        """A redirect target must satisfy the allowlist and stay on a consented host."""
        _, host = _parts(url)
        if host not in self.hosts:
            raise _refuse('the server redirected to a host you did not confirm')


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
        # read1 returns what one socket read delivered instead of waiting for a full buffer.
        return getattr(self._raw, 'read1', self._raw.read)(size)

    def abort(self) -> None:
        """Wake a read blocked in another thread. Best effort: closing alone does not interrupt recv."""
        sock = getattr(getattr(getattr(self._raw, 'fp', None), 'raw', None), '_sock', None)
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._raw.close()
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        self._raw.close()


def build_director() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores HTTPS_PROXY/ALL_PROXY: an environment proxy would otherwise observe that an analyst
    # is reading the KEV catalog.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def urllib_open(url: str, headers: Mapping[str, str], timeout: float):
    request = urllib.request.Request(url, headers=dict(headers), method='GET')
    try:
        return _Response(build_director().open(request, timeout=timeout))
    except urllib.error.HTTPError as exc:
        return _Response(exc)
    except (ValueError, http.client.HTTPException):
        raise ConnectionError('invalid request') from None
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


class _Retry(Exception):
    def __init__(self, wait: float | None):
        self.wait = wait


class KevTransport:
    """One bounded GET of the plan's URL. Every collaborator is injectable so tests never touch a socket."""

    def __init__(self, consent: KevConsent, *, opener: Callable = urllib_open, cancel: threading.Event | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float, threading.Event | None], None] = default_sleep,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC),
                 announce: Callable[[str], None] | None = None) -> None:
        self.consent, self.opener, self.cancel = consent, opener, cancel
        self.clock, self.sleep, self.now, self.announce = clock, sleep, now, announce
        self.requests: list[str] = []

    def _cancelled(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise KevError('PT-KEV-CANCEL', 'the download was cancelled')

    def fetch(self, plan: KevPlan) -> Fetched:
        if plan.url not in self.consent.urls:
            raise _refuse('the confirmed request does not cover this download')
        check_url(plan.url)
        self._cancelled()
        plan_deadline = self.clock() + limits.PLAN_TIMEOUT_S
        for attempt in range(1, limits.MAX_ATTEMPTS + 1):
            self._cancelled()
            try:
                return self._attempt(plan.url, plan_deadline)
            except _Retry as retry:
                if attempt == limits.MAX_ATTEMPTS:
                    raise KevError('PT-KEV-NETWORK', 'the connection failed or timed out') from None
                wait = float(2 ** (attempt - 1)) if retry.wait is None else retry.wait
                if wait > limits.RETRY_AFTER_MAX_S or self.clock() + wait >= plan_deadline:
                    raise KevError('PT-KEV-NETWORK', 'the server asked to retry later than allowed') from None
                self.sleep(wait, self.cancel)
        raise AssertionError('unreachable')

    def _open(self, url: str, timeout: float):
        headers = {'Accept': ACCEPT, 'User-Agent': USER_AGENT}
        try:
            return interruptible(partial(self.opener, url, headers, timeout), self.cancel,
                                 cleanup=lambda r: r.close())
        except Cancelled:
            raise KevError('PT-KEV-CANCEL', 'the download was cancelled') from None
        except TooManyAbandoned:
            raise KevError('PT-KEV-NETWORK', 'earlier requests are still closing') from None
        except TimeoutError:
            raise _Retry(None) from None
        except (OSError, http.client.HTTPException):
            raise KevError('PT-KEV-NETWORK', 'the connection failed or timed out') from None

    def _attempt(self, url: str, plan_deadline: float) -> Fetched:
        deadline = min(self.clock() + limits.REQUEST_TIMEOUT_S, plan_deadline)
        current = url
        for _hop in range(limits.MAX_REDIRECTS + 1):
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise KevError('PT-KEV-NETWORK', 'the connection failed or timed out')
            if self.announce is not None:
                self.announce(f'GET {current}')
            self.requests.append(current)
            response = self._open(current, min(float(limits.CONNECT_TIMEOUT_S), remaining))
            try:
                status = response.status
                if status in REDIRECT_STATUS:
                    location = response.headers.get('Location')
                    if not location:
                        raise KevError('PT-KEV-PROVIDER', 'the server sent a redirect without a target')
                    current = urllib.parse.urljoin(current, location)
                    self.consent.check_redirect(current)
                    continue
                if status in RETRYABLE_STATUS:
                    raise _Retry(_retry_after(response.headers.get('Retry-After'), self.now()))
                if status != 200:
                    raise KevError('PT-KEV-PROVIDER', f'the server answered HTTP {status}')
                body = self._read(response, deadline)
                return Fetched(url=url, final_url=current, body=body, sha256=hashlib.sha256(body).hexdigest(),
                               retrieved_at=_stamp(self.now()))
            finally:
                response.close()
        raise KevError('PT-KEV-NETWORK', 'the server redirected too many times')

    def _read(self, response, deadline: float) -> bytes:
        cap = limits.MAX_BYTES
        length = response.headers.get('Content-Length')
        digits = length.strip() if length is not None else ''
        if digits.isascii() and digits.isdigit() and (len(digits) > 18 or int(digits) > cap):
            raise KevError('PT-KEV-LIMIT', 'the file is larger than 16 MiB')
        stop = self._watch(response, deadline)
        try:
            return self._read_chunks(response, cap, deadline)
        finally:
            if stop is not None:
                stop.set()

    def _read_chunks(self, response, cap: int, deadline: float) -> bytes:
        data = bytearray()
        while True:
            self._live(deadline)
            try:
                chunk = response.read(min(_CHUNK, cap + 1 - len(data)))
            # AttributeError: http.client drops its stream on close, so a read racing an abort sees None.
            except (OSError, ValueError, AttributeError, http.client.HTTPException) as exc:
                self._live(deadline)  # an abort by the watcher surfaces here as a read error
                if isinstance(exc, TimeoutError):
                    raise _Retry(None) from None
                raise KevError('PT-KEV-NETWORK', 'the connection failed or timed out') from None
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > cap:
                raise KevError('PT-KEV-LIMIT', 'the file is larger than 16 MiB')

    def _live(self, deadline: float) -> None:
        self._cancelled()
        if self.clock() >= deadline:
            raise KevError('PT-KEV-NETWORK', 'the connection failed or timed out')

    def _watch(self, response, deadline: float) -> threading.Event | None:
        """Abort a read that blocks on a silent or dripping server once cancel or the deadline hits."""
        abort = getattr(response, 'abort', None)
        if abort is None:
            return None
        stop = threading.Event()

        def watch() -> None:
            while not stop.wait(WATCH_INTERVAL):
                if (self.cancel is not None and self.cancel.is_set()) or self.clock() >= deadline:
                    abort()
                    return
        threading.Thread(target=watch, daemon=True, name='kev-read-watch').start()
        return stop
