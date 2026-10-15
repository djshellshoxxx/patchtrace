"""Consented HTTPS transport for the CISA KEV catalog (KEV-integration-plan section 7, Transport).

Shape of ``intelligence/csaf/transport.py``, with one flaw not copied (random audit RA-3): that transport reads
``response.read(65536)``, which blocks until the chunk is full, so a server that sends one byte every few seconds never
lets the per-read socket timeout fire and the deadline, checked only between chunks, is never reached. Here every read
is ``read1`` (it returns what has arrived) and cancel, deadline and cap are checked around each one. A server that goes
completely silent is cut by the socket timeout, which is the smaller of 10 s and the time left when the request starts.

One consent allows GET requests for one fixed address and its same-host redirects, nothing else, and is not
remembered. The request is two fixed headers (no cookie, no credential, no project data, no CVE ID), environment proxies
are ignored (a proxy would see which catalog an analyst downloads) and every redirect hop is checked before it is
followed. The body is bytes: the content type is never trusted (the GitHub mirror serves ``text/plain``) and parsing
happens afterwards in ``service``.
"""
from __future__ import annotations

import email.utils
import hashlib
import http.client
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
from .contracts import SOURCE_URLS, KevError, KevPlan, https_host

CONSENT, NETWORK, PROVIDER, LIMIT, CANCEL = ('PT-KEV-CONSENT', 'PT-KEV-NETWORK', 'PT-KEV-PROVIDER', 'PT-KEV-LIMIT',
                                             'PT-KEV-CANCEL')
FIXED_URLS = frozenset(SOURCE_URLS.values())
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_CHUNK = 64 * limits.KIB
_HUGE = 10 ** 12                                   # a number too long to read: above every limit that is compared with it


@dataclass(frozen=True)
class KevConsent:
    """What the person agreed to: the exact addresses of the plan they were shown. One fetch, one consent."""
    urls: frozenset[str]

    def __post_init__(self) -> None:
        if not self.urls or not self.urls <= FIXED_URLS:
            raise KevError(CONSENT, 'consent can only name the fixed CISA catalog addresses')

    @classmethod
    def for_plan(cls, plan: KevPlan) -> KevConsent:
        return cls(frozenset({plan.url}))


def check_request(url: str, consent: KevConsent) -> str:
    """The host of ``url`` when it is exactly an address the consent names (nothing else is ever requested first)."""
    if url not in consent.urls:
        raise KevError(CONSENT, 'the request is not an address the consent names')
    return https_host(url)


def check_redirect(url: str, host: str) -> str:
    """``url`` when it is a plain https address on ``host`` (no port, userinfo, query or fragment), else PROVIDER.
    The grammar of ``https_host`` also keeps the address short enough for ``KevCatalogMeta.final_url``."""
    if https_host(url) != host:
        raise KevError(PROVIDER, 'the server redirected to an address PatchTrace does not use')
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Every 3xx is surfaced so that the transport checks each hop instead of urllib following it.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    """What the transport reads from an HTTP response: urllib's own, or a test double with the same four members."""

    def __init__(self, raw):
        self._raw = raw
        self.status = getattr(raw, 'status', None) or raw.code
        self.headers = raw.headers

    def read1(self, size: int) -> bytes:
        return self._raw.read1(size)

    def close(self) -> None:
        self._raw.close()


def build_director() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores HTTPS_PROXY and ALL_PROXY: an environment proxy would see which catalog is downloaded.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def urllib_open(url: str, headers: Mapping[str, str], timeout: float) -> Response:
    request = urllib.request.Request(url, headers=dict(headers), method='GET')
    try:
        return Response(build_director().open(request, timeout=timeout))
    except urllib.error.HTTPError as exc:
        return Response(exc)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError('timed out') from None
        raise ConnectionError('connection failed') from None


def default_sleep(seconds: float, cancel: threading.Event | None) -> None:
    if cancel is None:
        time.sleep(seconds)
    else:
        cancel.wait(seconds)


def stamp(moment: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ``, the contract's timestamp, from an aware time."""
    if moment.tzinfo is None:
        raise ValueError('a timestamp needs a timezone-aware time')
    return moment.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def _retry_after(value: str | None, now: datetime) -> float | None:
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        return float(int(value)) if len(value) < 10 else float(_HUGE)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return float(max(0, int((when - now).total_seconds()) + 1))


def _declared_length(headers: Mapping[str, str]) -> int | None:
    """The announced body size; ``None`` when the header is absent, not a plain number or overridden by chunking."""
    if headers.get('Transfer-Encoding'):                       # the chunks carry the length; http.client ignores the header
        return None
    value = headers.get('Content-Length')
    digits = value.strip() if isinstance(value, str) else ''
    if not (digits.isascii() and digits.isdigit()):
        return None
    return int(digits) if len(digits) <= 12 else _HUGE


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
    """GET one catalog under one consent. ``opener(url, headers, timeout)`` returns a `Response`-like object; the clock,
    the sleep and ``now`` are parameters so that tests control time. ``announce`` receives ``GET <url>`` before each
    request is sent. Cancellation is observed by ``interruptible``, which refuses to start a call once ``cancel`` is set
    and abandons one in flight, so every connect and every read is a cancellation point."""

    def __init__(self, consent: KevConsent, *, opener: Callable = urllib_open, cancel: threading.Event | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float, threading.Event | None], None] = default_sleep,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC),
                 announce: Callable[[str], None] | None = None, plan_deadline: float = limits.PLAN_TIMEOUT_S):
        self.consent, self.opener, self.cancel = consent, opener, cancel
        self.clock, self.sleep, self.now, self.announce = clock, sleep, now, announce
        self.deadline = clock() + plan_deadline

    def fetch(self, plan: KevPlan) -> Fetched:
        host = check_request(plan.url, self.consent)
        for attempt in range(1, limits.ATTEMPTS + 1):
            try:
                return self._attempt(plan, host)
            except _Retry as retry:
                self._pause(attempt, retry.wait)
        raise AssertionError('unreachable')

    def _pause(self, attempt: int, told: float | None) -> None:
        if attempt == limits.ATTEMPTS:
            raise KevError(NETWORK, f'the server stayed unavailable after {limits.ATTEMPTS} attempts')
        wait = float(2 ** (attempt - 1)) if told is None else told
        if wait > limits.RETRY_AFTER_MAX_S:
            raise KevError(NETWORK, f'the server asked to retry later than {limits.RETRY_AFTER_MAX_S} seconds')
        if self.clock() + wait >= self.deadline:
            raise KevError(NETWORK, 'a retry would exceed the time limit')
        self.sleep(wait, self.cancel)

    def _open(self, url: str, headers: Mapping[str, str], timeout: float):
        try:
            return interruptible(partial(self.opener, url, headers, timeout), self.cancel,
                                 cleanup=lambda late: late.close())
        except Cancelled:
            raise KevError(CANCEL, 'the download was cancelled') from None
        except TooManyAbandoned:
            raise KevError(NETWORK, 'earlier requests are still closing') from None
        except (OSError, http.client.HTTPException):
            raise KevError(NETWORK, 'the connection failed or timed out') from None

    def _attempt(self, plan: KevPlan, host: str) -> Fetched:
        deadline = min(self.clock() + limits.REQUEST_TIMEOUT_S, self.deadline)
        current = plan.url
        for _hop in range(limits.MAX_REDIRECTS + 1):
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise KevError(NETWORK, 'the download did not finish within the time limit')
            if self.announce is not None:
                self.announce(f'GET {current}')
            response = self._open(current, dict(plan.headers), min(limits.CONNECT_TIMEOUT_S, remaining))
            try:
                status = response.status
                if status in REDIRECT_STATUS:
                    current = self._redirect_target(current, response, host)
                    continue
                if status in RETRYABLE_STATUS:
                    raise _Retry(_retry_after(response.headers.get('Retry-After'), self.now()))
                if status != 200:
                    raise KevError(PROVIDER, f'the server answered HTTP {status}')
                encoding = response.headers.get('Content-Encoding') or 'identity'
                if encoding.strip().lower() != 'identity':
                    raise KevError(PROVIDER, 'the server sent an encoded body that PatchTrace did not ask for')
                body = self._read(response, plan.max_bytes, deadline)
                return Fetched(url=plan.url, final_url=current, body=body, sha256=hashlib.sha256(body).hexdigest(),
                               retrieved_at=stamp(self.now()))
            finally:
                response.close()
        raise KevError(PROVIDER, f'more than {limits.MAX_REDIRECTS} redirects refused')

    @staticmethod
    def _redirect_target(current: str, response, host: str) -> str:
        location = response.headers.get('Location')
        if not location:
            raise KevError(PROVIDER, 'the server redirected without giving an address')
        try:
            target = urllib.parse.urljoin(current, location)
        except ValueError:
            raise KevError(PROVIDER, 'the server redirected to an address PatchTrace does not use') from None
        return check_redirect(target, host)

    def _read1(self, response, size: int) -> bytes:
        try:
            return interruptible(partial(response.read1, size), self.cancel)
        except Cancelled:
            raise KevError(CANCEL, 'the download was cancelled') from None
        except TooManyAbandoned:
            raise KevError(NETWORK, 'earlier requests are still closing') from None
        except (OSError, http.client.HTTPException):
            raise KevError(NETWORK, 'the connection failed or timed out') from None

    def _read(self, response, cap: int, deadline: float) -> bytes:
        declared = _declared_length(response.headers)
        if declared is not None and declared > cap:
            raise KevError(LIMIT, f'the file is larger than {cap // limits.MIB} MiB')
        data = bytearray()
        while declared is None or len(data) < declared:           # all announced bytes in: do not wait for the close
            if self.clock() >= deadline:                          # ``interruptible`` observes cancel before each read
                raise KevError(NETWORK, 'the download did not finish within the time limit')
            chunk = self._read1(response, min(_CHUNK, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > cap:
                raise KevError(LIMIT, f'the file is larger than {cap // limits.MIB} MiB')
        if declared is not None and len(data) != declared:       # read1 reports a short body as a clean end of file
            raise KevError(NETWORK, 'the download does not match the size the server announced')
        return bytes(data)
