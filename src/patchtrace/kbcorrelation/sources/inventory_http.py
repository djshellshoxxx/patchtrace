"""PW-01 URL policy and a stdlib HTTPS connection pinned to its validated DNS answer.

No global socket, DNS, proxy or urllib state is changed. Planning and saved-HTML
parsing use only the pure URL functions; DNS happens only in the consented opener.
"""
from __future__ import annotations

import functools
import http.client
import ipaddress
import math
import queue
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from ...acquisition import transport as tr
from .cvrf import SourceError

HOSTS = frozenset({'support.microsoft.com', 'go.microsoft.com', 'download.microsoft.com'})
MAX_URL = 2048
_PERCENT = re.compile(r'%(?![0-9A-Fa-f]{2})')
_ENCODED_UNSAFE = re.compile(r'%(?:0[0-9a-f]|1[0-9a-f]|20|7f|5c)', re.IGNORECASE)
_DNS_SLOTS = threading.BoundedSemaphore(4)
_DNS_POLL = 0.05
_MAX_ADDRESSES = 32
_NAT64 = ipaddress.ip_network('64:ff9b::/96')


def _url_error() -> SourceError:
    return SourceError('PT-KBC-INPUT', 'URL is outside the exact inventory HTTPS policy')


def _reference(value: str) -> None:
    # Check before urlsplit/urljoin: those silently discard leading controls and CR/LF/tab.
    if (type(value) is not str or not value or len(value) > MAX_URL
            or any(not '!' <= char <= '~' for char in value)
            or '\\' in value or '#' in value or _PERCENT.search(value) or _ENCODED_UNSAFE.search(value)):
        raise _url_error()


def validate_url(value: str, *, kind: str) -> str:
    """Return the unchanged, validated URL. This function performs no I/O."""
    _reference(value)
    try:
        parts = urllib.parse.urlsplit(value)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise _url_error() from None
    if (parts.scheme != 'https' or host not in HOSTS or port not in (None, 443)
            or parts.username is not None or parts.password is not None
            or parts.netloc.lower() not in (host, host + ':443') or parts.fragment):
        raise _url_error()
    path = urllib.parse.unquote(parts.path)
    if ('\\' in path or any(part in ('.', '..') for part in path.split('/'))
            or re.search(r'%2f', parts.path, re.IGNORECASE)):
        raise _url_error()
    if kind == 'support-page':
        allowed = host == 'support.microsoft.com'
    elif kind == 'file-inventory':
        allowed = ((host == 'go.microsoft.com' and parts.path in ('/fwlink', '/fwlink/'))
                   or (host == 'download.microsoft.com' and parts.path.startswith('/download/')))
    else:
        raise _url_error()
    if not allowed:
        raise _url_error()
    return value


def resolve_url(current: str, reference: str, *, kind: str) -> str:
    """Resolve one inert href/Location only after checking its original spelling."""
    _reference(reference)
    try:
        result = urllib.parse.urljoin(current, reference)
    except ValueError:
        raise _url_error() from None
    return validate_url(result, kind=kind)


def _remaining(deadline, cancel, clock) -> float:
    if cancel is not None and cancel.is_set():
        raise SourceError('PT-KBC-CANCEL', 'inventory retrieval was cancelled')
    remaining = deadline - clock()
    if remaining <= 0:
        raise TimeoutError('inventory connection timed out')
    return remaining


def _resolve(host, deadline, cancel, clock, resolver):
    """Bound the caller's DNS wait, including cancellation and occupied worker slots.

    libc resolution cannot be interrupted portably. At most four daemon workers
    may outlive a cancelled/timed-out call; a worker only resolves, never connects.
    """
    while not _DNS_SLOTS.acquire(timeout=min(_DNS_POLL, _remaining(deadline, cancel, clock))):
        pass
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            value = resolver(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            result.put((True, value))
        except Exception:
            result.put((False, None))
        finally:
            _DNS_SLOTS.release()

    try:
        _remaining(deadline, cancel, clock)
        threading.Thread(target=resolve, name='patchtrace-inventory-dns', daemon=True).start()
    except BaseException:
        _DNS_SLOTS.release()
        raise
    while True:
        try:
            ok, value = result.get(timeout=min(_DNS_POLL, _remaining(deadline, cancel, clock)))
            _remaining(deadline, cancel, clock)
            if not ok:
                raise ConnectionError('inventory DNS resolution failed')
            return value
        except queue.Empty:
            continue


def _public(ip) -> bool:
    if (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified
            or ip.is_link_local or ip.is_loopback or getattr(ip, 'is_site_local', False)):
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = []
        if ip.ipv4_mapped is not None:
            embedded.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            embedded.append(ip.sixtofour)
        if ip.teredo is not None:
            embedded.extend(ip.teredo)
        if ip in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(ip) & (2**32 - 1)))
        if any(not _public(address) for address in embedded):
            return False
    return True


def _addresses(answers):
    if type(answers) not in (list, tuple) or not answers or len(answers) > _MAX_ADDRESSES:
        raise SourceError('PT-KBC-SOURCE', 'DNS returned an invalid or excessive address set')
    checked = []
    for answer in answers:
        try:
            family, kind, protocol, _name, address = answer
            if (family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM
                    or protocol != socket.IPPROTO_TCP or type(address) is not tuple
                    or len(address) != (2 if family == socket.AF_INET else 4)
                    or type(address[0]) is not str or '%' in address[0] or address[1] != 443
                    or (family == socket.AF_INET6 and address[2:] != (0, 0))):
                raise ValueError
            ip = ipaddress.ip_address(address[0])
            if (ip.version != (4 if family == socket.AF_INET else 6)) or not _public(ip):
                raise ValueError
        except (ValueError, TypeError):
            raise SourceError('PT-KBC-SOURCE', 'DNS returned a non-global or invalid destination') from None
        # Validate the entire set before connecting: mixed public/private answers fail closed.
        checked.append((family, kind, protocol, address))
    return checked


def connect_public(address, timeout, source_address=None, *, resolver=None, socket_factory=None,
                   cancel=None, clock=time.monotonic):
    """Resolve once, validate every result, and connect to that same numeric sockaddr."""
    if (type(address) is not tuple or len(address) != 2 or type(address[0]) is not str
            or address[0].lower() not in HOSTS or address[1] != 443
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10):
        raise SourceError('PT-KBC-INPUT', 'invalid inventory connection request')
    deadline = clock() + timeout
    _remaining(deadline, cancel, clock)
    answers = _addresses(_resolve(address[0].lower(), deadline, cancel, clock, resolver or socket.getaddrinfo))
    factory = socket_factory or socket.socket
    for family, kind, protocol, sockaddr in answers:
        sock = None
        try:
            remaining = _remaining(deadline, cancel, clock)
            sock = factory(family, kind, protocol)
            sock.settimeout(remaining)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect(sockaddr)
            sock.settimeout(_remaining(deadline, cancel, clock))
            return sock
        except OSError:
            if sock is not None:
                sock.close()
            _remaining(deadline, cancel, clock)
        except BaseException:
            if sock is not None:
                sock.close()
            raise
    raise ConnectionError('inventory connection failed')


class _GuardedResponse(http.client.HTTPResponse):
    def __init__(self, *args, guard, idle, **kwargs):
        super().__init__(*args, **kwargs)
        raw = getattr(self.fp, 'raw', None)
        sock = getattr(raw, '_sock', None)
        if sock is not None:
            # Install before HTTPResponse.begin reads status and headers. Slow header
            # drips must obey the same total deadline as subsequent body reads.
            raw._sock = tr._SlicedSocket(sock, guard, idle)


class PublicHTTPSConnection(http.client.HTTPSConnection):
    """Normal hostname-verified TLS over a DNS-validated, pinned TCP connection."""
    def __init__(self, host, *, timeout=10, context=None, resolver=None, socket_factory=None,
                 cancel=None, clock=time.monotonic, deadline=None, **kwargs):
        context = context if context is not None else ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise SourceError('PT-KBC-INPUT', 'inventory HTTPS requires certificate and hostname validation')
        super().__init__(host, timeout=timeout, context=context, **kwargs)
        self._cancel, self._clock = cancel, clock
        self._read_deadline = deadline if deadline is not None else clock() + timeout
        self._create_connection = functools.partial(connect_public, resolver=resolver, socket_factory=socket_factory,
                                                   cancel=cancel, clock=clock)
        self.response_class = functools.partial(_GuardedResponse, guard=self._guard, idle=timeout)

    def _guard(self):
        _remaining(self._read_deadline, self._cancel, self._clock)

    def connect(self):
        if self._tunnel_host:
            raise SourceError('PT-KBC-SOURCE', 'inventory HTTPS does not permit proxy tunnels')
        deadline = min(self._read_deadline, self._clock() + self.timeout)
        self.timeout = min(self.timeout, _remaining(deadline, self._cancel, self._clock))
        try:
            super().connect()  # HTTPSConnection wraps using server_hostname=self.host.
            self.sock.settimeout(min(self.timeout, _remaining(deadline, self._cancel, self._clock)))
        except BaseException:
            self.close()
            raise


def urllib_open(method, url, headers, timeout, *, kind, cancel=None, clock=time.monotonic, deadline=None):
    """Consented production opener: no proxy inheritance or automatic redirect follow-up."""
    validate_url(url, kind=kind)
    if method != 'GET':
        raise SourceError('PT-KBC-INPUT', 'inventory retrieval only permits GET')
    connection = functools.partial(PublicHTTPSConnection, cancel=cancel, clock=clock, deadline=deadline)

    class Handler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(connection, req, context=self._context)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), tr._NoRedirect(), Handler())
    try:
        response = opener.open(urllib.request.Request(url, headers=dict(headers), method=method), timeout=timeout)
        return tr._Response(response, timeout)
    except urllib.error.HTTPError as exc:
        return tr._Response(exc, timeout)
    except (ValueError, http.client.HTTPException):
        raise ConnectionError('invalid inventory request') from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError('inventory request timed out') from None
        raise ConnectionError('inventory connection failed') from None
