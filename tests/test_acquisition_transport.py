"""SPEC-08 §4 transport with a fake opener: no live network."""
from __future__ import annotations

import hashlib
import threading
import urllib.request

import pytest

from patchtrace.acquisition import transport as tr
from patchtrace.acquisition.contracts import AcquisitionError, PlannedDownload

NAME = 'afd.sys'
URL = 'https://msdl.microsoft.com/download/symbols/afd.sys/D37888A1b2000/afd.sys'
META = 'https://winbindex.m417z.com/data/by_filename_compressed/afd.sys.json.gz'
BLOB = 'https://msdlstore.blob.core.windows.net/x/afd.sys?sv=1&sig=SECRET'
BODY = b'MZ' + b'\0' * 98


class Resp:
    def __init__(self, status=200, body=b'', headers=None):
        self.status, self.headers, self._body, self.closed = status, headers or {}, body, False

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        self.closed = True


class Opener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self, method, url, headers, timeout):
        with self.lock:
            self.calls.append((method, url, dict(headers)))
            item = self.responses.pop(0) if not callable(self.responses[0]) else self.responses[0]
        if callable(item):
            item = item(method, url)
        if isinstance(item, BaseException):
            raise item
        return item


def make(opener, **kw):
    sleeps = []
    return tr.Transport(opener=opener, sleep=lambda s, c: sleeps.append(s), **kw), sleeps


def planned(body=BODY, url=URL, size=None, sha=None):
    return PlannedDownload(side='older', file_name=NAME, sha256=sha or hashlib.sha256(body).hexdigest(),
                           size=len(body) if size is None else size, url=url, record_sha256='0' * 64)


def consent(*urls):
    return tr.AcquisitionConsent.for_urls(urls)


def test_download_follows_one_redirect_to_blob_and_verifies(tmp_path):
    opener = Opener(Resp(302, headers={'Location': BLOB}), Resp(200, BODY))
    t, _ = make(opener)
    got = t.download(planned(), consent(URL), tmp_path)
    assert got.path.read_bytes() == BODY and got.redirect_host == 'msdlstore.blob.core.windows.net'
    assert got.sha256 == hashlib.sha256(BODY).hexdigest() and got.source_url == URL
    assert [c[:2] for c in opener.calls] == [('GET', URL), ('GET', BLOB)]
    assert all(c[2] == {'User-Agent': 'PatchTrace'} for c in opener.calls)
    # The signed blob URL is never retained in the result.
    assert 'SECRET' not in repr(got)


@pytest.mark.parametrize('location', [
    'http://msdlstore.blob.core.windows.net/x',          # not HTTPS
    'https://evil.example/x',                             # not allowlisted
    'https://blob.core.windows.net.evil.example/x',       # suffix trick
    'https://.blob.core.windows.net/x',
    'https://u:p@msdlstore.blob.core.windows.net/x',      # credentials
    'https://msdlstore.blob.core.windows.net:8443/x',     # port
    'https://msdl.microsoft.com/other',                   # redirect only to blob host
])
def test_redirect_outside_blob_allowlist_refused(tmp_path, location):
    opener = Opener(Resp(302, headers={'Location': location}))
    t, _ = make(opener)
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-NETWORK' and len(opener.calls) == 1
    assert list(tmp_path.iterdir()) == []


def test_second_redirect_refused(tmp_path):
    opener = Opener(Resp(302, headers={'Location': BLOB}), Resp(302, headers={'Location': BLOB}))
    t, _ = make(opener)
    with pytest.raises(AcquisitionError, match='more than one redirect'):
        t.download(planned(), consent(URL), tmp_path)


def test_404_means_not_on_symbol_server(tmp_path):
    t, _ = make(Opener(Resp(404)))
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-NOTFOUND' and 'not on the symbol server' in err.value.message


def test_hash_and_size_mismatch_rejected_and_file_removed(tmp_path):
    t, _ = make(Opener(Resp(302, headers={'Location': BLOB}), Resp(200, BODY)))
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(sha='a' * 64), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-VERIFY' and list(tmp_path.iterdir()) == []
    t, _ = make(Opener(Resp(302, headers={'Location': BLOB}), Resp(200, BODY[:-1])))
    with pytest.raises(AcquisitionError, match='size'):
        t.download(planned(), consent(URL), tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_body_larger_than_plan_is_cut_off_while_streaming(tmp_path):
    t, _ = make(Opener(Resp(302, headers={'Location': BLOB}), Resp(200, BODY + b'x' * 10)))
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-LIMIT'
    t, _ = make(Opener(Resp(302, headers={'Location': BLOB}),
                       Resp(200, BODY, headers={'Content-Length': str(10**10)})))
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-LIMIT'


def test_consent_must_name_exact_url(tmp_path):
    opener = Opener(Resp(200, BODY))
    t, _ = make(opener)
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL.replace('b2000', 'b3000')), tmp_path)
    assert err.value.code == 'PT-ACQ-CONFIG' and opener.calls == []
    with pytest.raises(AcquisitionError):
        t.download(planned(), tr.AcquisitionConsent(frozenset(), frozenset({URL})), tmp_path)
    with pytest.raises(AcquisitionError):
        t.fetch_metadata(NAME, consent(URL))
    assert opener.calls == []


def test_retries_honour_retry_after_and_cap(tmp_path):
    opener = Opener(Resp(503, headers={'Retry-After': '7'}), Resp(302, headers={'Location': BLOB}),
                    Resp(200, BODY))
    t, sleeps = make(opener)
    t.download(planned(), consent(URL), tmp_path)
    assert sleeps == [7.0]
    # A retry re-requests msdl: the expired signed blob URL is never reused.
    assert [c[1] for c in opener.calls] == [URL, URL, BLOB]
    t, _ = make(Opener(Resp(429, headers={'Retry-After': '61'})))
    with pytest.raises(AcquisitionError, match='60 s'):
        t.download(planned(), consent(URL), tmp_path)
    t, sleeps = make(Opener(Resp(500), Resp(500), Resp(500)))
    with pytest.raises(AcquisitionError, match='after retries'):
        t.download(planned(), consent(URL), tmp_path)
    assert sleeps == [1.0, 2.0]


def test_cancellation_before_and_during_sleep(tmp_path):
    cancel = threading.Event()
    cancel.set()
    opener = Opener(Resp(200, BODY))
    t, _ = make(opener, cancel=cancel)
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-CANCEL' and opener.calls == []
    cancel = threading.Event()
    t = tr.Transport(opener=Opener(Resp(503, headers={'Retry-After': '30'}), Resp(200, BODY)), cancel=cancel,
                     sleep=lambda s, c: c.set())
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-CANCEL'


def test_default_sleep_is_cancellable():
    cancel = threading.Event()
    cancel.set()
    tr.default_sleep(60, cancel)  # returns immediately


def test_metadata_fetch_cap_404_and_date():
    t, _ = make(Opener(Resp(200, b'gz', headers={'Last-Modified': 'Wed, 30 Sep 2026 10:00:00 GMT'})))
    got = t.fetch_metadata(NAME, consent(META))
    assert got.body == b'gz' and got.data_date == '2026-09-30'
    t, _ = make(Opener(Resp(200, b'gz')))
    undated = t.fetch_metadata(NAME, consent(META))
    assert undated.last_modified is None and undated.data_date == undated.retrieved_at[:10]
    t, _ = make(Opener(Resp(404)))
    with pytest.raises(AcquisitionError) as err:
        t.fetch_metadata(NAME, consent(META))
    assert err.value.code == 'PT-ACQ-NOTFOUND'
    t, _ = make(Opener(Resp(302, headers={'Location': BLOB})))
    with pytest.raises(AcquisitionError, match='redirect'):
        t.fetch_metadata(NAME, consent(META))
    t, _ = make(Opener(Resp(200, b'x', headers={'Content-Length': str(65 * 1024 * 1024)})))
    with pytest.raises(AcquisitionError) as err:
        t.fetch_metadata(NAME, consent(META))
    assert err.value.code == 'PT-ACQ-LIMIT'


def test_probe_semantics_and_exactly_one_valid():
    urls = [URL.replace('b2000', f'b{n}000') for n in range(2, 7)]
    valid = urls[2]
    seen = []

    def answer(method, url):
        seen.append(method)
        return Resp(302 if url == valid else 404)
    t, _ = make(Opener(answer))
    assert t.resolve(urls, consent(*urls)) == valid and set(seen) == {'HEAD'}
    t, _ = make(Opener(lambda m, u: Resp(302)))
    with pytest.raises(AcquisitionError, match='ambiguous'):
        t.resolve(urls, consent(*urls))
    t, _ = make(Opener(lambda m, u: Resp(404)))
    with pytest.raises(AcquisitionError) as err:
        t.resolve(urls, consent(*urls))
    assert err.value.code == 'PT-ACQ-NOTFOUND'
    t, _ = make(Opener(lambda m, u: Resp(200)))
    with pytest.raises(AcquisitionError) as err:
        t.resolve(urls, consent(*urls))
    assert err.value.code == 'PT-ACQ-PROVIDER'
    with pytest.raises(AcquisitionError):
        t.resolve(urls, consent(*urls[:-1]))


def test_probe_concurrency_is_bounded():
    active, peak, lock = [0], [0], threading.Lock()
    gate = threading.Barrier(tr.MAX_CONCURRENT_PROBES, timeout=5)

    def answer(method, url):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            gate.wait()
        except threading.BrokenBarrierError:
            pass
        with lock:
            active[0] -= 1
        return Resp(404)
    urls = [URL.replace('b2000', f'{n:x}000') for n in range(16, 32)]
    t, _ = make(Opener(answer))
    with pytest.raises(AcquisitionError):
        t.resolve(urls, consent(*urls))
    assert peak[0] == tr.MAX_CONCURRENT_PROBES


def test_default_opener_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:8080')
    built = []

    def spy(*handlers):
        built.append(handlers)
        raise ConnectionError('stop before network')
    monkeypatch.setattr(urllib.request, 'build_opener', spy)
    with pytest.raises(ConnectionError):
        tr.urllib_open('GET', URL, {}, 1)
    proxies = [h for h in built[0] if isinstance(h, urllib.request.ProxyHandler)]
    assert proxies and proxies[0].proxies == {}
    assert any(isinstance(h, tr._NoRedirect) for h in built[0])


def test_connection_errors_and_timeouts(tmp_path):
    t, sleeps = make(Opener(TimeoutError(), Resp(302, headers={'Location': BLOB}), Resp(200, BODY)))
    t.download(planned(), consent(URL), tmp_path)
    assert sleeps == [1.0]
    t, _ = make(Opener(ConnectionError()))
    with pytest.raises(AcquisitionError) as err:
        t.download(planned(), consent(URL), tmp_path)
    assert err.value.code == 'PT-ACQ-NETWORK'


def test_download_reports_monotonic_byte_progress_ending_at_total(tmp_path, monkeypatch):
    monkeypatch.setattr(tr, '_CHUNK', 10)
    body = bytes(range(250)) * 2
    t, _ = make(Opener(Resp(200, body)))
    seen = []
    got = t.download(planned(body), consent(URL), tmp_path, lambda done, total: seen.append((done, total)))
    assert got.size == len(body)
    assert seen[0] == (0, len(body)) and seen[-1] == (len(body), len(body))
    assert [d for d, _ in seen] == sorted(d for d, _ in seen) and {t for _, t in seen} == {len(body)}


def test_progress_restarts_at_zero_on_retry_and_is_optional(tmp_path):
    t, sleeps = make(Opener(Resp(503), Resp(200, BODY)))
    seen = []
    t.download(planned(), consent(URL), tmp_path, lambda done, total: seen.append(done))
    assert seen[0] == 0 and seen[-1] == len(BODY) and sleeps
    t2, _ = make(Opener(Resp(200, BODY)))
    assert t2.download(planned(), consent(URL), tmp_path / '.', None).size == len(BODY)


def test_retry_after_and_content_length_hostile_digits_are_ignored(tmp_path):
    from datetime import UTC, datetime
    now = datetime.now(UTC)
    assert tr._retry_after('9' * 5000, now) is None
    assert tr._retry_after('²', now) is None
    t, _ = make(Opener(Resp(200, BODY, headers={'Content-Length': '²'})))
    assert t.download(planned(), consent(URL), tmp_path).size == len(BODY)


def test_download_has_a_total_deadline(tmp_path):
    ticks = iter(range(0, 10 ** 6, 4000))
    t, _ = make(Opener(Resp(200, BODY)), clock=lambda: next(ticks))
    with pytest.raises(tr.AcquisitionError) as info:
        t.download(planned(), consent(URL), tmp_path)
    assert info.value.recoverable and 'timeout' in str(info.value)


def _drip_server(total: int, gap: float):
    """Loopback HTTP server sending `total` bytes one at a time, `gap` seconds apart."""
    import socket
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            srv.settimeout(0.1)
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n'.encode())
                    for _ in range(total):
                        if stop.wait(gap):
                            break
                        conn.sendall(b'x')
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def close():
        stop.set()
        thread.join(2)
        srv.close()
    return f'http://127.0.0.1:{srv.getsockname()[1]}/drip', close


def test_slow_drip_download_stops_at_the_total_deadline(tmp_path, monkeypatch):
    import time
    local, close = _drip_server(40, 0.2)  # 8 s of dripping against a 1 s deadline
    monkeypatch.setattr(tr, 'DOWNLOAD_DEADLINE', 1.0)
    t, _ = make(lambda method, url, headers, timeout: tr.urllib_open(method, local, headers, timeout))
    started = time.monotonic()
    try:
        with pytest.raises(AcquisitionError) as exc:
            t.download(planned(body=b'x' * 40), consent(URL), tmp_path)
    finally:
        close()
    assert exc.value.code == 'PT-ACQ-NETWORK' and 'timeout' in str(exc.value)
    assert time.monotonic() - started < 4


def test_slow_drip_download_observes_cancel(tmp_path):
    import time
    local, close = _drip_server(40, 0.2)
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    t, _ = make(lambda method, url, headers, timeout: tr.urllib_open(method, local, headers, timeout), cancel=cancel)
    started = time.monotonic()
    try:
        with pytest.raises(AcquisitionError) as exc:
            t.download(planned(body=b'x' * 40), consent(URL), tmp_path)
    finally:
        close()
    assert exc.value.code == 'PT-ACQ-CANCEL' and time.monotonic() - started < 4


def test_http_protocol_error_is_typed_network_error(tmp_path):
    import http.client
    t, _ = make(Opener(http.client.BadStatusLine('NOT-HTTP garbage')))
    with pytest.raises(AcquisitionError) as exc:
        t.download(planned(), consent(URL), tmp_path)
    assert exc.value.code == 'PT-ACQ-NETWORK' and 'garbage' not in str(exc.value)


def test_malformed_redirect_location_is_typed_network_error(tmp_path):
    opener = Opener(Resp(302, headers={'Location': 'https://[x'}))
    t, _ = make(opener)
    with pytest.raises(AcquisitionError) as exc:
        t.download(planned(), consent(URL), tmp_path)
    assert exc.value.code == 'PT-ACQ-NETWORK' and '[x' not in str(exc.value) and len(opener.calls) == 1
