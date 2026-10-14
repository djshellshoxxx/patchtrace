"""Audit C regressions: real-socket slow-drip cancellation, URL hygiene, promote cleanup, name rules."""
from __future__ import annotations

import hashlib
import http.client
import http.server
import threading
import time

import pytest

from patchtrace.acquisition import delta
from patchtrace.acquisition import quarantine as q
from patchtrace.acquisition import transport as tr
from patchtrace.acquisition.contracts import (
    AcquiredArtifact,
    AcquisitionError,
    PlannedDownload,
    Provenance,
    acquisition_id,
    validate_file_name,
)
from patchtrace.sample import synthetic_pe

URL = 'https://msdl.microsoft.com/download/symbols/afd.sys/D37888A1b2000/afd.sys'
SIZE = 4000


class _Drip(http.server.BaseHTTPRequestHandler):
    interval = 0.1
    stall = 0.0

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(SIZE))
        self.end_headers()
        self.wfile.flush()
        stop = self.server.stop
        if self.stall and stop.wait(self.stall):
            return
        try:
            for _ in range(SIZE):
                if stop.wait(self.interval):
                    return
                self.wfile.write(b'x')
                self.wfile.flush()
        except OSError:
            return

    def log_message(self, *args):
        pass


@pytest.fixture
def drip_server():
    servers: list = []

    def start(**attrs):
        handler = type('H', (_Drip,), attrs)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.stop = threading.Event()
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    yield start
    for server in servers:
        server.stop.set()
        server.shutdown()
        server.server_close()


def local_opener(server):
    port = server.server_address[1]

    def opener(method, url, headers, timeout):
        return tr.urllib_open(method, f'http://127.0.0.1:{port}/blob', headers, timeout)
    return opener


def planned():
    return PlannedDownload(side='older', file_name='afd.sys', sha256='0' * 64, size=SIZE, url=URL,
                           record_sha256='0' * 64)


def run_download(transport, directory):
    outcome: dict = {}

    def target():
        try:
            transport.download(planned(), tr.AcquisitionConsent.for_urls([URL]), directory)
        except BaseException as exc:
            outcome['error'] = exc
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, outcome


@pytest.mark.parametrize('stall', [0.0, 30.0], ids=['slow-drip', 'silent-stall'])
def test_cancel_interrupts_slow_response(drip_server, tmp_path, stall):
    server = drip_server(stall=stall)
    cancel = threading.Event()
    thread, outcome = run_download(tr.Transport(opener=local_opener(server), cancel=cancel), tmp_path)
    time.sleep(0.4)
    cancel.set()
    thread.join(5)
    assert not thread.is_alive()
    assert outcome['error'].code == 'PT-ACQ-CANCEL'
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('stall', [0.0, 30.0], ids=['slow-drip', 'silent-stall'])
def test_total_deadline_interrupts_slow_response(drip_server, tmp_path, monkeypatch, stall):
    monkeypatch.setattr(tr, 'DOWNLOAD_DEADLINE', 0.5)
    server = drip_server(stall=stall)
    thread, outcome = run_download(tr.Transport(opener=local_opener(server)), tmp_path)
    thread.join(5)
    assert not thread.is_alive()
    assert outcome['error'].code == 'PT-ACQ-NETWORK'
    assert list(tmp_path.iterdir()) == []


class Resp:
    def __init__(self, status=200, headers=None):
        self.status, self.headers = status, headers or {}

    def read(self, size):
        return b''

    def close(self):
        pass


@pytest.mark.parametrize('location', ['https://x.blob.core.windows.net/a b', 'https://x.blob.core.windows.net/a\x7fb',
                                      'https://x.blob.core.windows.net/aé'],
                         ids=['space', 'del', 'non-ascii'])
def test_redirect_target_with_unsafe_characters_is_refused(tmp_path, location):
    calls = []

    def opener(method, url, headers, timeout):
        calls.append(url)
        return Resp(302, {'Location': location})
    transport = tr.Transport(opener=opener, sleep=lambda s, c: None)
    with pytest.raises(AcquisitionError) as err:
        transport.download(planned(), tr.AcquisitionConsent.for_urls([URL]), tmp_path)
    assert err.value.code == 'PT-ACQ-NETWORK'
    assert calls == [URL]


def test_invalid_url_error_from_http_client_is_typed_and_does_not_echo_the_url():
    with pytest.raises(ConnectionError) as err:
        tr.urllib_open('GET', 'https://msdl.microsoft.com/a b?sig=SECRET', {}, 1.0)
    assert 'SECRET' not in str(err.value)


def test_http_client_error_while_reading_is_typed():
    class Broken(Resp):
        def read(self, size):
            raise http.client.IncompleteRead(b'', 5)
    transport = tr.Transport(opener=lambda *a: Broken(), sleep=lambda s, c: None)
    with pytest.raises(AcquisitionError) as err:
        transport._read(Broken(), lambda chunk: None, 100, 'download')
    assert err.value.code == 'PT-ACQ-NETWORK'


def test_resolve_stops_queued_probes_after_the_first_failure():
    urls = [f'https://msdl.microsoft.com/download/symbols/afd.sys/D37888A1{i:x}/afd.sys' for i in range(24)]
    release, started = threading.Event(), []
    lock = threading.Lock()

    def opener(method, url, headers, timeout):
        with lock:
            started.append(url)
        if url == urls[0]:
            release.wait(5)
        if url == urls[1]:
            release.set()
            raise ConnectionError('boom')
        return Resp(404)
    transport = tr.Transport(opener=opener, sleep=lambda s, c: None)
    with pytest.raises(AcquisitionError):
        transport.resolve(urls, tr.AcquisitionConsent.for_urls(urls))
    assert len(started) <= tr.MAX_CONCURRENT_PROBES + 2


@pytest.mark.parametrize('bad', ['con.dll', 'nul.sys', 'aux.exe', 'com1.dll', 'lpt9.sys', 'prn.drv', 'con.foo.dll',
                                 '.dll', '..sys'])
def test_device_names_and_empty_stems_are_refused(bad):
    with pytest.raises(AcquisitionError):
        validate_file_name(bad)


def test_device_name_lookalikes_are_accepted():
    assert validate_file_name('console.dll') == 'console.dll'
    assert validate_file_name('com10.dll') == 'com10.dll'


def test_acquire_into_reused_side_directory_is_typed(tmp_path):
    (tmp_path / 'older').mkdir()
    plan = PlannedDownload(side='older', file_name='afd.sys', sha256='0' * 64, size=1, url=URL,
                           record_sha256='0' * 64)
    with pytest.raises(AcquisitionError) as err:
        q.acquire(plan, tr.AcquisitionConsent.for_urls([URL]), tmp_path, tr.Transport())
    assert err.value.code == 'PT-ACQ-CONFIG'


def _acquired(tmp_path):
    staging = q.create_staging(tmp_path)
    items = []
    for side, data in (('older', synthetic_pe(0)), ('newer', synthetic_pe(1))):
        folder = staging / side
        folder.mkdir()
        path = folder / 'demo.sys'
        path.write_bytes(data)
        fmt, machine = q.identify(path)
        sha = hashlib.sha256(data).hexdigest()
        items.append(AcquiredArtifact(
            acquisition_id=acquisition_id('demo.sys', sha), side=side, file_name='demo.sys', path=str(path),
            sha256=sha, size=len(data), format=fmt, machine=machine,
            provenance=Provenance(source_url=URL, redirect_host=None, retrieved_at='2026-01-01T00:00:00Z',
                                  winbindex_record_sha256='0' * 64)))
    return items


def test_promote_refuses_a_tampered_staged_file_and_creates_nothing(tmp_path):
    older, newer = _acquired(tmp_path)
    tampered = tmp_path / 'tampered.sys'
    tampered.write_bytes(synthetic_pe(5))
    older = older.model_copy(update={'path': str(tampered)})
    root = tmp_path / 'project'
    with pytest.raises(AcquisitionError) as err:
        q.promote(older, newer, 'demo', root)
    assert err.value.code == 'PT-ACQ-VERIFY'
    assert not root.exists()


def test_promote_failure_after_create_removes_the_project(tmp_path, monkeypatch):
    older, newer = _acquired(tmp_path)
    older = older.model_copy(update={'sha256': '1' * 64})  # the project copy will not match this record
    monkeypatch.setattr(q, '_staged_matches', lambda item: True)
    root = tmp_path / 'project'
    with pytest.raises(AcquisitionError) as err:
        q.promote(older, newer, 'demo', root)
    assert err.value.code == 'PT-ACQ-VERIFY'
    assert not root.exists()


def test_delta_input_cap_is_enforced_before_loading_msdelta(monkeypatch):
    monkeypatch.setattr(delta, 'MAX_DELTA_INPUT', 10)
    with pytest.raises(AcquisitionError) as err:
        delta.apply_raw(b'x' * 11, b'PA30' + b'\0' * 8)
    assert err.value.code == 'PT-ACQ-LIMIT'
