"""Builder HTTPS policy through urllib's real redirect dispatch, with no sockets."""
from __future__ import annotations

import http.client
import importlib.util
import io
import sys
import urllib.parse
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
START = 'https://vendor.invalid/start'
DATA = b'authored pinned component\n'


def _load(name):
    spec = importlib.util.spec_from_file_location(name + '_https_test', ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = _load('build_backend_bundle')
verifier = _load('verify_backend_pins')


class Body(io.BytesIO):
    def __init__(self, data, *, forbid_read=False):
        super().__init__(data)
        self.forbid_read = forbid_read
        self.read_sizes = []
        self.request_headers = {}

    def read(self, size=-1):
        self.read_sizes.append(size)
        if self.forbid_read:
            raise AssertionError('redirect body must be closed without draining it')
        return super().read(size)


@pytest.fixture
def network(monkeypatch):
    """Replace only HTTP/HTTPS transport; preserve urllib error/redirect processors."""
    routes = {}
    calls = []
    bodies = []

    def respond(request):
        calls.append(request.full_url)
        assert request.full_url in routes, 'unexpected request outside authored schedule'
        status, location, data, forbid_read = routes[request.full_url]
        headers = Message()
        if location is not None:
            headers['Location'] = location
        body = Body(data, forbid_read=forbid_read)
        body.request_headers = {key.lower(): value for key, value in request.header_items()}
        bodies.append(body)
        response = urllib.response.addinfourl(body, headers, request.full_url, status)
        response.msg = 'authored response'
        return response

    class HTTP(urllib.request.HTTPHandler):
        def http_open(self, request):
            return respond(request)

    class HTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return respond(request)

    build = urllib.request.build_opener

    def fake_build(*handlers):
        return build(*handlers, HTTP(), HTTPS())

    monkeypatch.setattr(urllib.request, 'build_opener', fake_build)
    monkeypatch.setattr(urllib.request, '_opener', fake_build())
    return routes, calls, bodies


def perform(caller, target, url=START, limit=128):
    if caller == 'builder':
        builder.download(url, target, limit)
    else:
        verifier._fetch(url, target, limit)


def failure(caller):
    return builder.BundleBuildError if caller == 'builder' else verifier.VerifyError


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_http_redirect_is_refused_before_dispatch(caller, status, network, tmp_path):
    routes, calls, bodies = network
    target = tmp_path / 'component'
    target.write_bytes(b'existing output')
    foreign = 'http://insecure.invalid/component'
    routes.update({START: (status, foreign, b'redirect', False), foreign: (200, None, DATA, False)})
    with pytest.raises(failure(caller)) as caught:
        perform(caller, target)
    if caller == 'builder':
        assert caught.value.code == 'PT-BUNDLE-FETCH'
    assert calls == [START]
    assert target.read_bytes() == b'existing output'
    assert bodies and all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
@pytest.mark.parametrize('location', ['https://[', 'file:///local/component'])
def test_malformed_or_non_network_redirect_is_typed_and_closed(caller, location, network, tmp_path):
    routes, calls, bodies = network
    routes[START] = (302, location, b'redirect', False)
    target = tmp_path / 'component'
    with pytest.raises(failure(caller)):
        perform(caller, target)
    assert calls == [START]
    assert not target.exists()
    assert bodies and all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
@pytest.mark.parametrize(('location', 'final'), [
    ('/component', 'https://vendor.invalid/component'),
    ('//cdn.invalid/component', 'https://cdn.invalid/component'),
    ('https://cdn.invalid/component', 'https://cdn.invalid/component'),
])
def test_valid_https_redirect_preserves_download_bytes(caller, location, final, network, tmp_path):
    routes, calls, bodies = network
    routes.update({START: (302, location, b'redirect', False), final: (200, None, DATA, False)})
    target = tmp_path / 'component'
    perform(caller, target)
    assert calls == [START, final]
    assert target.read_bytes() == DATA
    for url, body in zip(calls, bodies, strict=True):
        assert body.request_headers['host'] == urllib.parse.urlsplit(url).netloc
        assert body.request_headers['user-agent'] == (
            'patchtrace-backend-builder/1' if caller == 'builder' else 'patchtrace-pin-verify/1')
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
def test_redirect_response_is_closed_without_reading_its_body(caller, network, tmp_path):
    routes, calls, bodies = network
    final = 'https://vendor.invalid/component'
    routes.update({START: (302, final, b'', True), final: (200, None, DATA, False)})
    target = tmp_path / 'component'
    perform(caller, target)
    assert calls == [START, final]
    assert target.read_bytes() == DATA
    assert bodies[0].read_sizes == []
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
def test_redirect_limit_is_checked_before_eleventh_followup(caller, network, tmp_path):
    routes, calls, bodies = network
    urls = [f'https://vendor.invalid/{number}' for number in range(13)]
    for first, second in zip(urls, urls[1:], strict=False):
        routes[first] = (302, second, b'redirect', False)
    routes[urls[-1]] = (200, None, DATA, False)
    target = tmp_path / 'component'
    with pytest.raises(failure(caller)):
        perform(caller, target, urls[0])
    assert calls == urls[:11]
    assert not target.exists()
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
def test_error_response_is_closed_and_does_not_change_output(caller, network, tmp_path):
    routes, calls, bodies = network
    routes[START] = (404, None, b'not found', False)
    target = tmp_path / 'component'
    target.write_bytes(b'original')
    with pytest.raises(failure(caller)):
        perform(caller, target)
    assert calls == [START]
    assert target.read_bytes() == b'original'
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
def test_initial_http_url_never_reaches_transport(caller, network, tmp_path):
    _, calls, bodies = network
    with pytest.raises(failure(caller)):
        perform(caller, tmp_path / 'component', 'http://vendor.invalid/component')
    assert calls == bodies == []


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
@pytest.mark.parametrize('redirect', [False, True], ids=['initial', 'redirect'])
@pytest.mark.parametrize('encoded', ['%00', '%09', '%0a', '%0d', '%20', '%7f'])
def test_encoded_authority_controls_are_refused_before_dispatch(caller, redirect, encoded, network, tmp_path):
    routes, calls, bodies = network
    invalid = f'https://bad{encoded}host.invalid/component'
    routes[invalid] = (200, None, DATA, False)
    routes[START] = (302, invalid, b'redirect', False)
    target = tmp_path / 'component'
    target.write_bytes(b'original')
    with pytest.raises(failure(caller)):
        perform(caller, target, START if redirect else invalid)
    assert calls == ([START] if redirect else [])
    assert target.read_bytes() == b'original'
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize(('final', 'same_origin'), [
    ('https://vendor.invalid/component', True),
    ('https://vendor.invalid:444/component', False),
    ('https://cdn.invalid/component', False),
])
def test_redirect_headers_follow_the_target_origin(final, same_origin, network):
    routes, calls, bodies = network
    routes.update({START: (302, final, b'redirect', False), final: (200, None, DATA, False)})
    request = urllib.request.Request(START, headers={
        'User-Agent': 'authored-client', 'Accept-Encoding': 'identity',
        'Authorization': 'authored credential canary', 'Cookie': 'authored cookie canary',
        'Content-Type': 'application/octet-stream', 'Content-Length': '0',
    })
    with verifier.open_https(request) as response:
        assert response.read() == DATA
    assert calls == [START, final]
    headers = bodies[-1].request_headers
    assert headers['host'] == urllib.parse.urlsplit(final).netloc
    assert headers['user-agent'] == 'authored-client'
    assert headers['accept-encoding'] == 'identity'
    assert ('authorization' in headers) is same_origin
    assert ('cookie' in headers) is same_origin
    assert 'content-length' not in headers and 'content-type' not in headers
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize('caller', ['builder', 'verifier'])
def test_transport_invalid_url_is_a_typed_failure(caller, monkeypatch, tmp_path):
    class Reject:
        def open(self, request, timeout):
            raise http.client.InvalidURL('authored invalid request target')

    monkeypatch.setattr(urllib.request, 'build_opener', lambda *handlers: Reject())
    target = tmp_path / 'component'
    target.write_bytes(b'original')
    with pytest.raises(failure(caller)):
        perform(caller, target)
    assert target.read_bytes() == b'original'
