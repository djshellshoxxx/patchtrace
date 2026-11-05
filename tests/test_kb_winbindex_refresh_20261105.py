"""Explicit metadata-only refresh over authored Winbindex responses; no live evidence."""
from __future__ import annotations

import gzip
import hashlib
import json
import threading
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k5_support import record
from test_acquisition_transport import Opener, Resp

from patchtrace.acquisition import transport as tr
from patchtrace.acquisition import winbindex as wb
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.winbindex_fetch import RefreshRequest, build_plan, refresh, render_plan
from patchtrace.kbcorrelation.wiring import WorkspaceFileIndex

pytestmark = pytest.mark.usefixtures('no_sockets')
NAME = 'exampledrv.sys'
NOW = datetime(2099, 2, 15, tzinfo=UTC)
RAW = json.dumps(record()).encode()
GZIP = gzip.compress(RAW, mtime=0)


def request(tmp_path, **changes):
    plan = build_plan(NAME)
    return replace(RefreshRequest(tmp_path / 'workspace', NAME, plan.to_json(), plan.hosts, plan.plan_sha), **changes)


def transport(opener, **kwargs):
    return tr.Transport(opener=opener, now=lambda: NOW, sleep=lambda *_: None, **kwargs)


def test_preview_is_pure_exact_and_contains_all_headers_caps_and_digest(tmp_path):
    plan = build_plan(NAME)
    text = render_plan(plan)
    data = plan.as_dict()
    assert plan.url in text and plan.hosts[0] in text and plan.plan_sha in text
    for name, value in plan.headers:
        assert f'{name}: {value}' in text
    for name in ('max_response_bytes', 'max_decompressed_bytes', 'request_timeout_s', 'total_timeout_s',
                 'attempts', 'retry_after_max_s', 'redirect_policy'):
        assert name in text and str(data[name]) in text
    assert 'third-party' in text.lower() and 'Microsoft' in text
    assert json.loads(plan.to_json()) == data and not (tmp_path / 'workspace').exists()


@pytest.mark.parametrize('compressed', [False, True])
def test_consented_refresh_reuses_real_saved_index_and_preserves_exact_raw_bytes(tmp_path, compressed):
    body = GZIP if compressed else RAW
    opener = Opener(Resp(200, body, {'Last-Modified': 'Thu, 12 Feb 2099 00:00:00 GMT'}))
    asked = request(tmp_path)
    result = refresh(asked, threading.Event(), transport=transport(opener))
    assert result.raw_sha256 == hashlib.sha256(body).hexdigest() and result.raw_bytes == len(body)
    assert result.data_date == result.last_modified == '2099-02-12'
    assert result.date_basis == 'http-last-modified' and result.retrieved_at == '2099-02-15T00:00:00Z'
    assert result.source_kind == 'third-party-index' and result.authenticity == 'tls-allowlisted-host'
    assert (asked.workspace / result.stored_as).read_bytes() == body
    rows, skipped = WorkspaceFileIndex(asked.workspace).rows(NAME, '11-24H2')
    assert rows and result.rows > 0 and skipped == result.skipped
    assert opener.calls == [('GET', build_plan(NAME).url, {'User-Agent': 'PatchTrace'})]


@pytest.mark.parametrize('change', ['offline', 'host', 'digest', 'filename', 'duplicate', 'extra', 'missing',
                                   'bool-cap', 'float-cap', 'oversize', 'nan', 'url'])
def test_invalid_stale_or_unconsented_plan_cannot_request_or_write(tmp_path, change):
    asked, opener = request(tmp_path), Opener()
    if change == 'offline':
        asked = replace(asked, offline=True)
    elif change == 'host':
        asked = replace(asked, consent_hosts=('evil.invalid',))
    elif change == 'digest':
        asked = replace(asked, consent_plan='0' * 64)
    elif change == 'filename':
        asked = replace(asked, file_name='examplenet.sys')
    elif change == 'duplicate':
        asked = replace(asked, plan_json=asked.plan_json[:-1] + ',"file_name":"exampledrv.sys"}')
    elif change == 'oversize':
        asked = replace(asked, plan_json=' ' * 65537)
    else:
        data = json.loads(asked.plan_json)
        if change == 'extra':
            data['extra'] = True
        elif change == 'missing':
            del data['headers']
        elif change == 'bool-cap':
            data['attempts'] = True
        elif change == 'float-cap':
            data['attempts'] = float(data['attempts'])
        elif change == 'nan':
            data['total_timeout_s'] = float('nan')
        else:
            data['url'] += '?private_path=/analyst/project'
        asked = replace(asked, plan_json=json.dumps(data))
    with pytest.raises(SourceError):
        refresh(asked, threading.Event(), transport=transport(opener))
    assert opener.calls == [] and not asked.workspace.exists()


@pytest.mark.parametrize('body', [b'{"bad":true}', b'{"x":1,"x":2}', b'<html>unavailable</html>',
                                  b'{}', gzip.compress(b'{}')])
def test_invalid_response_preserves_saved_record_and_creates_no_private_workspace_files(tmp_path, body):
    asked = request(tmp_path)
    saved = refresh(asked, threading.Event(), transport=transport(Opener(Resp(200, GZIP))))
    before = {p.name: p.read_bytes() for p in (asked.workspace / 'winbindex').iterdir()}
    with pytest.raises(SourceError):
        refresh(asked, threading.Event(), transport=transport(Opener(Resp(200, body))))
    assert {p.name: p.read_bytes() for p in (asked.workspace / 'winbindex').iterdir()} == before
    assert (asked.workspace / saved.stored_as).read_bytes() == GZIP


def test_cancel_before_request_and_after_response_prevents_publication(tmp_path):
    asked, event = request(tmp_path), threading.Event()
    opener = Opener()
    event.set()
    with pytest.raises(SourceError, match='cancel'):
        refresh(asked, event, transport=transport(opener))
    assert opener.calls == [] and not asked.workspace.exists()
    event.clear()
    response = Resp(200, GZIP)
    original_close = response.close
    def close_then_cancel():
        original_close()
        event.set()
    response.close = close_then_cancel
    with pytest.raises(SourceError, match='cancel'):
        refresh(asked, event, transport=transport(Opener(response)))
    assert not asked.workspace.exists() and response.closed


def test_missing_last_modified_is_explicit_retrieval_date_fallback(tmp_path):
    result = refresh(request(tmp_path), threading.Event(), transport=transport(Opener(Resp(200, GZIP))))
    assert result.last_modified is None and result.date_basis == 'retrieved-at'
    assert result.data_date == '2099-02-15'


def test_http_failure_closes_response_without_publishing(tmp_path):
    response = Resp(404)
    with pytest.raises(SourceError):
        refresh(request(tmp_path), threading.Event(), transport=transport(Opener(response)))
    assert response.closed and not (tmp_path / 'workspace').exists()


@pytest.mark.parametrize('changes', [
    {'url': 'https://evil.invalid/metadata'}, {'retrieved_at': '2099-02-30T00:00:00Z'},
    {'retrieved_at': '2099-02-15T00:00:00'}, {'last_modified': '2099-02-30'},
    {'last_modified': '2099-2-12'}, {'last_modified': '2099-02-16'}, {'body': 'not bytes'},
])
def test_response_identity_dates_and_byte_type_fail_before_publication(tmp_path, monkeypatch, changes):
    response = tr.MetadataResponse(GZIP, build_plan(NAME).url, '2099-02-15T00:00:00Z', None)
    monkeypatch.setattr(tr.Transport, 'fetch_metadata', lambda *args: replace(response, **changes))
    with pytest.raises(SourceError):
        refresh(request(tmp_path), threading.Event(), transport=transport(Opener()))
    assert not (tmp_path / 'workspace').exists()


def test_compressed_and_decompressed_caps_are_enforced_before_workspace_write(tmp_path, monkeypatch):
    monkeypatch.setattr(wb, 'MAX_COMPRESSED', 1024)
    response = tr.MetadataResponse(b'x' * 1025, build_plan(NAME).url, '2099-02-15T00:00:00Z', None)
    monkeypatch.setattr(tr.Transport, 'fetch_metadata', lambda *args: response)
    with pytest.raises(SourceError) as error:
        refresh(request(tmp_path), threading.Event(), transport=transport(Opener()))
    assert error.value.code == 'PT-KBC-LIMIT' and not (tmp_path / 'workspace').exists()
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', 64)
    response = replace(response, body=gzip.compress(b' ' * 65))
    with pytest.raises(SourceError) as error:
        refresh(request(tmp_path), threading.Event(), transport=transport(Opener()))
    assert error.value.code == 'PT-KBC-LIMIT' and not (tmp_path / 'workspace').exists()


def test_publication_failure_keeps_prior_bytes_and_cleans_own_source_stage(tmp_path):
    asked = request(tmp_path)
    saved = refresh(asked, threading.Event(), transport=transport(Opener(Resp(200, GZIP))))
    captured = []
    def fail_before_commit(root, source, name, data_date):
        assert source.read_bytes() == GZIP
        captured.append(source)
        raise OSError('authored publication refusal')
    with pytest.raises(SourceError) as error:
        refresh(asked, threading.Event(), transport=transport(Opener(Resp(200, GZIP))), publish=fail_before_commit)
    assert error.value.code == 'PT-KBC-STORAGE'
    assert captured and not captured[0].exists() and not captured[0].parent.exists()
    assert (asked.workspace / saved.stored_as).read_bytes() == GZIP


def test_late_cancel_retains_successful_publication(tmp_path):
    from patchtrace.kbcorrelation.wiring import save_winbindex_record
    asked, event = request(tmp_path), threading.Event()
    def publish_then_cancel(*args):
        result = save_winbindex_record(*args)
        event.set()
        return result
    result = refresh(asked, event, transport=transport(Opener(Resp(200, GZIP))), publish=publish_then_cancel)
    assert event.is_set() and (asked.workspace / result.stored_as).read_bytes() == GZIP
