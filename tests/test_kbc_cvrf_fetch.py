"""K6: consented CVRF sync (KB-integration-plan 6 "consent drift", 8.1 `kb index sync`). A fake opener stands in for the
network: no socket is ever opened, so none of this is live evidence (the MSRC URL shape stays unverified until L1)."""
from __future__ import annotations

import gzip
import json
import threading
from datetime import UTC, datetime

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401

from patchtrace.kbcorrelation import cli_online
from patchtrace.kbcorrelation.cli_index import IndexPorts
from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources import net_plan
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.cvrf_fetch import fetch_months, to_imported
from patchtrace.kbcorrelation.sources.importer import import_bytes

pytestmark = pytest.mark.usefixtures('no_sockets')
HOST = 'api.msrc.microsoft.com'
FEB = f'https://{HOST}/cvrf/v3.0/cvrf/2099-Feb?api-version=2023-11-01'
MAR = f'https://{HOST}/cvrf/v3.0/cvrf/2099-Mar?api-version=2023-11-01'
JAN = f'https://{HOST}/cvrf/v3.0/cvrf/2099-Jan?api-version=2023-11-01'
BODY = h.fixture_path('cvrf-2099-Feb.json').read_bytes()
NOW = '2099-02-15T00:00:00Z'


class Resp:
    def __init__(self, status=200, body=b'', headers=None, on_read=None):
        self.status, self.headers, self._body, self.closed, self._on_read = status, headers or {}, body, False, on_read

    def read(self, size):
        if self._on_read:
            self._on_read()
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        self.closed = True


class Opener:
    """Answers by URL; a list is consumed in order, the last item repeats."""

    def __init__(self, routes):
        self.routes = {url: (list(v) if isinstance(v, list) else [v]) for url, v in routes.items()}
        self.calls = []

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url, dict(headers)))
        queue = self.routes.get(url, [Resp(404)])
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        return item() if callable(item) else item


class Clock:
    def now_utc(self):
        return NOW


def feb_plan(**kw):
    return net_plan.build_plan(['2099-Feb'], **kw)


def go(plan, opener, *, hosts=(HOST,), sha=None, sleeps=None, **kw):
    sleeps = [] if sleeps is None else sleeps
    return list(fetch_months(plan, consent_hosts=hosts, consent_plan=sha or plan.plan_sha, opener=opener,
                             sleep=lambda s, c: sleeps.append(s), now=lambda: datetime(2099, 2, 15, tzinfo=UTC), **kw))


# ------------------------------------------------------------------------------------------ consent

@pytest.mark.parametrize('hosts, sha, message', [
    ((), None, 'exactly'), (('evil.example',), None, 'exactly'), ((HOST, 'evil.example'), None, 'exactly'),
    ((HOST,), '0' * 64, 'different plan'),
], ids=['no-host', 'wrong-host', 'extra-host', 'wrong-digest'])
def test_consent_must_equal_plan_and_nothing_is_requested(hosts, sha, message):
    opener = Opener({FEB: Resp(200, BODY)})
    with pytest.raises(SourceError) as err:
        go(feb_plan(), opener, hosts=hosts, sha=sha)
    assert err.value.code == 'PT-KBC-CONSENT' and message in err.value.message
    assert opener.calls == []


def test_consent_binds_plan_sha_to_the_months():
    old, new = feb_plan(), net_plan.build_plan(['2099-Feb', '2099-Mar'])
    with pytest.raises(SourceError) as err:
        go(new, Opener({}), sha=old.plan_sha)
    assert err.value.code == 'PT-KBC-CONSENT'


def test_offline_refuses_even_with_full_consent():
    opener = Opener({FEB: Resp(200, BODY)})
    with pytest.raises(SourceError) as err:
        go(feb_plan(), opener, offline=True)
    assert err.value.code == 'PT-KBC-INPUT' and opener.calls == []


def test_forged_plan_is_refused():
    plan = feb_plan()
    forged = net_plan.IndexPlan.model_construct(**{**dict(plan), 'requests': (
        plan.requests[0].model_copy(update={'url': 'https://evil.example/cvrf/v3.0/cvrf/2099-Feb'}),)})
    opener = Opener({})
    with pytest.raises(SourceError) as err:
        go(forged, opener)
    assert err.value.code == 'PT-KBC-UNSUPPORTED' and opener.calls == []


def test_index_request_cannot_be_synced():
    with pytest.raises(SourceError) as err:
        go(net_plan.build_plan(['2099-Feb'], include_index=True), Opener({}))
    assert err.value.code == 'PT-KBC-CONSENT'  # a plan with the discovery request is not the one built for months


# ------------------------------------------------------------------------------------------ fetching

def test_fetch_sends_accept_and_marks_the_document_fetched():
    opener = Opener({FEB: Resp(200, BODY)})
    (result,) = go(feb_plan(), opener)
    assert result.state == 'fetched' and result.document.raw == BODY
    assert opener.calls[0][0] == 'GET' and opener.calls[0][2]['Accept'] == 'application/json'
    doc = to_imported(result.document)
    local = import_bytes(BODY, now=NOW)
    assert doc.source.origin == 'https-fetch' and doc.source.uri == FEB
    assert doc.source.authenticity == 'tls-allowlisted-host'
    assert doc.doc_id == local.doc_id and doc.edges == local.edges  # same bytes, one document


def test_gzip_body_is_unpacked_to_the_exact_bytes():
    (result,) = go(feb_plan(), Opener({FEB: Resp(200, gzip.compress(BODY))}))
    assert result.document.raw == BODY


def test_wrong_month_served_is_rejected():
    opener = Opener({MAR: Resp(200, BODY)})
    (result,) = go(net_plan.build_plan(['2099-Mar']), opener)
    with pytest.raises(SourceError) as err:
        to_imported(result.document)
    assert err.value.code == 'PT-KBC-SOURCE' and '2099-Mar' in err.value.message


def test_garbage_is_rejected_like_a_local_import():
    (result,) = go(feb_plan(), Opener({FEB: Resp(200, b'<html>sign in</html>')}))
    with pytest.raises(SourceError):
        to_imported(result.document)


def test_404_is_not_published_and_other_months_are_still_tried():
    plan = net_plan.build_plan(['2099-Feb', '2099-Mar'])
    results = go(plan, Opener({FEB: Resp(200, BODY), MAR: Resp(404)}))
    assert [(r.month, r.state) for r in results] == [('2099-Feb', 'fetched'), ('2099-Mar', 'not-published')]


@pytest.mark.parametrize('status', [429, 500, 503], ids=['429', '500', '503'])
def test_retryable_status_honours_retry_after_then_succeeds(status):
    opener = Opener({FEB: [Resp(status, headers={'Retry-After': '7'}), Resp(200, BODY)]})
    sleeps = []
    (result,) = go(feb_plan(), opener, sleeps=sleeps)
    assert result.state == 'fetched' and sleeps == [7.0] and len(opener.calls) == 2


def test_retries_are_bounded_and_failure_is_partial_not_fatal():
    plan = net_plan.build_plan(['2099-Feb', '2099-Mar'])
    opener = Opener({FEB: Resp(503), MAR: Resp(200, BODY)})
    sleeps = []
    results = go(plan, opener, sleeps=sleeps)
    assert [r.state for r in results] == ['failed', 'fetched']
    assert results[0].error.code == 'PT-KBC-ACQUIRE' and sleeps == [1.0, 2.0]
    assert [c[1] for c in opener.calls].count(FEB) == 3


def test_retry_after_beyond_the_cap_is_not_waited_for():
    sleeps = []
    (result,) = go(feb_plan(), Opener({FEB: Resp(429, headers={'Retry-After': '61'})}), sleeps=sleeps)
    assert result.state == 'failed' and sleeps == []


def test_connection_error_is_a_failed_month():
    def refuse(method, url, headers, timeout):
        raise ConnectionError('connection failed')
    (result,) = go(feb_plan(), refuse)
    assert result.state == 'failed' and result.error.code == 'PT-KBC-ACQUIRE'


# ------------------------------------------------------------------------------------------ size cap

LIMITS = KbcLimits(cvrf_doc_bytes=1024)


def test_declared_oversize_is_refused_before_reading():
    plan = net_plan.build_plan(['2099-Feb'], limits=LIMITS)
    (result,) = go(plan, Opener({FEB: Resp(200, b'{}', headers={'Content-Length': '1025'})}), limits=LIMITS)
    assert result.state == 'failed' and result.error.code == 'PT-KBC-LIMIT'


def test_streamed_oversize_is_refused_without_content_length():
    plan = net_plan.build_plan(['2099-Feb'], limits=LIMITS)
    (result,) = go(plan, Opener({FEB: Resp(200, b'x' * 5000)}), limits=LIMITS)
    assert result.error.code == 'PT-KBC-LIMIT'


def test_default_cap_is_32_mib():
    assert feb_plan().caps.max_bytes_per_document == 32 * 1024 * 1024
    (result,) = go(feb_plan(), Opener({FEB: Resp(200, b'{}', headers={'Content-Length': str(32 * 1024 ** 2 + 1)})}))
    assert result.error.code == 'PT-KBC-LIMIT'


# ------------------------------------------------------------------------------------------ redirects

@pytest.mark.parametrize('location', [
    'https://evil.example/cvrf/x', 'http://api.msrc.microsoft.com/cvrf/x',
    'https://user:pw@api.msrc.microsoft.com/cvrf/x', 'https://api.msrc.microsoft.com:8443/cvrf/x',
    'https://api.msrc.microsoft.com.evil.example/x', 'https://api.msrc.microsoft.com/a b', '', None],
    ids=['other-host', 'http', 'userinfo', 'port', 'suffix-trick', 'space', 'empty', 'missing'])
def test_hostile_redirect_is_refused_and_never_followed(location):
    headers = {} if location is None else {'Location': location}
    evil = Opener({FEB: Resp(302, headers=headers)})
    (result,) = go(feb_plan(), evil)
    assert result.state == 'failed' and result.error.code == 'PT-KBC-SOURCE'
    assert [c[1] for c in evil.calls] == [FEB]


def test_same_host_redirect_is_followed_and_loops_are_bounded():
    target = f'https://{HOST}/cvrf/v3.0/document/2099-Feb'
    opener = Opener({FEB: Resp(301, headers={'Location': target}), target: Resp(200, BODY)})
    (result,) = go(feb_plan(), opener)
    assert result.state == 'fetched' and [c[1] for c in opener.calls] == [FEB, target]
    loop = Opener({FEB: Resp(302, headers={'Location': FEB})})
    (looped,) = go(feb_plan(), loop)
    assert looped.state == 'failed' and len(loop.calls) == 4  # the request plus max_redirects (3)


# ------------------------------------------------------------------------------------------ cancel

def test_cancel_before_a_request_stops_the_generator():
    cancel = threading.Event()
    plan = net_plan.build_plan(['2099-Feb', '2099-Mar'])
    opener = Opener({FEB: Resp(200, BODY), MAR: Resp(200, BODY)})
    stream = fetch_months(plan, consent_hosts=[HOST], consent_plan=plan.plan_sha, opener=opener, cancel=cancel)
    assert next(stream).state == 'fetched'
    cancel.set()
    with pytest.raises(SourceError) as err:
        next(stream)
    assert err.value.code == 'PT-KBC-CANCEL' and len(opener.calls) == 1


def test_cancel_during_a_read_stops_at_the_next_chunk():
    cancel = threading.Event()
    opener = Opener({FEB: Resp(200, BODY, on_read=cancel.set)})
    with pytest.raises(SourceError) as err:
        go(feb_plan(), opener, cancel=cancel)
    assert err.value.code == 'PT-KBC-CANCEL'


def test_cancel_during_retry_wait_stops_without_another_request():
    cancel = threading.Event()
    opener = Opener({FEB: Resp(503, headers={'Retry-After': '5'})})
    with pytest.raises(SourceError) as err:
        list(fetch_months(feb_plan(), consent_hosts=[HOST], consent_plan=feb_plan().plan_sha, opener=opener,
                          cancel=cancel, sleep=lambda s, c: cancel.set()))
    assert err.value.code == 'PT-KBC-CANCEL' and len(opener.calls) == 1


# ------------------------------------------------------------------------------------------ CLI

def run(tmp_path, capsys, *argv, routes=None, fetch=None):
    opener = Opener(routes or {})
    ports = cli_online.OnlinePorts(IndexPorts(clock=Clock()), {'opener': opener, 'sleep': lambda s, c: None,
                                                               **(fetch or {})})
    code = cli_online.main([*argv, '--json', '--workspace', str(tmp_path / 'ws')], ports=ports)
    out = capsys.readouterr()
    return code, json.loads(out.out) if out.out else None, opener, out.err


def consent_args(plan):
    return ['--consent-hosts', HOST, '--consent-plan', plan.plan_sha]


def test_cli_without_consent_prints_the_default_12_month_plan_and_requests_nothing(tmp_path, capsys):
    code, doc, opener, err = run(tmp_path, capsys, routes={})
    plan = doc['result']['plan']
    assert code == 2 and opener.calls == [] and len(plan['requests']) == 12
    assert plan['months'][0] == '2098-Mar' and plan['months'][-1] == '2099-Feb'
    assert plan['plan_sha'] in doc['error'] and 'consent required' in err
    assert not (tmp_path / 'ws').exists()


@pytest.mark.parametrize('flag, count', [('24', 24), ('3', 3)], ids=['max', 'three'])
def test_cli_window_flag_extends_or_narrows_the_plan(tmp_path, capsys, flag, count):
    code, doc, _, _ = run(tmp_path, capsys, '--window-months', flag)
    assert code == 2 and len(doc['result']['plan']['months']) == count


@pytest.mark.parametrize('flag', ['0', '25', '-1'], ids=['zero', 'over', 'negative'])
def test_cli_window_flag_range_is_enforced(tmp_path, capsys, flag):
    code, _, opener, _ = run(tmp_path, capsys, '--window-months', flag)
    assert code == 2 and opener.calls == []


def test_cli_sync_stores_and_shows_coverage(tmp_path, capsys):
    plan = feb_plan()
    code, doc, opener, _ = run(tmp_path, capsys, '--months', '2099-Feb', *consent_args(plan), routes={FEB: Resp(200, BODY)})
    result = doc['result']
    assert code == 0 and doc['status'] == 'complete' and result['index_changed'] is True
    assert result['months'][0]['state'] == 'added' and result['coverage']['text']
    assert [c[1] for c in opener.calls] == [FEB]
    code, doc, _, _ = run(tmp_path, capsys, '--months', '2099-Feb', *consent_args(plan), routes={FEB: Resp(200, BODY)})
    assert code == 0 and doc['result']['months'][0]['state'] == 'already-present'
    assert doc['result']['index_changed'] is False


def test_cli_missing_month_is_partial_exit_3_never_ok(tmp_path, capsys):
    plan = net_plan.build_plan(['2099-Jan', '2099-Feb'])
    code, doc, _, _ = run(tmp_path, capsys, '--months', '2099-Jan,2099-Feb', *consent_args(plan),
                          routes={JAN: Resp(404), FEB: Resp(200, BODY)})
    assert code == 3 and doc['status'] == 'partial'
    assert [r['state'] for r in doc['result']['months']] == ['not-published', 'added']
    assert any('earlier documents' in w for w in doc['warnings'])


def test_cli_nothing_fetched_leaves_no_workspace(tmp_path, capsys):
    plan = feb_plan()
    code, doc, _, _ = run(tmp_path, capsys, '--months', '2099-Feb', *consent_args(plan), routes={FEB: Resp(503)})
    assert code == 3 and doc['status'] == 'partial' and not (tmp_path / 'ws').exists()


def test_cli_wrong_document_is_failed_and_not_stored(tmp_path, capsys):
    plan = net_plan.build_plan(['2099-Jan'])
    code, doc, _, _ = run(tmp_path, capsys, '--months', '2099-Jan', *consent_args(plan), routes={JAN: Resp(200, BODY)})
    assert code == 3 and doc['result']['months'][0]['state'] == 'failed' and doc['result']['index_changed'] is False


@pytest.mark.parametrize('extra', [[], ['--consent-hosts', HOST]], ids=['bare', 'consent'])
def test_cli_offline_is_exit_2(tmp_path, capsys, extra):
    code, _, opener, _ = run(tmp_path, capsys, '--months', '2099-Feb', '--offline', *extra)
    assert code == 2 and opener.calls == []


def test_cli_wrong_digest_is_exit_2_and_requests_nothing(tmp_path, capsys):
    code, doc, opener, _ = run(tmp_path, capsys, '--months', '2099-Feb', '--consent-hosts', HOST,
                               '--consent-plan', '1' * 64, routes={FEB: Resp(200, BODY)})
    assert code == 2 and opener.calls == [] and 'different plan' in doc['error']


def test_cli_cancel_keeps_earlier_months_and_exits_5(tmp_path, capsys):
    cancel = threading.Event()
    plan = net_plan.build_plan(['2099-Jan', '2099-Feb'])
    routes = {JAN: Resp(200, BODY), FEB: lambda: cancel.set() or Resp(200, BODY)}
    code, doc, _, _ = run(tmp_path, capsys, '--months', '2099-Jan,2099-Feb', *consent_args(plan), routes=routes,
                          fetch={'cancel': cancel})
    assert code == 5 and doc['status'] == 'cancelled'
    assert [r['state'] for r in doc['result']['months']] == ['failed']  # Jan got the Feb bytes


def test_cli_future_month_is_exit_2(tmp_path, capsys):
    code, _, opener, _ = run(tmp_path, capsys, '--months', '2099-Dec')
    assert code == 2 and opener.calls == []
