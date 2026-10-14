"""K1: pure request preview and plan_sha (KB-integration-plan 6 consent drift, 8.1 `kb index plan`). Mocked: the MSRC URL
shape is unverified until live probe L1; no request is ever made."""
from __future__ import annotations

import json
import socket

import pytest
from kbc_k1_support import no_sockets  # noqa: F401

from patchtrace.kbcorrelation import cli_index
from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources import net_plan
from patchtrace.kbcorrelation.sources.cvrf import SourceError

pytestmark = pytest.mark.usefixtures('no_sockets')
HOST = 'api.msrc.microsoft.com'


def test_plan_lists_exact_requests_hosts_caps_and_digest():
    plan = net_plan.build_plan(['2099-03', '2099-Feb'], now_release='2099-Mar')
    assert plan.months == ('2099-Feb', '2099-Mar')
    assert [r.url for r in plan.requests] == [
        f'https://{HOST}/cvrf/v3.0/cvrf/2099-Feb?api-version=2023-11-01',
        f'https://{HOST}/cvrf/v3.0/cvrf/2099-Mar?api-version=2023-11-01']
    assert plan.hosts == (HOST,) and plan.accept == 'application/json' and len(plan.plan_sha) == 64
    assert plan.caps.max_bytes_per_document == 32 * 1024 * 1024 and plan.caps.concurrency == 1
    assert any('unverified' in n for n in plan.notes)
    assert net_plan.build_plan(['2099-Feb', '2099-Mar'], now_release='2099-Mar') == plan  # deterministic


def test_plan_sha_changes_with_any_url_month_cap_or_index():
    base = net_plan.build_plan(['2099-Feb'])
    shas = {base.plan_sha,
            net_plan.build_plan(['2099-Mar']).plan_sha,
            net_plan.build_plan(['2099-Feb'], include_index=True).plan_sha,
            net_plan.build_plan(['2099-Feb'], limits=KbcLimits(cvrf_doc_bytes=1024)).plan_sha,
            net_plan.build_plan(['2099-Feb', '2099-Mar']).plan_sha}
    assert len(shas) == 5
    edited = base.model_dump(mode='json')
    edited['requests'][0]['url'] = edited['requests'][0]['url'].replace('2099-Feb', '2099-Jan')
    with pytest.raises(ValueError, match='plan_sha'):
        type(base).model_validate_json(json.dumps(edited))


def test_consent_binds_plan_sha():
    """Plan 6: consent for one plan is not consent for another; hosts must equal the planned set."""
    plan = net_plan.build_plan(['2099-Feb'])
    net_plan.verify_consent(plan, consent_hosts=[HOST.upper()], consent_plan=plan.plan_sha)
    other = net_plan.build_plan(['2099-Feb', '2099-Mar'])
    with pytest.raises(SourceError, match='different plan') as info:
        net_plan.verify_consent(other, consent_hosts=[HOST], consent_plan=plan.plan_sha)
    assert info.value.code == 'PT-KBC-CONSENT'
    for hosts in ([], [HOST, 'evil.example.invalid'], ['evil.example.invalid']):
        with pytest.raises(SourceError, match='consent hosts must name exactly'):
            net_plan.verify_consent(plan, consent_hosts=hosts, consent_plan=plan.plan_sha)
    forged = plan.model_copy(update={'accept': 'text/html'})
    with pytest.raises(SourceError, match='altered'):
        net_plan.verify_consent(forged, consent_hosts=[HOST], consent_plan=plan.plan_sha)


def test_scope_errors():
    with pytest.raises(SourceError) as info:
        net_plan.build_plan([])
    assert info.value.code == 'PT-KBC-SCOPE'
    twenty_five = net_plan.months_since('2097-01', '2099-01')
    assert len(twenty_five) == 25
    with pytest.raises(SourceError, match='at most 24'):
        net_plan.build_plan(twenty_five)
    assert len(net_plan.build_plan(net_plan.months_since('2098-02', '2099-01')).requests) == 12
    with pytest.raises(SourceError, match='future'):
        net_plan.build_plan(['2099-Apr'], now_release='2099-Mar')
    with pytest.raises(SourceError, match='reaches back'):
        net_plan.build_plan(['2090-Jan'], now_release='2099-Mar')
    with pytest.raises(SourceError, match='yyyy-MM'):
        net_plan.build_plan(['2099-13'])
    with pytest.raises(SourceError, match='ends before'):
        net_plan.months_since('2099-05', '2099-01')


def test_with_index_adds_one_discovery_request():
    plan = net_plan.build_plan(['2099-Feb'], include_index=True)
    assert plan.requests[0].url.endswith('/Updates?api-version=2023-11-01') and len(plan.requests) == 2
    assert 'no KB data' in plan.requests[0].why


def test_building_a_plan_does_no_io(monkeypatch):
    """Pure: no socket, no DNS, no file open, no subprocess."""
    import builtins
    import subprocess

    def refuse(*a, **k):
        raise AssertionError('I/O in a pure planner')

    monkeypatch.setattr(builtins, 'open', refuse)
    monkeypatch.setattr(subprocess, 'Popen', refuse)
    monkeypatch.setattr(socket, 'getaddrinfo', refuse)
    plan = net_plan.build_plan(['2099-Feb'], now_release='2099-Feb')
    assert net_plan.render_plan(plan).count('GET ') == 1


def test_render_is_a_hand_fetch_recipe():
    text = net_plan.render_plan(net_plan.build_plan(['2099-Feb']))
    assert 'GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2099-Feb' in text
    assert 'Header: Accept: application/json' in text and 'kb index import' in text and 'plan_sha:' in text


class Clock:
    def now_utc(self):
        return '2099-03-10T00:00:00Z'


def run(argv, capsys):
    code = cli_index.main(argv, ports=cli_index.IndexPorts(clock=Clock()))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_plan_json_envelope(capsys):
    code, out, _ = run(['plan', '--months', '2099-02,2099-03', '--json'], capsys)
    doc = json.loads(out)
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'kb index plan'
    assert doc['result']['contract'] == 'kbcorrelation/1' and len(doc['result']['plan']['requests']) == 2
    assert doc['result']['plan']['plan_sha'] == net_plan.build_plan(['2099-02', '2099-03']).plan_sha


def test_cli_plan_since_defaults_to_the_current_month(capsys):
    code, out, _ = run(['plan', '--since', '2099-01', '--json'], capsys)
    assert code == 0 and json.loads(out)['result']['plan']['months'] == ['2099-Jan', '2099-Feb', '2099-Mar']
    code, out, _ = run(['plan', '--since', '2099-01', '--until', '2099-02'], capsys)
    assert code == 0 and out.count('GET ') == 2


@pytest.mark.parametrize('argv', [['plan'], ['plan', '--months', 'x'], ['plan', '--months', '2099-05'],
                                  ['plan', '--months', '2099-01', '--since', '2099-01'], ['plan', '--months', ',']])
def test_cli_plan_errors_are_exit_2(argv, capsys):
    code, out, err = run([*argv, '--json'], capsys)
    assert code == 2 and err.startswith('error:')
    assert json.loads(out)['status'] == 'failed'
