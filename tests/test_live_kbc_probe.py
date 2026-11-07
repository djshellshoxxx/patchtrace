"""Classification logic of tools/live_kbc_probe.py with fake hosts and a fake CLI runner. These are NOT live
acceptance results: the real run happens in .github/workflows/live-kbc.yml. The one real-CLI check (plan preview)
makes no network request."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
import live_kbc_probe as P  # noqa: E402
from check_live_status import load  # noqa: E402

SHA = 'c' * 64


def out(**doc):
    return P.CliRun(0, json.dumps(doc), '')


class Fake:
    """Routes by the CLI verb; every call is recorded."""

    def __init__(self, **over):
        self.calls = []
        self.over = over

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        key = 'winbindex' if argv[0] == 'acquire' else argv[1] if argv[0] == 'kb' and argv[1] != 'index' \
            else argv[2] if argv[0] == 'kb' else argv[0]
        if key in self.over:
            return self.over[key]
        defaults = {
            'plan': out(result={'plan': {'plan_sha': SHA, 'hosts': [P.MSRC_HOST]}}),
            'sync': out(result={'months': [{'month': '2024-Aug', 'state': 'added', 'sha256': 'a' * 64}]}),
            'verify': out(status='ok', result={}),
            'search': P.CliRun(0, 'CVE-2024-38063 -> KB5041585 ... coverage: complete_in_scope', ''),
            'winbindex': P.CliRun(0, '{"name": "afd.sys"}', ''),
        }
        return defaults[key]


def run(fake=None, hosts=lambda h: (True, 'ok'), **kw):
    fake = fake or Fake()
    return P.probe('2024-Aug', 'CVE-2024-38063', Path(kw.pop('work')), 5, check_host=hosts, runner=fake, **kw), fake


def test_all_checks_pass(tmp_path):
    res, fake = run(work=tmp_path)
    assert res['status'] == 'passed' and set(res['checks']) >= {'plan', 'sync', 'verify', 'search', 'winbindex'}
    sync = next(c for c in fake.calls if c[:3] == ['kb', 'index', 'sync'])
    assert sync[sync.index('--consent-plan') + 1] == SHA and sync[sync.index('--consent-hosts') + 1] == P.MSRC_HOST


def test_unreachable_msrc_is_blocked_and_runs_no_msrc_command(tmp_path):
    res, fake = run(hosts=lambda h: (False, 'timed out') if h == P.MSRC_HOST else (True, 'ok'), work=tmp_path)
    assert res['status'] == 'blocked' and not any(c[0] == 'kb' for c in fake.calls)


@pytest.mark.parametrize('stderr', ['HTTP 403 from host', 'HTTP 429', 'request timed out', 'connection reset'])
def test_external_sync_failures_are_blocked_not_failed(tmp_path, stderr):
    res, _ = run(Fake(sync=P.CliRun(3, '', stderr)), work=tmp_path)
    assert res['checks']['sync']['result'] == 'blocked' and res['status'] == 'blocked'
    assert 'verify' not in res['checks']


def test_not_published_month_is_drift_and_fails(tmp_path):
    bad = out(result={'months': [{'month': '2024-Aug', 'state': 'not-published'}]})
    res, _ = run(Fake(sync=P.CliRun(3, bad.stdout, '')), work=tmp_path)
    assert res['status'] == 'failed' and 'not-published' in res['reason']


def test_parser_rejection_reports_the_error_code(tmp_path):
    bad = out(result={'months': [{'month': '2024-Aug', 'state': 'failed', 'code': 'PT-KBC-SOURCE', 'message': 'bad doc'}]})
    res, _ = run(Fake(sync=P.CliRun(3, bad.stdout, '')), work=tmp_path)
    assert res['status'] == 'failed' and 'PT-KBC-SOURCE' in res['checks']['sync']['detail']


@pytest.mark.parametrize('text,needle', [
    ('nothing here coverage', 'not found'),
    ('CVE-2024-38063 coverage only', 'no KB number'),
    ('CVE-2024-38063 KB5041585', 'coverage'),
])
def test_search_must_resolve_cve_to_kb_and_state_coverage(tmp_path, text, needle):
    res, _ = run(Fake(search=P.CliRun(0, text, '')), work=tmp_path)
    assert res['status'] == 'failed' and needle in res['checks']['search']['detail']


def test_failed_verify_fails_even_after_a_good_sync(tmp_path):
    res, _ = run(Fake(verify=P.CliRun(3, '', 'hash mismatch')), work=tmp_path)
    assert res['status'] == 'failed' and 'search' not in res['checks']


def test_winbindex_blocked_and_skip_flag(tmp_path):
    res, _ = run(Fake(winbindex=P.CliRun(124, '', 'probe timeout', True)), work=tmp_path)
    assert res['checks']['winbindex']['result'] == 'blocked' and res['status'] == 'blocked'
    res2, fake = run(work=tmp_path / 'b', skip_winbindex=True)
    assert 'winbindex' not in res2['checks'] and res2['status'] == 'passed'


def test_failed_outranks_blocked(tmp_path):
    res, _ = run(Fake(search=P.CliRun(0, 'x', ''), winbindex=P.CliRun(124, '', 'x', True)), work=tmp_path)
    assert res['status'] == 'failed'


@pytest.mark.parametrize('month,cve', [('2024-08', 'CVE-2024-38063'), ('2024-Aug', 'cve-1'), ('x', 'y')])
def test_invalid_inputs_are_refused(tmp_path, month, cve):
    with pytest.raises(ValueError):
        P.probe(month, cve, tmp_path, 5, check_host=lambda h: (True, ''), runner=Fake())


def test_status_file_matches_the_live_status_convention(tmp_path, monkeypatch):
    monkeypatch.setattr(P, 'reachable', lambda h, timeout=10.0: (False, 'no network here'))
    target = tmp_path / 'live-status' / 'kbc-live.json'
    assert P.main(['--out', str(target), '--work', str(tmp_path / 'w')]) == 0  # blocked exits 0, loudly
    (row,) = load(target.parent)
    assert row['engine'] == 'kbc-live' and row['status'] == 'blocked' and row['reason']
    assert P.main(['--month', 'bad', '--out', str(target)]) == 2


def test_real_cli_plan_preview_is_usable_and_makes_no_request(tmp_path):
    run_ = P.run_cli(['kb', 'index', 'plan', '--months', '2024-Aug', '--workspace', str(tmp_path), '--json'], 120)
    verdict, sha = P.check_plan(run_)
    assert verdict['result'] == 'passed' and sha and len(sha) == 64


def test_out_and_work_are_confined(tmp_path):
    assert P.main(['--out', '/etc/kbc-probe.json']) == 2
    assert P.main(['--out', str(tmp_path / 'o.json'), '--work', '/root/elsewhere']) == 2
    assert P.main(['--out', '/tmp/../etc/x.json']) == 2
