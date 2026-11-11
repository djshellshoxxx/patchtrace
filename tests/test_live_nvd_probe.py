"""tools/live_nvd_probe.py classification and the CLI parsing path it relies on.

RECORDED/MOCKED, not live evidence: the transport is replaced by a fake opener that serves the real but
trimmed 2026-10-12 provider responses in tests/fixtures/cve (see its README); hosts are stubbed as
reachable or unreachable. Only the scheduled/manual `live-nvd` workflow produces live results.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_live_status  # noqa: E402
import live_nvd_probe as probe_mod  # noqa: E402

from patchtrace import cli  # noqa: E402
from patchtrace.enrichment import intelligence  # noqa: E402

FIXTURES = ROOT / 'tests' / 'fixtures' / 'cve'
CVE = 'CVE-2024-38063'


class _Response:
    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None):
        self.status, self._body, self.headers = status, body, headers or {}

    def read(self, size: int) -> bytes:
        chunk, self._body = self._body[:size], self._body[size:]
        return chunk

    def close(self) -> None:
        pass


def _serve(monkeypatch, *, nvd=None, msrc=None):
    """Fake transport: provider -> (status, body); default = the recorded fixture with HTTP 200."""
    bodies = {'nvd': nvd or (200, (FIXTURES / f'nvd_{CVE}.json').read_bytes()),
              'msrc': msrc or (200, (FIXTURES / f'msrc_{CVE}.json').read_bytes())}
    seen = []

    def opener(url, headers, timeout):
        provider = 'nvd' if 'nvd.nist.gov' in url else 'msrc'
        seen.append((provider, url, dict(headers)))
        status, body = bodies[provider]
        return _Response(status, body, {'Retry-After': '0'} if status != 200 else {})
    monkeypatch.setattr(intelligence, 'urllib_open', opener)
    return seen


def _inprocess(argv, timeout):
    out, err = io.StringIO(), io.StringIO()
    start = time.monotonic()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return probe_mod.CliRun(code, out.getvalue(), err.getvalue(), time.monotonic() - start)


def _up(_host):
    return True, 'stub: reachable'


def _down(host):
    return False, f'stub: {host} unreachable'


def test_recorded_responses_pass_through_cli(monkeypatch, tmp_path):
    seen = _serve(monkeypatch)
    result = probe_mod.probe([CVE], ['nvd', 'msrc'], tmp_path, 60, check_host=_up, runner=_inprocess)
    assert result['status'] == 'passed', result['reason']
    assert {p: d['result'] for p, d in result['providers'].items()} == {'nvd': 'ok', 'msrc': 'ok'}
    assert len(result['snapshot_ids']) == 1 and result['mocked'] is True  # fake transport: labelled mocked
    assert result['cli_exit'] == 0 and any(line.startswith('request: nvd') for line in result['consent_preview'])
    assert sorted(p for p, _u, _h in seen) == ['msrc', 'nvd']
    assert all('apiKey' not in h for _p, _u, h in seen)  # keyless


def test_mocked_label_is_false_only_for_the_production_seams():
    # positive control: probe() with the real seams would hit the network, so compare the seam pair directly
    assert (probe_mod.reachable, probe_mod.run_cli) == probe_mod._LIVE_PARTS
    assert (_up, probe_mod.run_cli) != probe_mod._LIVE_PARTS


def test_unreachable_hosts_are_blocked_without_cli(tmp_path):
    def never(*_a):
        raise AssertionError('CLI must not run when no host is reachable')
    result = probe_mod.probe([CVE], ['nvd', 'msrc'], tmp_path, 60, check_host=_down, runner=never)
    assert result['status'] == 'blocked' and 'services.nvd.nist.gov' in result['reason']
    assert result['cli_exit'] == 0 and result['snapshot_ids'] == []


def test_one_unreachable_host_is_blocked_not_passed(monkeypatch, tmp_path):
    _serve(monkeypatch)
    hosts = {'services.nvd.nist.gov': (True, 'up'), 'api.msrc.microsoft.com': (False, 'TimeoutError')}
    result = probe_mod.probe([CVE], ['nvd', 'msrc'], tmp_path, 60, check_host=hosts.__getitem__,
                             runner=_inprocess)
    assert result['status'] == 'blocked'
    assert result['providers']['nvd']['result'] == 'ok' and result['providers']['msrc']['result'] == 'blocked'


def test_schema_drift_is_failed(monkeypatch, tmp_path):
    drifted = json.loads((FIXTURES / f'nvd_{CVE}.json').read_text(encoding='utf-8'))
    drifted['vulnerabilities'] = 'renamed upstream'
    _serve(monkeypatch, nvd=(200, json.dumps(drifted).encode()))
    result = probe_mod.probe([CVE], ['nvd', 'msrc'], tmp_path, 60, check_host=_up, runner=_inprocess)
    assert result['status'] == 'failed' and result['providers']['nvd']['result'] == 'failed'
    assert result['providers']['msrc']['result'] == 'ok'


def test_rate_limit_is_blocked(monkeypatch, tmp_path):
    _serve(monkeypatch, msrc=(429, b''))
    result = probe_mod.probe([CVE], ['nvd', 'msrc'], tmp_path, 60, check_host=_up, runner=_inprocess)
    assert result['status'] == 'blocked' and result['providers']['msrc']['result'] == 'blocked'
    assert result['providers']['nvd']['result'] == 'ok'


def test_probe_timeout_is_blocked(tmp_path):
    def stalled(_argv, timeout):
        return probe_mod.CliRun(None, '', '', timeout)
    result = probe_mod.probe([CVE], ['nvd'], tmp_path, 5, check_host=_up, runner=stalled)
    assert result['status'] == 'blocked' and 'did not finish' in result['reason']


def test_broken_keyless_pacing_is_failed(monkeypatch, tmp_path):
    second = 'CVE-2024-30088'
    nvd = json.loads((FIXTURES / f'nvd_{CVE}.json').read_text(encoding='utf-8'))
    snapshots = [{'cve_id': c, 'snapshot_id': c, 'response_digests': {'nvd': 'x'}} for c in (CVE, second)]
    envelope = json.dumps({'contract': 'enrichment-cli/1', 'command': 'correlate', 'status': 'complete',
                           'result': {}, 'warnings': []})

    def fast(argv, _timeout):
        Path(argv[argv.index('--save-snapshot') + 1]).write_text(json.dumps(snapshots), encoding='utf-8')
        return probe_mod.CliRun(0, envelope, '', 1.0)  # two keyless NVD requests in 1 s: pacing missing
    assert nvd  # the recorded body exists; this case only exercises the pacing rule
    result = probe_mod.probe([CVE, second], ['nvd'], tmp_path, 60, check_host=_up, runner=fast)
    assert result['status'] == 'failed' and result['pacing']['ok'] is False
    assert result['pacing']['min_expected_s'] == probe_mod.NVD_KEYLESS_INTERVAL


def test_main_writes_live_status_file(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(probe_mod, 'reachable', _down)
    out = tmp_path / 'live-status' / 'cve-providers.json'
    assert probe_mod.main(['--out', str(out), '--work', str(tmp_path / 'w')]) == 0
    rows = check_live_status.load(out.parent)
    assert [(r['engine'], r['status']) for r in rows] == [('cve-providers', 'blocked')]
    assert 'LIVE ACCEPTANCE BLOCKED' in capsys.readouterr().err


@pytest.mark.parametrize('bad', ['CVE-24-1', 'CVE-2024-38063\n'])
def test_main_rejects_invalid_cve(bad, tmp_path):
    with pytest.raises(SystemExit) as info:
        probe_mod.main(['--cve', bad, '--out', str(tmp_path / 'x.json')])
    assert info.value.code == 2
