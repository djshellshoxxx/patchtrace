"""SPEC-29 §9.4/§10 harness (mocked): provisioning fails closed, status aggregation, never-silent live test."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fake_bindiff import make_fake_bindiff

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import check_live_status  # noqa: E402
import provision_bindiff  # noqa: E402


def pin(tmp_path: Path, **asset) -> Path:
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps({'contract': 'bindiff-pin/1', 'version': '8', 'gap': 'g',
                                'assets': {'linux': {'url': None, 'sha256': None, 'size': None, **asset}}}))
    return path


def test_unpinned_asset_records_blocked_and_downloads_nothing(tmp_path):
    # The committed pin now holds the measured v8 values (tests/test_provision_bindiff.py); a pin without
    # URL/size/SHA-256 must still fail closed without any download.
    status = tmp_path / 'status'
    assert provision_bindiff.main(['--os', 'linux', '--pin', str(pin(tmp_path)), '--status-dir', str(status),
                                   '--cache', str(tmp_path / 'c'), '--dest', str(tmp_path / 'd')]) == 0
    record = json.loads((status / 'bindiff-provision.json').read_text())
    assert record['status'] == 'blocked' and record['reason'].startswith('pin-missing')
    assert not (tmp_path / 'c').exists()  # nothing downloaded on trust


@pytest.mark.parametrize('asset, message', [
    ({'url': 'https://evil.example/bindiff.deb', 'sha256': 'a' * 64, 'size': 1}, 'upstream'),
    ({'url': provision_bindiff.ALLOWED_PREFIX + 'v8/x.deb', 'sha256': 'XYZ', 'size': 1}, 'SHA-256'),
    ({'url': provision_bindiff.ALLOWED_PREFIX + 'v8/x.deb', 'sha256': 'a' * 64, 'size': True}, 'size'),
])
def test_malformed_pins_fail(tmp_path, asset, message):
    with pytest.raises(provision_bindiff.Failed, match=message):
        provision_bindiff.load_pin(pin(tmp_path, **asset), 'linux')


def test_fetch_verifies_size_and_digest(tmp_path, monkeypatch):
    payload = b'deb bytes'
    good = {'url': provision_bindiff.ALLOWED_PREFIX + 'v8/x.deb', 'sha256': hashlib.sha256(payload).hexdigest(),
            'size': len(payload), 'version': '8'}
    monkeypatch.setattr(provision_bindiff.urllib.request, 'urlopen', lambda url, timeout: io.BytesIO(payload))
    path = provision_bindiff.fetch(good, tmp_path / 'cache')
    assert path.read_bytes() == payload
    with pytest.raises(provision_bindiff.Failed, match='mismatch'):
        provision_bindiff.fetch({**good, 'sha256': 'b' * 64}, tmp_path / 'cache2')
    with pytest.raises(provision_bindiff.Failed, match='larger'):
        provision_bindiff.fetch({**good, 'sha256': 'c' * 64, 'size': 3}, tmp_path / 'cache3')
    assert not list((tmp_path / 'cache2').glob('*.part'))


def test_check_live_status_renders_and_flags_bad_files(tmp_path, capsys):
    (tmp_path / 'bindiff.json').write_text(json.dumps({'engine': 'bindiff', 'status': 'blocked', 'reason': 'no tool'}))
    (tmp_path / 'broken.json').write_text('{not json')
    (tmp_path / 'rz.json').write_text(json.dumps({'engine': 'rz-diff', 'status': 'passed', 'reason': 'ok|x'}))
    summary = tmp_path / 'summary.md'
    assert check_live_status.main(['--dir', str(tmp_path), '--summary', str(summary)]) == 0
    text = summary.read_text()
    assert 'LIVE ACCEPTANCE BLOCKED: bindiff (no tool)' in text and '| broken.json | broken | failed |' in text
    assert 'ok/x' in text
    assert check_live_status.main(['--dir', str(tmp_path), '--fail-on-failed']) == 1
    assert check_live_status.main(['--dir', str(tmp_path / 'none')]) == 0
    assert 'No live status files' in capsys.readouterr().out


def run_live(tmp_path: Path, **env) -> tuple[int, dict, str]:
    status = tmp_path / 'status'
    base = {k: v for k, v in os.environ.items() if not k.startswith('PATCHTRACE_')}
    proc = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '-rA',
                           str(ROOT / 'tests' / 'test_live_bindiff.py')], cwd=ROOT, capture_output=True, text=True,
                          timeout=300, env={**base, 'PATCHTRACE_LIVE_STATUS_DIR': str(status), **env})
    return proc.returncode, json.loads((status / 'bindiff.json').read_text()), proc.stdout


def test_live_test_reports_blocked_not_skipped(tmp_path):
    code, record, out = run_live(tmp_path)
    assert code == 0 and record['status'] == 'blocked' and 'LIVE ACCEPTANCE BLOCKED: bindiff' in out
    assert 'skipped' not in out


def test_live_test_fails_when_required_and_absent(tmp_path):
    code, record, _ = run_live(tmp_path, PATCHTRACE_REQUIRE_LIVE_BINDIFF='1')
    assert code != 0 and record['status'] == 'failed'


def test_live_test_with_probe_passing_tool_but_no_pair_is_blocked(tmp_path):
    exe = make_fake_bindiff(tmp_path / 'bd')
    code, record, _ = run_live(tmp_path, PATCHTRACE_BINDIFF=str(exe))
    if os.name == 'nt':  # the .cmd launcher is (correctly) not an accepted BinDiff executable name
        assert code == 0 and record['status'] == 'blocked' and 'not-found' in record['reason']
        return
    assert code == 0 and record['status'] == 'blocked'
    assert record['checks']['probe']['status'] == 'passed'
    assert record['checks']['end_to_end']['status'] == 'blocked'
