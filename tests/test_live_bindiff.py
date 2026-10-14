"""Live BinDiff acceptance (SPEC-29 §9.4, §10). REAL BinDiff only; mocked tests live elsewhere.

Never skipped: without `PATCHTRACE_BINDIFF` this records `blocked` in build/live-status/bindiff.json and
prints `LIVE ACCEPTANCE BLOCKED`. With `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` (set by the live job only after
a verified provisioning) an unavailable or unsupported tool FAILS. The end-to-end check additionally needs a
real `.BinExport` pair (`PATCHTRACE_LIVE_BINEXPORT_DIR` with older.BinExport, newer.BinExport, pair.json
{"older_sha256", "newer_sha256"}) and C3's BinExport acceptor; without them that check is `blocked`.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path

import pytest
from conftest import live_status_dir

from patchtrace.secondary import bindiff_probe, bindiff_run
from patchtrace.secondary.bindiff_inputs import bind_pair
from patchtrace.secondary.cli_bindiff import c3_acceptor
from patchtrace.secondary.contracts import SecondaryError

pytestmark = pytest.mark.live_bindiff


def _end_to_end(cap, tmp_path: Path) -> tuple[str, str, dict]:
    pair_dir = os.environ.get('PATCHTRACE_LIVE_BINEXPORT_DIR')
    if not pair_dir:
        return 'blocked', 'no real .BinExport pair (PATCHTRACE_LIVE_BINEXPORT_DIR unset)', {}
    acceptor = c3_acceptor(tmp_path / 'accepted')
    if acceptor is None:
        return 'blocked', 'C3 BinExport acceptance is not in this build', {}
    root = Path(pair_dir)
    hashes = json.loads((root / 'pair.json').read_text(encoding='utf-8'))
    older_sha, newer_sha = hashes['older_sha256'], hashes['newer_sha256']
    cancel = threading.Event()
    older = acceptor(root / 'older.BinExport', artifact_sha256=older_sha, role='older', accept_unbound=False,
                     cancel=cancel, other_sha256=newer_sha)
    newer = acceptor(root / 'newer.BinExport', artifact_sha256=newer_sha, role='newer', accept_unbound=False,
                     cancel=cancel, other_sha256=older_sha)
    try:  # (e) reversed inputs are refused before any spawn
        bind_pair(newer, older, older_sha, newer_sha)
        return 'failed', 'reversed .BinExport pair was not rejected', {}
    except SecondaryError as exc:
        if exc.code != 'PT-SECONDARY-ORIENTATION':
            return 'failed', f'reversed pair gave {exc.code}', {}
    pair = bind_pair(older, newer, older_sha, newer_sha)
    outcome = bindiff_run.run_bindiff(cap, pair, tmp_path / 'raw', older_sha, newer_sha, cancel=cancel,
                                      timeout_seconds=1800)
    out_dir = live_status_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(outcome.raw.kept_path, out_dir / 'bindiff-live.BinDiff')
    (out_dir / 'bindiff-live-stdout.txt').write_text(outcome.raw.stdout, encoding='utf-8')
    details = {'matches': len(outcome.match_set.matches), 'output_sha256': outcome.raw.output_sha256,
               'metadata_version': outcome.match_set.engine_version, 'summary': outcome.raw.summary,
               'version_consistent': outcome.version_consistent}
    if not outcome.match_set.matches:
        return 'failed', 'BinDiff produced zero matches on the live pair', details
    return 'passed', 'end-to-end run imported and validated', details


def test_live_bindiff_status(record_live_status, tmp_path):
    exe = os.environ.get('PATCHTRACE_BINDIFF', '').strip()
    required = os.environ.get('PATCHTRACE_REQUIRE_LIVE_BINDIFF') == '1'
    if not exe:
        reason = 'PATCHTRACE_BINDIFF is not set: no BinDiff installed or provisioned on this machine'
        record_live_status('bindiff', 'failed' if required else 'blocked', reason)
        if required:
            pytest.fail(reason)
        return
    report = bindiff_probe.probe_report(exe, use_cache=False)
    if not report.capability.supported:
        reason = f'probe: {report.kind}: {report.capability.reason}'
        record_live_status('bindiff', 'failed' if required else 'blocked', reason)
        if required:
            pytest.fail(reason)
        return
    checks = {'probe': {'status': 'passed', 'version': report.capability.version,
                        'untested_version': report.untested_version}}
    try:
        status, reason, details = _end_to_end(report.capability, tmp_path)
    except SecondaryError as exc:
        status, reason, details = 'failed', f'{exc.code} ({exc.kind}): {exc.message}', {}
    checks['end_to_end'] = {'status': status, 'reason': reason, **details}
    checks['no_network'] = {'status': 'blocked', 'reason': 'unshare -rn run not yet wired into the harness'}
    statuses = [c['status'] for c in checks.values()]
    overall = 'failed' if 'failed' in statuses else 'passed' if set(statuses) == {'passed'} else 'blocked'
    blocked = [f'{name}: {c["reason"]}' for name, c in checks.items() if c['status'] == 'blocked']
    record_live_status('bindiff', overall, '; '.join(blocked) or reason, checks=checks)
    assert overall != 'failed', checks
