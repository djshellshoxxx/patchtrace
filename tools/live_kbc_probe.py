"""Live check of the KB/CVE correlator's two network sources, recorded as a separate, advisory probe (KB plan, probe L1).

usage: live_kbc_probe.py [--month 2024-Aug] [--cve CVE-2024-38063] [--out build/live-status/kbc-live.json]
                         [--work DIR] [--timeout 300] [--skip-winbindex]

Real network, not mocked. Steps, all through the shipped CLI so the production transport is what gets tested:
(1) plain TCP reachability of api.msrc.microsoft.com and winbindex.m417z.com on port 443;
(2) `kb index plan` for one month (no network) to read the plan digest;
(3) `kb index sync` of exactly that plan with the matching consent flags into an empty workspace: this is the check
    that the MSRC CVRF URL shape derived from the swagger ("unverified until live probe L1") really returns a
    document the parser accepts;
(4) `kb index verify` re-hashes and re-parses what was stored;
(5) `kb search CVE` against the stored month: a CVE published that month must resolve to at least one KB, and the
    answer must state its coverage;
(6) `acquire search afd.sys` against Winbindex (skipped with --skip-winbindex).
Nothing is sent but the planned requests: no project data, no credential.

Classification: an unreachable host, a connection failure or time-out, HTTP 403 or 429 is BLOCKED (an external
condition, never a pass); a reachable source that answers with something the parser rejects, a month that is "not
published", a failed verify or an empty search is FAILED (the drift this probe exists to catch). Exit code: 1 when
failed, else 0 (blocked is printed loudly, never silent). The status file follows tools/check_live_status.py.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = 'kbc-live'
MSRC_HOST = 'api.msrc.microsoft.com'
WINBINDEX_HOST = 'winbindex.m417z.com'
REASON_CHARS = 280
_BLOCKED = re.compile(r'HTTP (?:403|429)\b|timed? ?out|unreachable|connection (?:refused|reset|error)|'
                      r'name or service|temporary failure|network is unreachable|PT-[A-Z]+-NETWORK', re.I)
_KB = re.compile(r'\bKB[0-9]{6,8}\b')
_MONTH = re.compile(r'^[0-9]{4}-[A-Z][a-z]{2}$')
_CVE = re.compile(r'^CVE-[0-9]{4}-[0-9]{4,7}$')


@dataclass(frozen=True)
class CliRun:
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False


Runner = Callable[[Sequence[str], float], CliRun]
HostCheck = Callable[[str], tuple[bool, str]]


def reachable(host: str, timeout: float = 10.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, 443), timeout=timeout):
            return True, 'tcp 443 open'
    except OSError as exc:
        return False, f'{type(exc).__name__}: {exc}'[:120]


def run_cli(argv: Sequence[str], timeout: float) -> CliRun:
    cmd = [sys.executable, '-m', 'patchtrace', *argv]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT,
                           env={'PYTHONPATH': str(ROOT / 'src'), 'PATH': _path(), 'PYTHONIOENCODING': 'utf-8'},
                           check=False)
    except subprocess.TimeoutExpired:
        return CliRun(124, '', f'probe timeout after {timeout:g}s', True)
    return CliRun(p.returncode, p.stdout, p.stderr)


def _path() -> str:
    import os
    return os.environ.get('PATH', '')


def _verdict(result: str, detail: str, **extra) -> dict:
    return {'result': result, 'detail': detail[:REASON_CHARS], **extra}


def _json(run: CliRun) -> dict | None:
    try:
        doc = json.loads(run.stdout)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _external(run: CliRun) -> bool:
    return run.timed_out or bool(_BLOCKED.search(run.stdout + '\n' + run.stderr))


def check_plan(run: CliRun) -> tuple[dict, str | None]:
    doc = _json(run)
    plan = ((doc or {}).get('result') or {}).get('plan') or {}
    sha, hosts = plan.get('plan_sha'), plan.get('hosts')
    if run.code != 0 or not isinstance(sha, str) or hosts != [MSRC_HOST]:
        return _verdict('failed', f'plan preview unusable (exit {run.code}, hosts {hosts})'), None
    return _verdict('passed', 'plan preview made no request', plan_sha=sha), sha


def check_sync(run: CliRun, month: str) -> dict:
    if _external(run) and run.code != 0:
        return _verdict('blocked', (run.stderr or run.stdout).strip().splitlines()[-1] if (run.stderr or run.stdout)
                        else 'network condition')
    doc = _json(run)
    rows = ((doc or {}).get('result') or {}).get('months') or []
    states = {r.get('month'): r.get('state') for r in rows if isinstance(r, dict)}
    if run.code == 0 and states.get(month) in ('added', 'already-present'):
        sha = next((r.get('sha256') for r in rows if r.get('month') == month), None)
        return _verdict('passed', f'{month} stored ({states[month]})', sha256=sha)
    if states.get(month) == 'not-published':
        return _verdict('failed', f'{month} reported not-published: URL shape or month naming drift')
    msgs = [f"{r.get('code')}: {r.get('message')}" for r in rows if isinstance(r, dict) and r.get('code')]
    return _verdict('failed', '; '.join(msgs) or f'sync exit {run.code}: {states or "no month rows"}')


def check_verify(run: CliRun) -> dict:
    doc = _json(run)
    if run.code == 0 and (doc or {}).get('status') in ('ok', 'passed', 'complete', 'success'):
        return _verdict('passed', 'stored documents re-hash and re-parse')
    if run.code == 0 and doc is not None and not (doc.get('error')):
        return _verdict('passed', f"verify exit 0, status {doc.get('status')!r}")
    return _verdict('failed', f'verify exit {run.code}: {(run.stderr or run.stdout)[-160:]}')


def check_search(run: CliRun, cve: str) -> dict:
    text = run.stdout
    if run.code != 0:
        return _verdict('failed', f'search exit {run.code}: {run.stderr[-160:]}')
    kbs = sorted(set(_KB.findall(text)))
    if cve not in text:
        return _verdict('failed', f'{cve} not found in the stored month: parser or scope drift')
    if not kbs:
        return _verdict('failed', f'{cve} found but no KB number resolved')
    if 'coverage' not in text.lower():
        return _verdict('failed', 'answer did not state its coverage')
    return _verdict('passed', f'{cve} resolves to {len(kbs)} KB id(s)', kb_count=len(kbs))


def check_winbindex(run: CliRun) -> dict:
    if _external(run) and run.code != 0:
        return _verdict('blocked', (run.stderr or run.stdout).strip().splitlines()[-1] if (run.stderr or run.stdout)
                        else 'network condition')
    if run.code == 0 and 'afd.sys' in run.stdout:
        return _verdict('passed', 'Winbindex record for afd.sys returned')
    return _verdict('failed', f'acquire search exit {run.code}: {(run.stderr or run.stdout)[-160:]}')


def _overall(parts: dict[str, dict]) -> tuple[str, str]:
    failed = [k for k, v in parts.items() if v['result'] == 'failed']
    blocked = [k for k, v in parts.items() if v['result'] == 'blocked']
    if failed:
        return 'failed', f"failed: {', '.join(failed)}: {parts[failed[0]]['detail']}"
    if blocked:
        return 'blocked', f"blocked: {', '.join(blocked)}: {parts[blocked[0]]['detail']}"
    return 'passed', f'{len(parts)} live checks passed'


def probe(month: str, cve: str, work: Path, timeout: float, *, skip_winbindex: bool = False,
          check_host: HostCheck | None = None, runner: Runner | None = None) -> dict:
    check_host = check_host or reachable  # resolved at call time so tests and callers can replace the module names
    runner = runner or run_cli
    if not _MONTH.match(month) or not _CVE.match(cve):
        raise ValueError('month must look like 2024-Aug and cve like CVE-2024-38063')
    parts: dict[str, dict] = {}
    ok, why = check_host(MSRC_HOST)
    parts['msrc-reachable'] = _verdict('passed' if ok else 'blocked', why)
    if ok:
        ws = work / 'kb-workspace'
        ws.mkdir(parents=True, exist_ok=True)
        base = ['--workspace', str(ws), '--json']
        parts['plan'], sha = check_plan(runner(['kb', 'index', 'plan', '--months', month, *base], timeout))
        if sha:
            sync = runner(['kb', 'index', 'sync', '--months', month, '--consent-hosts', MSRC_HOST,
                           '--consent-plan', sha, *base], timeout)
            parts['sync'] = check_sync(sync, month)
            if parts['sync']['result'] == 'passed':
                parts['verify'] = check_verify(runner(['kb', 'index', 'verify', *base], timeout))
                if parts['verify']['result'] == 'passed':  # never search a store that failed its own re-check
                    parts['search'] = check_search(
                        runner(['kb', 'search', cve, '--months', month, *base], timeout), cve)
    if not skip_winbindex:
        ok, why = check_host(WINBINDEX_HOST)
        parts['winbindex-reachable'] = _verdict('passed' if ok else 'blocked', why)
        if ok:
            parts['winbindex'] = check_winbindex(runner(
                ['acquire', 'search', 'afd.sys', '--consent-hosts', WINBINDEX_HOST, '--json'], timeout))
    status, reason = _overall(parts)
    return {'engine': ENGINE, 'status': status, 'reason': reason[:REASON_CHARS], 'month': month, 'cve': cve,
            'checks': parts}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--month', default='2024-Aug', help='release month to sync, like 2024-Aug')
    ap.add_argument('--cve', default='CVE-2024-38063', help='a CVE published in that month')
    ap.add_argument('--out', type=Path, default=ROOT / 'build' / 'live-status' / f'{ENGINE}.json')
    ap.add_argument('--work', type=Path, default=None)
    ap.add_argument('--timeout', type=float, default=300.0)
    ap.add_argument('--skip-winbindex', action='store_true')
    a = ap.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix='kbc-live-') as tmp:
            result = probe(a.month, a.cve, a.work or Path(tmp), a.timeout, skip_winbindex=a.skip_winbindex)
    except ValueError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f"{result['status'].upper()}: {result['reason']}")
    if result['status'] == 'blocked':
        print('LIVE ACCEPTANCE BLOCKED (external condition, not a pass)')
    return 1 if result['status'] == 'failed' else 0


if __name__ == '__main__':
    sys.exit(main())
