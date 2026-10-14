"""Live NVD/MSRC fetch through the CLI, recorded as a separate, advisory probe (SPEC-07h H10).

usage: live_nvd_probe.py [--cve CVE-...]... [--providers nvd,msrc] [--out build/live-status/cve-providers.json]
                         [--work DIR] [--timeout 600]

Real network, not mocked. Steps: (1) plain TCP reachability of each provider host on port 443 with no
proxy, exactly like the production transport (`intelligence.build_urllib_opener` ignores proxies);
(2) a synthetic sample project (no Microsoft binary); (3) `python -m patchtrace correlate PROJECT --fetch`
for the reachable providers, keyless, so NVD pacing (6 s between keyless requests) is exercised whenever
two CVEs are requested; (4) a strict status file in the live-status convention of
`tools/check_live_status.py`: `passed | failed | blocked` plus per-provider detail. Nothing secret is
sent or stored (no API key is ever used by this probe).

Classification: an unreachable host, a network/rate-limit error (`PT-ENRICH-NETWORK`, NVD 403/429) or
a probe timeout is BLOCKED (external condition, never a pass); a reachable provider whose answer
cannot be normalized, a CLI usage/runtime failure or broken pacing is FAILED (the drift this probe
exists to catch). Exit code: 1 when failed, else 0 (blocked is printed loudly, never silent).
The workflow `.github/workflows/live-nvd.yml` runs it on a schedule and on demand; it is never a
required check and its results are never summed with pytest counts.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CVES = ('CVE-2024-38063', 'CVE-2024-30088')  # two Microsoft CVEs: two keyless NVD requests are paced
HOSTS = {'nvd': 'services.nvd.nist.gov', 'msrc': 'api.msrc.microsoft.com'}
NVD_KEYLESS_INTERVAL = 6.0
ENGINE = 'cve-providers'
_CODE = re.compile(r'\((PT-ENRICH-[A-Z]+)\)')


@dataclass(frozen=True)
class CliRun:
    exit_code: int | None  # None: the probe's own timeout expired
    stdout: str
    stderr: str
    seconds: float


def reachable(host: str, timeout: float = 10.0) -> tuple[bool, str]:
    """Direct TCP connect to host:443 (no proxy, like the production transport)."""
    try:
        with socket.create_connection((host, 443), timeout=timeout):
            return True, 'tcp/443 reachable'
    except OSError as exc:
        return False, f'{type(exc).__name__}: {exc}'[:200]


def run_cli(argv: Sequence[str], timeout: float) -> CliRun:
    # The CLI of this checkout (not whatever `patchtrace` happens to be installed) is the one probed.
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [str(ROOT / 'src'), os.environ.get('PYTHONPATH')])))
    start = time.monotonic()
    try:
        done = subprocess.run([sys.executable, '-m', 'patchtrace', *argv], capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=timeout, cwd=ROOT, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode('utf-8', 'replace') if isinstance(exc.stdout, bytes) else exc.stdout or ''
        return CliRun(None, out, '', time.monotonic() - start)
    return CliRun(done.returncode, done.stdout, done.stderr, time.monotonic() - start)


def _provider_errors(warnings: Sequence[str], error: str) -> dict[str, str]:
    """provider -> error code named in CLI warnings/errors ('' when the provider is not mentioned)."""
    out: dict[str, str] = {}
    for text in [*warnings, error]:
        for provider in HOSTS:
            if f'provider {provider} failed' in text:
                match = _CODE.search(text)
                out[provider] = match.group(1) if match else 'PT-ENRICH-PROVIDER'
    return out


def classify(run: CliRun, providers: Sequence[str], cves: Sequence[str], snapshots: list[dict],
             unreachable: dict[str, str]) -> dict:
    """Pure: probe result from the CLI outcome. `snapshots` is the `--save-snapshot` JSON (may be empty)."""
    detail = {p: {'reachable': p not in unreachable, 'result': 'blocked' if p in unreachable else 'unknown',
                  'detail': unreachable.get(p, '')} for p in providers}
    if not [p for p in providers if p not in unreachable]:
        return {'status': 'blocked', 'reason': 'no provider host reachable: ' + '; '.join(
            f'{HOSTS[p]} ({unreachable[p]})' for p in providers), 'providers': detail}
    if run.exit_code is None:
        return {'status': 'blocked', 'reason': f'CLI did not finish within {run.seconds:.0f} s (network stall)',
                'providers': detail}
    try:
        doc = json.loads(run.stdout)
        if not isinstance(doc, dict) or doc.get('contract') != 'enrichment-cli/1':
            raise ValueError('not an enrichment-cli/1 document')
    except ValueError as exc:
        return {'status': 'failed', 'reason': f'CLI exit {run.exit_code} without a valid JSON envelope ({exc})',
                'providers': detail}
    warnings = [w for w in doc.get('warnings', []) if isinstance(w, str)]
    error = doc.get('error') if isinstance(doc.get('error'), str) else ''
    codes = _provider_errors(warnings, error)
    covered: dict[str, set[str]] = {}
    for snap in snapshots:
        if isinstance(snap, dict) and isinstance(snap.get('response_digests'), dict):
            covered.setdefault(snap.get('cve_id'), set()).update(snap['response_digests'])
    failed, blocked = [], []
    for p in providers:
        if p in unreachable:
            blocked.append(p)
            continue
        code = codes.get(p, '')
        if all(p in covered.get(c, set()) for c in cves):
            detail[p].update(result='ok', detail=f'{len(cves)} snapshot(s) normalized')
        elif code == 'PT-ENRICH-NETWORK' or (not code and 'PT-ENRICH-NETWORK' in error):
            detail[p].update(result='blocked', detail=f'network or rate limit ({code or "PT-ENRICH-NETWORK"})')
            blocked.append(p)
        else:
            detail[p].update(result='failed', detail=f'no normalized snapshot ({code or error[:120] or "unknown"})')
            failed.append(p)
    if run.exit_code == 2:
        return {'status': 'failed', 'reason': f'CLI usage/environment error: {error[:200]}', 'providers': detail,
                'cli_status': doc.get('status')}
    if failed:
        return {'status': 'failed', 'reason': 'provider response not normalized: ' + ', '.join(failed),
                'providers': detail, 'cli_status': doc.get('status')}
    if blocked:
        return {'status': 'blocked', 'reason': 'provider unreachable or rate limited: ' + ', '.join(blocked),
                'providers': detail, 'cli_status': doc.get('status')}
    if run.exit_code != 0:
        return {'status': 'failed', 'reason': f'CLI exit {run.exit_code}: {error[:200]}', 'providers': detail,
                'cli_status': doc.get('status')}
    return {'status': 'passed', 'reason': 'all providers fetched and normalized through the CLI',
            'providers': detail, 'cli_status': doc.get('status')}


def pacing(run: CliRun, providers: Sequence[str], cves: Sequence[str], status: str) -> dict:
    """Keyless NVD pacing evidence: n NVD requests take at least (n - 1) * 6 s."""
    nvd = len(cves) if 'nvd' in providers else 0
    expected = max(0, nvd - 1) * NVD_KEYLESS_INTERVAL
    observed = round(run.seconds, 2)
    ok = None if status != 'passed' or nvd < 2 else observed >= expected
    return {'nvd_requests': nvd, 'keyed': False, 'min_expected_s': expected, 'observed_s': observed, 'ok': ok}


def make_project(work: Path) -> Path:
    sys.path.insert(0, str(ROOT / 'src'))
    from patchtrace.service import ProjectService
    service = ProjectService.sample(work / 'case')  # synthetic, labelled sample project
    try:
        return service.root
    finally:
        service.close()


def probe(cves: Sequence[str], providers: Sequence[str], work: Path, timeout: float, *,
          check_host: Callable[[str], tuple[bool, str]] = reachable,
          runner: Callable[[Sequence[str], float], CliRun] = run_cli) -> dict:
    unreachable = {}
    for p in providers:
        ok, why = check_host(HOSTS[p])
        if not ok:
            unreachable[p] = why
    live = [p for p in providers if p not in unreachable]
    run = CliRun(0, '', '', 0.0)
    snapshots: list[dict] = []
    if live:
        project = make_project(work)
        saved = work / 'snapshots.json'
        argv = ['correlate', str(project), '--fetch', '--providers', ','.join(live),
                '--consent-providers', ','.join(live), '--json', '--dry-run', '--save-snapshot', str(saved)]
        for cve in cves:
            argv += ['--cve', cve]
        run = runner(argv, timeout)
        try:
            loaded = json.loads(saved.read_text(encoding='utf-8')) if saved.is_file() else []
            snapshots = loaded if isinstance(loaded, list) else []
        except (OSError, ValueError):
            snapshots = []
    result = classify(run, providers, cves, snapshots, unreachable)
    result['pacing'] = pacing(run, live, cves, result['status'])
    if result['pacing']['ok'] is False:
        result['status'] = 'failed'
        result['reason'] = (f'keyless NVD pacing broken: {result["pacing"]["observed_s"]} s for '
                            f'{result["pacing"]["nvd_requests"]} requests')
    preview = [line for line in run.stderr.splitlines() if line.startswith('request: ') or 'NVD request' in line]
    return {'engine': ENGINE, 'mocked': False, 'cves': list(cves), 'providers_requested': list(providers),
            'cli_exit': run.exit_code, 'cli_seconds': round(run.seconds, 2), 'consent_preview': preview[:20],
            'snapshot_ids': sorted(s.get('snapshot_id') for s in snapshots if isinstance(s, dict)
                                   and isinstance(s.get('snapshot_id'), str)),
            'python': platform.python_version(), 'platform': platform.platform(),
            'utc': datetime.now(UTC).isoformat(timespec='seconds'), **result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--cve', action='append', default=None, help='repeatable; default: two Microsoft CVEs')
    parser.add_argument('--providers', default='nvd,msrc')
    parser.add_argument('--out', type=Path, default=ROOT / 'build' / 'live-status' / f'{ENGINE}.json')
    parser.add_argument('--work', type=Path, default=None, help='scratch directory (default: a new temp dir)')
    parser.add_argument('--timeout', type=float, default=600.0)
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT / 'src'))
    from patchtrace.enrichment.contracts import EnrichmentError
    from patchtrace.enrichment.intelligence import validate_cve_id
    providers = [p for p in args.providers.split(',') if p]
    try:
        cves = [validate_cve_id(c) for c in (args.cve or DEFAULT_CVES)]
    except EnrichmentError as exc:
        parser.error(str(exc))
    if not providers or any(p not in HOSTS for p in providers):
        parser.error('--providers must be a subset of nvd,msrc')
    with tempfile.TemporaryDirectory(prefix='patchtrace-live-nvd-') as scratch:
        result = probe(cves, providers, Path(args.work or scratch), args.timeout)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('engine', 'status', 'reason')}))
    if result['status'] == 'blocked':
        print(f'LIVE ACCEPTANCE BLOCKED: {ENGINE} ({result["reason"]})', file=sys.stderr)
    return 1 if result['status'] == 'failed' else 0


if __name__ == '__main__':
    sys.exit(main())
