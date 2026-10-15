"""Live check of the CISA KEV catalog through the CLI, recorded as a separate, advisory probe (KEV plan, slice K6).

usage: live_kev_probe.py [--sources cisa-site,cisa-github] [--out build/live-status/kev-catalog.json] [--work DIR]
                         [--timeout 300]

Real network, not mocked. Steps: (1) plain TCP reachability of each source host on port 443 with no proxy, exactly like
the production transport (which ignores environment proxies); (2) `python -m patchtrace kev fetch --source S
--consent-hosts HOST` for every reachable source into its own empty folder: the canonical www.cisa.gov address with
the fixed User-Agent `PatchTrace`, and CISA's GitHub mirror; (3) the two catalogs compared (one release must have one
content_digest, and a catalog carrying fields the parser does not know is drift); (4) CISA's live JSON Schema, read
from the mirror, compared with the vendored copy in docs/schemas/kev/upstream/ (a difference in keys, required fields
or patterns is drift; formatting alone is noted); (5) a strict status file in the live-status convention of
`tools/check_live_status.py`: `passed | failed | blocked` plus per-source detail. Nothing is sent but the two fixed
request headers: no CVE ID, no project data, no credential.

Classification: an unreachable host, a connection failure or time-out (PT-KEV-NETWORK, which includes a server that
stays unavailable), HTTP 403 or 429 (access denied or rate limited, possibly because of the runner's address) or a
probe timeout is BLOCKED (an external condition, never a pass); a reachable source whose answer is not a valid
catalog (HTTP 404 or any other status, a refused redirect, a wrong format or size), unknown fields, different content
for one release, releases far apart, or a changed schema is FAILED (the drift this probe exists to catch). Exit code:
1 when failed, else 0 (blocked is printed loudly, never silent). Fallback: `--sources cisa-github` probes the mirror
only; a pass then says nothing about the canonical address.
The workflow `.github/workflows/live-kev.yml` runs it on a schedule and on demand; it is never a required check and its
results are never summed with pytest counts.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
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
sys.path.insert(0, str(ROOT / 'src'))

from patchtrace.kev import transport  # noqa: E402
from patchtrace.kev.contracts import PLAN_HEADERS, SOURCE_HOSTS  # noqa: E402

ENGINE = 'kev-catalog'
HOSTS = dict(SOURCE_HOSTS)
SCHEMA_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities_schema.json'
VENDORED = ROOT / 'docs' / 'schemas' / 'kev' / 'upstream' / 'known_exploited_vulnerabilities_schema.json'
BLOCKING_STATUS = (403, 429)
MAX_SCHEMA_BYTES = 64 * 1024
MAX_RELEASE_GAP_HOURS = 72                      # the mirror is "synchronized within minutes"; days apart is drift
REASON_CHARS = 280                              # check_live_status.py cuts a table cell at 300
_CODE = re.compile(r'PT-KEV-[A-Z]+')
_HTTP = re.compile(r'HTTP ([0-9]{3})')


@dataclass(frozen=True)
class CliRun:
    exit_code: int | None  # None: the probe's own timeout expired
    stdout: str
    stderr: str
    seconds: float


@dataclass(frozen=True)
class SchemaFetch:
    status: int | None     # None: no answer at all
    body: bytes
    error: str             # empty when a 200 answer was read whole


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


# --- one source -----------------------------------------------------------------------------------------------

def _verdict(result: str, detail: str, **extra) -> dict:
    return {'result': result, 'detail': detail, 'catalog': None, 'http_status': None, **extra}


def _summary(catalog: dict) -> dict:
    names = ('catalog_version', 'date_released', 'entry_count', 'content_digest', 'raw_sha256', 'raw_size',
             'unknown_fields', 'warnings')
    return {name: catalog.get(name) for name in names}


def classify_fetch(run: CliRun) -> dict:
    """Pure: the verdict on one `kev fetch --json` run (`ok`, `blocked` or `failed`), with the catalog summary."""
    if run.exit_code is None:
        return _verdict('blocked', f'the CLI did not finish within {run.seconds:.0f} s (network stall)')
    try:
        doc = json.loads(run.stdout)
        if not isinstance(doc, dict) or doc.get('contract') != 'enrichment-cli/1':
            raise ValueError('not an enrichment-cli/1 document')
    except ValueError as exc:
        return _verdict('failed', f'CLI exit {run.exit_code} without a valid JSON envelope ({exc})')
    error = doc.get('error') if isinstance(doc.get('error'), str) else ''
    if run.exit_code == 0 and doc.get('status') in ('complete', 'partial') and isinstance(doc.get('result'), dict):
        catalog = _summary(doc['result'].get('catalog') or {})
        if catalog['unknown_fields']:
            names = ', '.join(str(name) for name in catalog['unknown_fields'][:6])
            return _verdict('failed', f'the catalog carries fields the parser does not know ({names}): schema drift',
                            catalog=catalog)
        return _verdict('ok', f'catalog {catalog["catalog_version"]}, {catalog["entry_count"]} entries, released '
                        f'{catalog["date_released"]}', catalog=catalog)
    named, answered = _CODE.search(error), _HTTP.search(error)
    code = named.group(0) if named else ''
    status = int(answered.group(1)) if answered else None
    if code in ('PT-KEV-NETWORK', 'PT-KEV-CANCEL') or (code == 'PT-KEV-PROVIDER' and status in BLOCKING_STATUS):
        return _verdict('blocked', error[:200] or code, http_status=status)
    return _verdict('failed', f'CLI exit {run.exit_code}: {error[:200] or "no error text"}', http_status=status)


# --- the two catalogs together --------------------------------------------------------------------------------

def _released(catalog: dict) -> datetime:
    return datetime.strptime(catalog['date_released'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC)


def cross_check(results: dict) -> dict:
    """Pure: the same release must have the same content; releases days apart mean one source has stopped following."""
    catalogs = {name: item['catalog'] for name, item in results.items() if item['result'] == 'ok'}
    if set(catalogs) != set(HOSTS):
        return {'result': 'skipped', 'detail': 'needs both sources fetched'}
    site, mirror = catalogs['cisa-site'], catalogs['cisa-github']
    if site['catalog_version'] == mirror['catalog_version']:
        equal = site['content_digest'] == mirror['content_digest']
        return {'result': 'ok' if equal else 'failed', 'same_release': True, 'content_digest_equal': equal,
                'detail': (f'release {site["catalog_version"]} has the same content on both sources' if equal else
                           f'release {site["catalog_version"]} has different content on the two sources')}
    gap = abs((_released(site) - _released(mirror)).total_seconds()) / 3600
    detail = (f'releases differ (site {site["catalog_version"]}, mirror {mirror["catalog_version"]}, {gap:.1f} h '
              'apart): not comparable')
    return {'result': 'failed' if gap > MAX_RELEASE_GAP_HOURS else 'ok', 'same_release': False,
            'content_digest_equal': None, 'detail': detail, 'gap_hours': round(gap, 1)}


# --- the schema -----------------------------------------------------------------------------------------------

def schema_facts(raw: bytes) -> dict:
    """What the kev/1 parser relies on in CISA's schema: keys, required keys and the two patterns."""
    schema = json.loads(raw.decode('utf-8'))
    entry = schema['$defs']['vulnerability']
    return {'required keys': sorted(schema['required']), 'properties': sorted(schema['properties']),
            'entry required keys': sorted(entry['required']), 'entry properties': sorted(entry['properties']),
            'cveID pattern': entry['properties']['cveID']['pattern'],
            'cwes pattern': entry['properties']['cwes']['items']['pattern']}


def _change(name: str, old, new) -> str:
    if isinstance(old, list):
        added, removed = sorted(set(new) - set(old)), sorted(set(old) - set(new))
        return f'{name}: ' + '; '.join(part for part in (f'added {", ".join(added)}' if added else '',
                                                          f'removed {", ".join(removed)}' if removed else '') if part)
    return f'{name} changed from {old!r} to {new!r}'[:160]


def schema_drift(vendored: bytes, live: bytes) -> list[str]:
    """Pure: what differs in meaning between the vendored schema and the live one (empty: the same, whatever the
    formatting)."""
    try:
        new = schema_facts(live)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return [f'the live schema is not a recognisable KEV schema ({type(exc).__name__})']
    old = schema_facts(vendored)
    return [_change(name, old[name], new[name]) for name in old if old[name] != new[name]]


def check_schema(fetched: SchemaFetch, vendored: bytes) -> dict:
    """Pure: the verdict on one read of the live schema."""
    if fetched.status is None or fetched.status in BLOCKING_STATUS:
        return {'result': 'blocked', 'detail': f'the live schema could not be read ({fetched.error or "no answer"})'}
    if fetched.status != 200 or fetched.error:
        return {'result': 'failed', 'detail': f'the live schema could not be read ({fetched.error or "no answer"})'}
    same_bytes = hashlib.sha256(fetched.body).digest() == hashlib.sha256(vendored).digest()
    differences = [] if same_bytes else schema_drift(vendored, fetched.body)
    detail = ('identical to the vendored copy' if same_bytes else 'same keys, required fields and patterns; only the '
              'formatting differs' if not differences else 'schema drift: ' + '; '.join(differences))
    return {'result': 'failed' if differences else 'ok', 'detail': detail[:400], 'identical': same_bytes,
            'live_sha256': hashlib.sha256(fetched.body).hexdigest(),
            'vendored_sha256': hashlib.sha256(vendored).hexdigest()}


def fetch_live_schema(url: str = SCHEMA_URL, timeout: float = 30.0) -> SchemaFetch:
    """Read the live schema with the production opener (no proxy, no redirect) and bounded time and size."""
    deadline = time.monotonic() + timeout
    try:
        response = transport.urllib_open(url, PLAN_HEADERS, timeout)
    except (OSError, http.client.HTTPException) as exc:
        return SchemaFetch(None, b'', f'{type(exc).__name__}: {exc}'[:200])
    try:
        if response.status != 200:
            return SchemaFetch(response.status, b'', f'HTTP {response.status}')
        body = bytearray()
        while time.monotonic() < deadline:
            chunk = response.read1(MAX_SCHEMA_BYTES + 1 - len(body))
            if not chunk:
                return SchemaFetch(200, bytes(body), '')
            body.extend(chunk)
            if len(body) > MAX_SCHEMA_BYTES:
                return SchemaFetch(200, b'', f'larger than {MAX_SCHEMA_BYTES} bytes')
        return SchemaFetch(None, b'', f'not finished within {timeout:.0f} s')
    except (OSError, http.client.HTTPException) as exc:
        return SchemaFetch(None, b'', f'{type(exc).__name__}: {exc}'[:200])    # trouble on the way: no answer, not drift
    finally:
        response.close()


# --- the probe ------------------------------------------------------------------------------------------------

def _overall(parts: dict[str, dict], sources: Sequence[str]) -> tuple[str, str]:
    """Failed beats blocked beats passed; the reason names what failed or was blocked, or what was proven."""
    failed = {name: item for name, item in parts.items() if item['result'] == 'failed'}
    blocked = {name: item for name, item in parts.items() if item['result'] == 'blocked'}
    shown = failed or blocked
    if shown:
        reason = '; '.join(f'{name}: {item["detail"]}' for name, item in shown.items())
        return ('failed' if failed else 'blocked'), reason[:REASON_CHARS]
    proven = [parts[name]['detail'] for name in ('cross-check', 'schema') if parts[name]['result'] == 'ok']
    reason = ' and '.join(sources) + ' fetched through the CLI; ' + '; '.join(proven)
    if 'cisa-site' not in sources:
        reason += ' (mirror only: the canonical address was not probed)'
    return 'passed', reason[:REASON_CHARS]


_LIVE_PARTS = (reachable, run_cli, fetch_live_schema, transport.urllib_open)


def _mocked(check_host, runner, schema_reader) -> bool:
    """True when any seam (or the HTTP opener) is not the production one: such a run is never live evidence."""
    return (check_host, runner, schema_reader, transport.urllib_open) != _LIVE_PARTS


def probe(sources: Sequence[str], work: Path, timeout: float, *,
          check_host: Callable[[str], tuple[bool, str]] | None = None,
          runner: Callable[[Sequence[str], float], CliRun] | None = None,
          schema_reader: Callable[[], SchemaFetch] | None = None, vendored: bytes | None = None) -> dict:
    # Resolved per call (not bound as default arguments) so callers and tests can replace the module functions.
    check_host = check_host or reachable
    runner = runner or run_cli
    schema_reader = schema_reader or fetch_live_schema
    vendored = VENDORED.read_bytes() if vendored is None else vendored
    results: dict[str, dict] = {}
    seconds = 0.0
    for source in sources:
        up, why = check_host(HOSTS[source])
        if not up:
            results[source] = _verdict('blocked', f'{HOSTS[source]} unreachable ({why})', reachable=False)
            continue
        run = runner(['kev', 'fetch', '--source', source, '--consent-hosts', HOSTS[source], '--kev-dir',
                      str(work / source), '--json'], timeout)
        seconds += run.seconds
        results[source] = {**classify_fetch(run), 'reachable': True, 'cli_exit': run.exit_code}
    parts = dict(results)
    parts['cross-check'] = cross_check(results)
    mirror = results.get('cisa-github')
    schema = (check_schema(schema_reader(), vendored) if mirror and mirror['reachable']
              else {'result': 'skipped', 'detail': 'needs the mirror host'})
    parts['schema'] = schema
    status, reason = _overall(parts, sources)
    return {'engine': ENGINE, 'mocked': _mocked(check_host, runner, schema_reader), 'status': status, 'reason': reason, 'sources_requested': list(sources),
            'canonical_probed': 'cisa-site' in sources, 'sources': results, 'cross_check': parts['cross-check'],
            'schema': schema, 'cli_seconds': round(seconds, 2), 'python': platform.python_version(),
            'platform': platform.platform(), 'utc': datetime.now(UTC).isoformat(timespec='seconds')}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--sources', default=','.join(HOSTS),
                        help='comma list of cisa-site, cisa-github (default both; cisa-github alone is the fallback)')
    parser.add_argument('--out', type=Path, default=ROOT / 'build' / 'live-status' / f'{ENGINE}.json')
    parser.add_argument('--work', type=Path, default=None, help='scratch directory (default: a new temp dir)')
    parser.add_argument('--timeout', type=float, default=300.0, help='seconds allowed for one download')
    args = parser.parse_args(argv)
    sources = [part for part in args.sources.split(',') if part]
    if not sources or len(set(sources)) != len(sources) or any(part not in HOSTS for part in sources):
        parser.error('--sources must be a comma list of cisa-site and cisa-github, each at most once')
    with tempfile.TemporaryDirectory(prefix='patchtrace-live-kev-') as scratch:
        result = probe(sources, Path(args.work or scratch), args.timeout)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('engine', 'status', 'reason')}))
    if result['status'] == 'blocked':
        print(f'LIVE ACCEPTANCE BLOCKED: {ENGINE} ({result["reason"]})', file=sys.stderr)
    return 1 if result['status'] == 'failed' else 0


if __name__ == '__main__':
    sys.exit(main())
