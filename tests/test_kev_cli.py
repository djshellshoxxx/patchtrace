"""``patchtrace kev status|plan|fetch|import|lookup|diff|prune`` through the real entry point (``patchtrace.cli.main``,
so the registry adapter is covered too), over a fake network and a fixed clock. Nothing here opens a socket."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest
from kev_helpers import (
    NOW,
    REAL,
    SYNTHETIC,
    at,
    document,
    entry,
    fixture_bytes,
    parse_bytes,
    render,
    socket_guard,
)

from patchtrace import cli, cli_commands
from patchtrace.enrichment import cve as enrichment_cve
from patchtrace.kev import cli as kev_cli
from patchtrace.kev import limits, service
from patchtrace.kev.contracts import EXIT_CODES, KevError, plan_for
from patchtrace.kev.service import KevService

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)

ROOT = Path(__file__).resolve().parents[1]
SITE, MIRROR = plan_for('cisa-site'), plan_for('cisa-github')
MIRROR_HOST, SITE_HOST = 'raw.githubusercontent.com', 'www.cisa.gov'
STAMP = '2099-03-02T12:00:00Z'
LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN = 'CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004'
BANNED = re.compile(r'\b(exploitable|vulnerable function|confirmed vulnerab\w*|weaponi[sz]ed|proves?|is safe|fixes this'
                    r'|risk|probab\w*|likelihood)\b|%', re.IGNORECASE)
UNSAFE_RANGES = ((0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x9F), (0xAD, 0xAD), (0x61C, 0x61C), (0x180E, 0x180E),
                 (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x206F), (0xFEFF, 0xFEFF))
INVISIBLE = re.compile('[' + ''.join(f'{chr(low)}-{chr(high)}' for low, high in UNSAFE_RANGES) + ']')   # tab and LF are fine


def digits(text: str, zero: int) -> str:
    """ASCII digits written in another digit system; ``zero`` is the code point of that system's 0."""
    return ''.join(chr(zero + int(char)) for char in text)


FULLWIDTH = 'CVE-' + digits('2099', 0xFF10) + '-' + digits('10001', 0xFF10)
ARABIC_INDIC = 'CVE-' + digits('2099', 0x0660) + '-10001'


def strings(value):
    """Every string of a decoded JSON document (the raw JSON text escapes non-ASCII, so it cannot be searched)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


class Response:
    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None):
        self.status, self._body, self.headers = status, body, dict(headers or {})

    def read1(self, size: int) -> bytes:
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self) -> None:
        pass


@dataclass
class Run:
    code: int
    out: str
    err: str
    doc: dict | None = None

    @property
    def result(self) -> dict:
        return self.doc['result']


class World:
    """A fake network and clock behind the real command line, and the catalog folder it works on."""

    def __init__(self, tmp_path: Path, monkeypatch, capsys):
        self.tmp_path, self.capsys = tmp_path, capsys
        self.kev_dir = tmp_path / 'kev'
        self.routes: dict = {}
        self.calls: list[str] = []
        self.now = NOW
        monkeypatch.setattr(service.transport, 'urllib_open', self._open)
        monkeypatch.setattr(service, 'utc_now', lambda: self.now)

    def _open(self, url, headers, timeout):
        self.calls.append(url)
        answer = self.routes.get(url, 404)
        if isinstance(answer, BaseException) or (isinstance(answer, type) and issubclass(answer, BaseException)):
            raise answer
        if isinstance(answer, bytes):
            return Response(200, answer, {'Content-Type': 'text/plain; charset=utf-8'})
        return Response(answer)

    def service(self) -> KevService:
        return KevService(self.kev_dir, now=lambda: self.now)

    def install(self, raw: bytes) -> None:
        self.service().store.install(raw, parse_bytes(raw), now=STAMP)

    def run(self, verb: str, *rest: str, text: bool = False) -> Run:
        folder = () if verb == 'plan' else ('--kev-dir', str(self.kev_dir))          # a plan touches no folder
        argv = ['kev', verb, *folder, *rest, *(() if text else ('--json',))]
        code = cli.main(argv)
        captured = self.capsys.readouterr()
        doc = None
        if not text:
            assert captured.out.endswith('\n') and captured.out.count('\n') == 1, captured.out
            doc = json.loads(captured.out)
            assert doc['contract'] == 'enrichment-cli/1' and set(doc) >= {'command', 'status', 'result', 'warnings'}
            assert not captured.err.lstrip().startswith('{')                  # diagnostics only on stderr
        return Run(code, captured.out, captured.err, doc)


@pytest.fixture
def world(tmp_path, monkeypatch, capsys):
    return World(tmp_path, monkeypatch, capsys)


def catalog_bytes(day: int = 1, entries: int = 10, **first) -> bytes:
    rows = [entry(1, **first), *(entry(n) for n in range(2, entries + 1))]
    return render(document(rows, dateReleased=f'2098-02-{day:02d}T12:00:00Z', catalogVersion=f'2098.02.{day:02d}'))


def synthetic(world: World) -> None:
    world.install(fixture_bytes(SYNTHETIC))


def labels(run: Run) -> dict:
    return {row['cve_id']: row['label'] for row in run.result['rows']}


# --- one JSON document, exit codes ----------------------------------------------------------------------------

def _status_none(w):
    return ['status'], 4, 'unavailable', 'kev status', 'status'


def _plan(w):
    return ['plan', '--source', 'cisa-site'], 0, 'complete', 'kev plan', 'plan'


def _fetch_ok(w):
    w.routes[MIRROR.url] = fixture_bytes(SYNTHETIC)
    return ['fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST], 0, 'complete', 'kev fetch', 'fetch'


def _fetch_no_consent(w):
    return ['fetch', '--source', 'cisa-github'], 2, 'failed', 'kev fetch', None


def _fetch_down(w):
    w.routes[MIRROR.url] = ConnectionError('down')
    return ['fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST], 3, 'failed', 'kev fetch', None


def _fetch_interrupted(w):
    w.routes[MIRROR.url] = KeyboardInterrupt
    return ['fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST], 5, 'cancelled', 'kev fetch', None


def _import_ok(w):
    path = w.tmp_path / 'in.json'
    path.write_bytes(fixture_bytes(SYNTHETIC))
    return ['import', str(path)], 0, 'complete', 'kev import', 'import'


def _import_csv(w):
    path = w.tmp_path / 'in.csv'
    path.write_bytes(b'cveID,vendorProject\n')
    return ['import', str(path)], 2, 'failed', 'kev import', None


def _import_garbage(w):
    path = w.tmp_path / 'in.json'
    path.write_bytes(b'{"a": 1}')
    return ['import', str(path)], 3, 'failed', 'kev import', None


def _lookup_none(w):
    return ['lookup', LISTED_KNOWN], 4, 'unavailable', 'kev lookup', 'lookup'


def _lookup_ok(w):
    synthetic(w)
    return ['lookup', LISTED_KNOWN, NOT_LISTED], 0, 'complete', 'kev lookup', 'lookup'


def _lookup_stale(w):
    synthetic(w)
    w.now = at(2099, 3, 20)
    return ['lookup', LISTED_KNOWN], 0, 'partial', 'kev lookup', 'lookup'


def _status_ok(w):
    synthetic(w)
    return ['status'], 0, 'complete', 'kev status', 'status'


def _diff_alone(w):
    synthetic(w)
    return ['diff'], 4, 'unavailable', 'kev diff', 'diff'


def _prune_unconfirmed(w):
    return ['prune', '--keep', '1'], 2, 'failed', 'kev prune', None


def _prune_ok(w):
    synthetic(w)
    return ['prune', '--keep', '1', '--yes'], 0, 'complete', 'kev prune', 'prune'


SCENARIOS = {fn.__name__[1:].replace('_', '-'): fn for fn in (
    _status_none, _status_ok, _plan, _fetch_ok, _fetch_no_consent, _fetch_down, _fetch_interrupted, _import_ok,
    _import_csv, _import_garbage, _lookup_none, _lookup_ok, _lookup_stale, _diff_alone, _prune_unconfirmed, _prune_ok)}


@pytest.mark.parametrize('scenario', list(SCENARIOS), ids=list(SCENARIOS))
def test_cli_json_is_one_document_with_exit_codes(world, scenario):
    argv, code, status, command, record = SCENARIOS[scenario](world)
    run = world.run(*argv)
    assert (run.code, run.doc['status'], run.doc['command']) == (code, status, command), run.err
    if record is None:
        assert run.doc['result'] is None
        assert status == 'cancelled' or (run.doc['error'] and run.doc['error'] in run.err)
    else:
        assert run.result['contract'] == 'kev/1' and run.result['record'] == record
    assert not any(INVISIBLE.search(text) for text in strings(run.doc))


@pytest.mark.parametrize('code', sorted(EXIT_CODES), ids=lambda c: c.removeprefix('PT-KEV-').lower())
def test_every_kev_error_code_maps_to_its_documented_exit_code(world, monkeypatch, code):
    def raising(self, *args, **kwargs):
        raise KevError(code, 'a fixed message')
    monkeypatch.setattr(KevService, 'fetch', raising)
    run = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    assert run.code == EXIT_CODES[code]
    expected = {5: 'cancelled', 4: 'unavailable'}.get(run.code, 'failed')
    assert run.doc['status'] == expected
    if expected == 'failed':
        assert run.doc['error'].startswith(f'{code}: a fixed message')
        assert ('--accept-shrink' in run.doc['error']) == (code == 'PT-KEV-SHRINK')


# --- consent --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('hosts', [None, '', 'www.cisa.gov', 'raw.githubusercontent.com,www.cisa.gov', 'github.com',
                                   'raw.githubusercontent.com.', 'raw.githubusercontent.com:443', 'cisa.gov'],
                         ids=['absent', 'empty', 'other-source', 'both', 'github', 'trailing-dot', 'port', 'bare'])
def test_cli_fetch_requires_exact_consent_host(world, hosts):
    world.routes[MIRROR.url] = fixture_bytes(SYNTHETIC)
    flags = [] if hosts is None else ['--consent-hosts', hosts]
    run = world.run('fetch', '--source', 'cisa-github', *flags)
    assert run.code == 2 and run.doc['status'] == 'failed' and 'PT-KEV-CONSENT' in run.doc['error']
    assert MIRROR_HOST in run.doc['error'] and world.calls == [] and not world.kev_dir.exists()
    assert run.err.startswith('error: PT-KEV-CONSENT')


@pytest.mark.parametrize('argv', [['fetch', '--consent-hosts', MIRROR_HOST], ['fetch', '--consent-hosts', SITE_HOST],
                                  ['fetch', '--source', 'cisa-mirror'], ['plan']],
                         ids=['github-host', 'site-host', 'unknown-source', 'plan-without-source'])
def test_the_source_has_no_default_and_must_be_one_of_the_two(world, argv):
    world.routes.update({SITE.url: fixture_bytes(SYNTHETIC), MIRROR.url: fixture_bytes(SYNTHETIC)})
    run = world.run(*argv, text=True)
    assert run.code == 2 and run.out == '' and '--source' in run.err
    assert world.calls == [] and not world.kev_dir.exists()


def test_the_exact_host_of_each_source_is_accepted_and_nothing_else_is_requested(world):
    world.routes.update({SITE.url: fixture_bytes(SYNTHETIC), MIRROR.url: fixture_bytes(SYNTHETIC)})
    assert world.run('fetch', '--source', 'cisa-site', '--consent-hosts', SITE_HOST).code == 0
    assert world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST).code == 0
    assert world.calls == [SITE.url, MIRROR.url]


# --- plan: no network ------------------------------------------------------------------------------------------

@pytest.mark.parametrize('source', ['cisa-site', 'cisa-github'])
def test_plan_does_no_network(world, source):
    plan = plan_for(source)
    run = world.run('plan', '--source', source)
    assert run.code == 0 and world.calls == [] and not world.kev_dir.exists()
    assert run.result['plan'] == plan.model_dump(mode='json') and run.result['consent_hosts'] == plan.host
    assert run.result['network'] == 'none'
    assert f'Request: GET {plan.url}' in run.result['request']
    text = world.run('plan', '--source', source, text=True)
    assert text.code == 0 and f'Request: GET {plan.url}' in text.out
    assert f'--source {source} --consent-hosts {plan.host}' in text.out


# --- fetch and import ------------------------------------------------------------------------------------------

def test_fetch_prints_the_request_on_stderr_first_and_installs_the_catalog(world):
    world.routes[MIRROR.url] = fixture_bytes(SYNTHETIC)
    run = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    assert run.err.splitlines()[0] == f'request: GET {MIRROR.url}'
    result = run.result
    assert (run.code, result['outcome'], result['plan_sha']) == (0, 'installed', MIRROR.plan_sha)
    assert result['catalog']['catalog_version'] == '2099.03.01' and result['catalog']['source'] == 'cisa-github'
    assert result['catalog']['consent']['surface'] == 'cli' and result['in_use']['snapshot_id'] == (
        result['catalog']['snapshot_id'])
    assert run.doc['warnings'] == []
    assert world.service().store.load_current().catalog.meta.snapshot_id == result['catalog']['snapshot_id']


def test_fetch_in_text_mode_says_what_was_stored_and_where_the_warning_goes(world):
    world.routes[MIRROR.url] = catalog_bytes(5)
    first = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST, text=True)
    assert first.code == 0 and 'Installed the KEV catalog now in use.' in first.out
    assert 'KEV catalog 2098.02.05' in first.out and '10 entries' in first.out
    assert 'CISA GitHub mirror' in first.out and first.err.strip() == f'request: GET {MIRROR.url}'
    world.routes[MIRROR.url] = catalog_bytes(3)
    older = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST, text=True)
    assert older.code == 0 and 'stays 2098.02.05' in older.out
    assert ('warning: The downloaded catalog (2098.02.03) is older than the one in use (2098.02.05); the newer one '
            'was kept.') in older.err


def test_a_mirror_older_than_the_catalog_in_use_is_a_partial_result_with_exit_zero(world):
    world.routes[MIRROR.url] = catalog_bytes(5)
    world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    world.routes[MIRROR.url] = catalog_bytes(3)
    run = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    assert (run.code, run.doc['status'], run.result['outcome']) == (0, 'partial', 'kept-newer')
    assert run.result['catalog']['catalog_version'] == '2098.02.03' and run.result['in_use']['catalog_version'] == (
        '2098.02.05')
    assert run.doc['warnings'] == ['The downloaded catalog (2098.02.03) is older than the one in use (2098.02.05); '
                                   'the newer one was kept.']
    again = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    assert again.result['outcome'] == 'kept-newer'
    world.routes[MIRROR.url] = catalog_bytes(5)
    assert world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST).result['outcome'] == 'unchanged'


def test_a_shrinking_catalog_is_refused_with_the_way_out_and_accepted_on_request(world):
    world.routes[MIRROR.url] = catalog_bytes(1, 10)
    world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    world.routes[MIRROR.url] = catalog_bytes(2, 8)
    run = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST)
    assert run.code == 3 and 'PT-KEV-SHRINK' in run.doc['error'] and '--accept-shrink' in run.doc['error']
    accepted = world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST, '--accept-shrink')
    assert accepted.code == 0 and accepted.result['in_use']['catalog_version'] == '2098.02.02'


def test_import_reads_a_file_offline_and_refuses_what_is_not_a_kev_catalog(world):
    path = world.tmp_path / 'saved.json'
    path.write_bytes(fixture_bytes(REAL))
    run = world.run('import', str(path))
    assert run.code == 0 and world.calls == []
    meta = run.result['catalog']
    assert (meta['source'], meta['file_name'], meta['entry_count'], meta['consent']) == (
        'local-import', 'saved.json', 12, None)
    text = world.run('import', str(path), text=True)
    assert 'already the catalog in use' in text.out
    csv = world.tmp_path / 'k.csv'
    csv.write_bytes(b'cveID,vendorProject,product\n')
    refused = world.run('import', str(csv))
    assert refused.code == 2 and 'PT-KEV-UNSUPPORTED' in refused.doc['error']
    missing = world.run('import', str(world.tmp_path / 'absent.json'))
    assert missing.code == 2 and 'PT-KEV-INPUT' in missing.doc['error']


def test_importing_an_older_catalog_keeps_the_newer_one_and_says_so(world):
    new, old = world.tmp_path / 'new.json', world.tmp_path / 'old.json'
    new.write_bytes(catalog_bytes(5))
    old.write_bytes(catalog_bytes(3))
    assert world.run('import', str(new)).code == 0
    run = world.run('import', str(old))
    assert (run.code, run.doc['status'], run.result['outcome']) == (0, 'partial', 'kept-newer')
    assert run.doc['warnings'] == ['The imported catalog (2098.02.03) is older than the one in use (2098.02.05); the '
                                   'newer one was kept.']


def test_import_can_accept_a_shrink_too(world):
    big, small = world.tmp_path / 'big.json', world.tmp_path / 'small.json'
    big.write_bytes(catalog_bytes(1, 10))
    small.write_bytes(catalog_bytes(2, 8))
    assert world.run('import', str(big)).code == 0
    assert world.run('import', str(small)).code == 3
    assert world.run('import', str(small), '--accept-shrink').result['outcome'] == 'installed'


# --- lookup ---------------------------------------------------------------------------------------------------

def test_lookup_answers_from_the_catalog_in_use_and_keeps_the_input_order(world):
    synthetic(world)
    run = world.run('lookup', LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN, 'cve-2099-10001')
    assert run.code == 0 and run.doc['status'] == 'complete'
    assert list(labels(run).items()) == [(LISTED_KNOWN, 'Listed - ransomware known'), (NOT_LISTED, 'Not listed'),
                                         (LISTED_UNKNOWN, 'Listed')]
    assert run.result['counts'] == {'listed': 2, 'listed_ransomware_known': 1, 'not_listed': 1, 'unavailable': 0,
                                    'invalid': 0}
    row = run.result['rows'][0]['lookup']
    assert (row['status'], row['entry']['date_added'], row['entry']['ransomware_use'], row['freshness'],
            row['age_days']) == ('listed', '2099-02-10', 'known', 'fresh', 1)
    assert run.result['catalog']['catalog_version'] == '2099.03.01' and run.result['freshness'] == 'fresh'
    assert run.result['summary'].startswith('2 of 3 CVEs are listed in CISA KEV (catalog 2099.03.01, 1 day old).')
    assert 'Not listed does not mean not exploited.' in run.result['summary']


def test_the_summary_counts_only_the_ids_the_catalog_answered(world):
    synthetic(world)
    mixed = world.run('lookup', LISTED_KNOWN, NOT_LISTED, 'bogus', FULLWIDTH)
    assert mixed.result['summary'].startswith('1 of 2 CVEs are listed in CISA KEV (catalog 2099.03.01')
    assert world.run('lookup', 'bogus', FULLWIDTH).result['summary'] is None


def test_lookup_in_text_mode_is_a_short_table_or_the_full_detail_of_one_cve(world):
    synthetic(world)
    table = world.run('lookup', LISTED_KNOWN, NOT_LISTED, text=True)
    lines = table.out.splitlines()
    assert lines[0].startswith('KEV catalog 2099.03.01 - released 2099-03-01 18:00:00 UTC - 4 entries')
    assert f'{LISTED_KNOWN}  Listed - ransomware known  (added 2099-02-10, CISA due date 2099-02-13)' in lines
    assert f'{NOT_LISTED}  Not listed' in lines and lines[-1].endswith('not endorsed by CISA or DHS.')
    assert table.err == ''
    detail = world.run('lookup', LISTED_KNOWN, text=True)
    assert 'KEV: listed' in detail.out and 'Known ransomware campaign use: Known' in detail.out
    assert 'Source: CISA KEV catalog (CC0 1.0)' in detail.out and 'Added to KEV: 2099-02-10' in detail.out
    assert 'CVEs are listed in CISA KEV' not in detail.out and 'CVEs are listed in CISA KEV' in table.out
    unlisted = world.run('lookup', NOT_LISTED, text=True)
    assert 'KEV: not listed' in unlisted.out and 'not evidence that the CVE is unexploited' in unlisted.out


def test_a_cve_id_that_is_not_ascii_is_invalid_and_never_not_listed(world):
    synthetic(world)
    run = world.run('lookup', FULLWIDTH, ARABIC_INDIC, 'CVE-2099-1', '\x1b[31mCVE-2099-10001')
    states = {row['cve_id']: row['label'] for row in run.result['rows']}
    assert set(states.values()) == {'Invalid CVE ID'} and len(states) == 4
    assert run.result['counts']['invalid'] == 4 and run.result['counts']['not_listed'] == 0 and run.code == 0
    assert FULLWIDTH in states and ARABIC_INDIC in states                 # echoed as typed, never matched
    assert '[31MCVE-2099-10001' in states and not any(INVISIBLE.search(text) for text in strings(run.doc))
    assert chr(92) + 'u001b' not in run.out                                 # the escape character was removed


def test_lookup_reads_ids_from_saved_cve_snapshots_and_merges_the_lists(world, tmp_path):
    synthetic(world)
    saved = tmp_path / 'snapshots.json'
    saved.write_text(json.dumps([{'cve_id': NOT_LISTED, 'snapshot_id': 'x', 'cwes': []}, {'cve_id': LISTED_KNOWN}]),
                     encoding='utf-8')
    other = tmp_path / 'one.json'
    other.write_text(json.dumps({'cve_id': LISTED_UNKNOWN}), encoding='utf-8')
    run = world.run('lookup', LISTED_KNOWN, '--from-cve-snapshot', str(saved), '--from-cve-snapshot', str(other))
    assert list(labels(run)) == [LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN]
    only = world.run('lookup', '--from-cve-snapshot', str(saved))
    assert list(labels(only)) == [NOT_LISTED, LISTED_KNOWN]


@pytest.mark.parametrize('content', [
    b'not json', b'{"cve_id": 1}', b'[1, 2]', b'{"cve_id": "CVE-2099-10001", "cve_id": "CVE-2099-10002"}',
    b'[{"cve_id": "CVE-2099-10001", "score": NaN}]', b'[{"cve_id": "CVE-2099-10001", "score": Infinity}]', b'',
    b'\xff\xfe', b'{}', b'[]'],
                         ids=['garbage', 'number-id', 'not-objects', 'duplicate-key', 'nan', 'infinity', 'empty',
                              'not-utf8', 'no-id', 'empty-list'])
def test_a_saved_snapshot_file_must_be_strict_json_with_an_id_in_each_record(world, tmp_path, content):
    synthetic(world)
    saved = tmp_path / 'bad.json'
    saved.write_bytes(content)
    run = world.run('lookup', '--from-cve-snapshot', str(saved))
    assert run.code == 2 and 'PT-KEV-INPUT' in run.doc['error']
    assert world.run('lookup', '--from-cve-snapshot', str(tmp_path / 'absent.json')).code == 2


def test_the_snapshot_file_cap_equals_the_enrichment_cap():
    assert kev_cli.MAX_SNAPSHOT_FILE_BYTES == enrichment_cve.MAX_SNAPSHOT_BYTES


def test_lookup_needs_at_least_one_id_and_stays_within_the_lookup_limit(world):
    synthetic(world)
    run = world.run('lookup')
    assert run.code == 2 and 'PT-KEV-INPUT' in run.doc['error']
    many = [f'CVE-2099-{n:05d}' for n in range(limits.MAX_LOOKUP_CVES + 1)]
    over = world.run('lookup', *many)
    assert over.code == 3 and 'PT-KEV-LIMIT' in over.doc['error']
    assert world.run('lookup', *many[:limits.MAX_LOOKUP_CVES]).code == 0


def test_lookup_with_a_catalog_file_does_not_install_it(world, tmp_path):
    path = tmp_path / 'look.json'
    path.write_bytes(fixture_bytes(SYNTHETIC))
    run = world.run('lookup', LISTED_KNOWN, '--catalog', str(path))
    assert run.code == 0 and labels(run) == {LISTED_KNOWN: 'Listed - ransomware known'}
    assert run.result['catalog']['source'] == 'local-import' and run.result['catalog']['file_name'] == 'look.json'
    assert not world.kev_dir.exists()
    assert world.run('lookup', LISTED_KNOWN, '--catalog', str(tmp_path / 'absent.json')).code == 2


def test_lookup_with_no_catalog_is_unavailable_and_says_nothing_about_the_cve(world):
    run = world.run('lookup', LISTED_KNOWN, 'bad id')
    assert (run.code, run.doc['status']) == (4, 'unavailable')
    assert labels(run) == {LISTED_KNOWN: 'No catalog', 'BAD': 'Invalid CVE ID', 'ID': 'Invalid CVE ID'}
    assert run.result['catalog'] is None and run.result['counts']['not_listed'] == 0
    text = world.run('lookup', LISTED_KNOWN, text=True)
    assert text.code == 4 and 'No KEV catalog is loaded' in text.out and 'patchtrace kev fetch' in text.out


AGING = 'This catalog is {n} days old. CVEs CISA added since then are not shown as listed.'
STALE = ('This catalog is 15 days old. A CVE shown as Not listed may have been added since. Update from CISA... or '
         'import a newer file.')
FUTURE = "The catalog's release time is in the future. Check this computer's clock and treat results as unverified."


@pytest.mark.parametrize('now, freshness, status, warning', [
    (at(2099, 3, 4), 'fresh', 'complete', None), (at(2099, 3, 5), 'aging', 'complete', AGING.format(n=4)),
    (at(2099, 3, 15), 'aging', 'complete', AGING.format(n=14)), (at(2099, 3, 16), 'stale', 'partial', STALE),
    (at(2099, 2, 1), 'future', 'partial', FUTURE)], ids=['fresh-3', 'aging-4', 'aging-14', 'stale-15', 'future'])
def test_lookup_reports_the_catalog_age_and_a_stale_catalog_is_a_partial_result(world, now, freshness, status, warning):
    synthetic(world)
    world.now = now
    run = world.run('lookup', NOT_LISTED)
    assert (run.code, run.doc['status'], run.result['freshness'], run.result['banner']) == (0, status, freshness, warning)
    assert run.doc['warnings'] == ([] if warning is None else [warning])
    text = world.run('lookup', NOT_LISTED, text=True)
    assert text.code == 0 and text.err == ('' if warning is None else f'warning: {warning}\n')


def test_lookup_markdown_is_a_report_block_with_every_untrusted_value_escaped(world):
    world.install(fixture_bytes(SYNTHETIC))
    hostile = '<script>alert(1)</script>|`x`'
    run = world.run('lookup', LISTED_KNOWN, NOT_LISTED, hostile, '--md')
    markdown = run.result['markdown']
    lines = markdown.splitlines()
    assert lines[0] == '### Exploitation context (CISA KEV)'
    assert lines[2].startswith('Catalog 2099.03.01, released 2099-03-01 18:00:00 UTC, 4 entries, retrieved 2099-03-02')
    assert 'SHA-256 ' in lines[2] and lines[2].endswith('CC0 1.0.')
    assert '| CVE | KEV | Added to KEV | CISA due date | Known ransomware campaign use | Forensic triage required by CISA |' in lines
    assert f'| {LISTED_KNOWN} | Listed - ransomware known | 2099-02-10 | 2099-02-13 | Known | Yes |' in lines
    assert f'| {NOT_LISTED} | Not listed | - | - | - | - |' in lines
    assert lines[-1] == ('KEV lists a CVE as a known exploited vulnerability. It does not identify builds, KBs, files or '
                         'functions. Not listed does not mean not exploited.')
    rows = [line for line in lines if line.startswith('| ') and 'Invalid CVE ID' in line]
    assert len(rows) == 1 and rows[0].count('|') - rows[0].count('\\|') == 7
    assert '<SCRIPT>' not in markdown and '`X`' not in markdown and '\\<SCRIPT\\>ALERT\\(1\\)' in markdown
    text = world.run('lookup', LISTED_KNOWN, NOT_LISTED, hostile, '--md', text=True)
    assert text.out == markdown + '\n' and text.err == ''


def test_a_hostile_catalog_version_is_escaped_in_the_markdown_provenance_line(world):
    world.install(render(document(catalogVersion='<b>|`v`')))
    provenance = world.run('lookup', 'CVE-2098-00001', '--md').result['markdown'].splitlines()[2]
    assert '<b>' not in provenance and '`v`' not in provenance
    assert provenance.startswith('Catalog ' + '\\<b\\>\\|\\`v\\`, released')


def test_lookup_markdown_without_a_catalog_says_so(world):
    run = world.run('lookup', LISTED_KNOWN, '--md')
    assert 'No KEV catalog is loaded.' in run.result['markdown'] and f'| {LISTED_KNOWN} | No catalog |' in (
        run.result['markdown'])


def test_hostile_catalog_text_reaches_the_terminal_as_plain_one_line_text(world):
    world.install(fixture_bytes(REAL))
    world.now = at(2026, 10, 14)                       # the day the real entries were copied: a fresh catalog, no banner
    for cve in ('CVE-2021-41773', 'CVE-2017-9841', 'CVE-2024-30088', 'CVE-2013-2597'):
        text = world.run('lookup', cve, text=True)
        assert text.code == 0 and 'KEV: listed' in text.out and not INVISIBLE.search(text.out)
        assert text.err == ''
    run = world.run('lookup', 'CVE-2017-9841', 'CVE-2021-41773', '--md')
    assert run.code == 0 and not any(INVISIBLE.search(text) for text in strings(run.doc))


# --- status ---------------------------------------------------------------------------------------------------

def test_status_describes_the_catalog_in_use(world):
    synthetic(world)
    run = world.run('status')
    result = run.result
    assert (run.code, run.doc['status'], result['freshness'], result['age_days'], result['banner']) == (
        0, 'complete', 'fresh', 1, None)
    assert result['catalog']['catalog_version'] == '2099.03.01' and result['snapshots'] == 1 and result['bytes'] > 0
    assert result['directory'] == str(world.kev_dir) and result['max_age_days'] is None and result['notes'] == []
    assert [item['catalog_version'] for item in result['stored']] == ['2099.03.01']
    assert set(result['stored'][0]) == {'snapshot_id', 'catalog_version', 'date_released', 'entry_count',
                                        'retrieved_at', 'source'}
    text = world.run('status', text=True)
    assert text.code == 0 and text.out.splitlines()[0].startswith('KEV catalog 2099.03.01 - released 2099-03-01 18:00:00')
    assert 'Stored catalogs: 1' in text.out and text.err == ''


def test_status_without_a_catalog_exits_four_and_names_the_way_forward(world):
    run = world.run('status')
    assert (run.code, run.doc['status'], run.result['catalog'], run.result['snapshots']) == (4, 'unavailable', None, 0)
    text = world.run('status', text=True)
    assert text.code == 4 and 'No KEV catalog is loaded' in text.out and not world.kev_dir.exists()


@pytest.mark.parametrize('now, limit, code, status, over', [
    (at(2099, 3, 2), 7, 0, 'complete', False), (at(2099, 3, 8), 7, 0, 'complete', False),
    (at(2099, 3, 9), 7, 3, 'partial', True), (at(2099, 3, 2), 0, 3, 'partial', True),
    (at(2099, 3, 1, 20), 0, 0, 'complete', False), (at(2099, 2, 1), 100, 3, 'partial', True)],
    ids=['1-day-of-7', '7-days-of-7', '8-days-of-7', '1-day-of-0', 'same-day-of-0', 'future'])
def test_status_max_age_days_turns_an_old_catalog_into_a_partial_result(world, now, limit, code, status, over):
    synthetic(world)
    world.now = now
    run = world.run('status', '--max-age-days', str(limit))
    assert (run.code, run.doc['status'], run.result['max_age_days']) == (code, status, limit)
    assert any('limit of' in warning for warning in run.doc['warnings']) is over
    plain = world.run('status')
    assert plain.code == 0 and plain.doc['status'] == 'complete' and plain.result['max_age_days'] is None


def test_status_lists_at_most_twenty_stored_catalogs_but_counts_them_all(world):
    for day in range(1, 23):
        world.install(catalog_bytes(day, 3))
    run = world.run('status')
    assert run.result['snapshots'] == 22 and len(run.result['stored']) == kev_cli.MAX_STORED_LISTED == 20
    assert run.result['stored'][0]['catalog_version'] == '2098.02.22'


def test_status_lists_the_stored_catalogs_and_the_notes_of_a_repaired_pointer(world):
    world.install(catalog_bytes(1))
    world.install(catalog_bytes(2))
    (world.kev_dir / 'current.json').write_text('{ damaged', encoding='utf-8')
    run = world.run('status')
    assert run.code == 0 and run.result['snapshots'] == 2
    assert [item['catalog_version'] for item in run.result['stored']] == ['2098.02.02', '2098.02.01']
    assert run.result['notes'] == ['The record of the catalog in use is damaged; the newest valid catalog is used.']
    assert run.doc['warnings'][0] == run.result['notes'][0]


def test_a_catalog_folder_that_is_a_file_is_no_catalog_for_status_and_a_storage_error_for_import(world, tmp_path):
    world.kev_dir.write_text('a file where the folder should be', encoding='utf-8')
    status = world.run('status')
    assert (status.code, status.doc['status']) == (4, 'unavailable')
    path = tmp_path / 'saved.json'
    path.write_bytes(fixture_bytes(SYNTHETIC))
    run = world.run('import', str(path))
    assert run.code == 3 and 'PT-KEV-STORAGE' in run.doc['error']


# --- diff and prune -------------------------------------------------------------------------------------------

def test_diff_lists_what_changed_since_the_previous_catalog(world):
    world.install(catalog_bytes(1, 10))
    world.install(catalog_bytes(2, 11, knownRansomwareCampaignUse='Known'))
    run = world.run('diff')
    assert run.code == 0 and run.doc['status'] == 'complete'
    delta = run.result['delta']
    assert (delta['added_count'], delta['changed_count'], delta['removed_count']) == (1, 1, 0)
    assert run.result['from']['catalog_version'] == '2098.02.01' and run.result['to']['catalog_version'] == '2098.02.02'
    assert run.result['lines'][0] == '1 new, 1 changed, 0 removed since catalog 2098.02.01.'
    assert 'CVE-2098-00001 changed: Known ransomware campaign use was Unknown, now Known' in run.result['lines']
    text = world.run('diff', text=True)
    assert text.out.splitlines()[0] == '1 new, 1 changed, 0 removed since catalog 2098.02.01.'
    first = delta['from_snapshot_id']
    explicit = world.run('diff', '--from', first, '--to', first)
    assert explicit.result['lines'] == ['0 new, 0 changed, 0 removed since catalog 2098.02.01.']


def test_diff_needs_two_stored_catalogs_and_known_ids(world):
    assert world.run('diff').code == 4
    world.install(catalog_bytes(1))
    alone = world.run('diff')
    assert (alone.code, alone.doc['status']) == (4, 'unavailable') and 'two stored catalogs' in alone.result['reason']
    assert world.run('diff', '--from', 'f' * 64).code == 4
    bad = world.run('diff', '--from', '../x')
    assert bad.code == 2 and 'PT-KEV-INPUT' in bad.doc['error']
    text = world.run('diff', text=True)
    assert text.code == 4 and 'two stored catalogs' in text.out


def test_prune_is_the_only_deletion_and_needs_yes(world):
    for day in (1, 2, 3):
        world.install(catalog_bytes(day))
    before = sorted(path.name for path in (world.kev_dir / 'snapshots').iterdir())
    refused = world.run('prune', '--keep', '1')
    assert refused.code == 2 and 'confirm it with --yes' in refused.doc['error']
    assert sorted(path.name for path in (world.kev_dir / 'snapshots').iterdir()) == before
    run = world.run('prune', '--keep', '1', '--yes')
    result = run.result
    assert run.code == 0 and len(result['removed']) == 2 and result['kept'] == 1 and result['removed_files'] >= 4
    assert result['freed_bytes'] > 0
    assert world.run('status').result['catalog']['catalog_version'] == '2098.02.03'
    text = world.run('prune', '--keep', '1', '--yes', text=True)
    assert text.code == 0 and 'Removed 0 stored catalogs' in text.out


@pytest.mark.parametrize('keep', ['0', '-1', 'x'])
def test_prune_keep_must_be_a_positive_number(world, keep):
    run = world.run('prune', '--keep', keep, '--yes', text=True)
    assert run.code == 2 and 'argument --keep: must be a whole number, 1 or greater' in run.err


# --- the registry adapter and the import rules ----------------------------------------------------------------

def test_the_adapter_is_at_most_25_lines_and_imports_only_the_registry_at_module_level():
    path = ROOT / 'src' / 'patchtrace' / 'cli_commands' / 'kev.py'
    source = path.read_text(encoding='utf-8')
    assert len(source.splitlines()) <= 25
    imports = [node for node in ast.parse(source).body if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert [(node.module, node.level) for node in imports] == [('__future__', 0), (None, 1)]
    command = cli_commands.discover()[0]['kev']
    assert command.name == 'kev' and 'KEV' in command.summary and len(command.summary) <= 80
    assert 'kev' in cli_commands.names() and 'kev' not in cli.COMMANDS


def test_kev_help_lists_every_action_and_loads_no_qt(capsys):
    assert cli.main(['kev', '--help']) == 0
    text = capsys.readouterr().out
    assert 'usage:' in text and all(action in text for action in (
        'status', 'plan', 'fetch', 'import', 'lookup', 'diff', 'prune'))
    assert cli.main(['--help']) == 0
    assert re.search(r'^\s+kev\s+\S', capsys.readouterr().out, re.MULTILINE)


def test_the_kev_command_line_imports_no_qt_and_no_ranking_code():
    code = ('import sys\nimport patchtrace.cli as cli\ncli.main(["kev", "plan", "--source", "cisa-site", "--json"])\n'
            'import patchtrace.kev.cli, patchtrace.kev.service, patchtrace.kev.transport\n'
            'bad = [m for m in sys.modules if m.split(".")[0] in ("PySide6", "shiboken6") '
            'or m.startswith(("patchtrace.ui", "patchtrace.enrichment.ranking", "patchtrace.enrichment.cve",\n'
            '                  "patchtrace.enrichment.signals", "patchtrace.enrichment.pipeline", "patchtrace.evidence"))]\n'
            'print("BAD", bad, file=sys.stderr)\nraise SystemExit(90 if bad else 0)\n')
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=False, cwd=ROOT,
                          env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')))
    assert done.returncode == 0, done.stderr


def test_all_text_a_person_reads_passes_the_claims_sweep(world):
    synthetic(world)
    world.routes[MIRROR.url] = catalog_bytes(9)
    outputs = [world.run('plan', '--source', 'cisa-site', text=True), world.run('status', text=True),
               world.run('lookup', LISTED_KNOWN, NOT_LISTED, text=True), world.run('lookup', NOT_LISTED, text=True),
               world.run('lookup', LISTED_KNOWN, '--md', text=True),
               world.run('fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST, text=True),
               world.run('diff', text=True), world.run('prune', '--keep', '1', '--yes', text=True)]
    world.now = at(2099, 3, 20)
    outputs += [world.run('lookup', LISTED_KNOWN, text=True), world.run('status', '--max-age-days', '3', text=True)]
    joined = '\n'.join(item.out + item.err for item in outputs)
    assert len(joined) > 1500
    cleaned = joined.replace('Not listed does not mean not exploited.', '').replace('not evidence that the CVE is unexploited',
                                                                                    '')
    assert not BANNED.search(cleaned), BANNED.search(cleaned)
    assert 'BOD' not in joined and 'federal' not in joined.lower()


def test_the_exit_codes_are_those_of_the_command_line_contract():
    assert (kev_cli.OK, kev_cli.RUNTIME, kev_cli.NO_RESULTS, kev_cli.CANCELLED) == (0, 3, 4, 5)
    assert kev_cli.SUMMARY == cli_commands.discover()[0]['kev'].summary


def test_a_cancel_event_that_is_already_set_stops_a_fetch_with_the_cancelled_envelope(world, capsys):
    parser = cli._parser(['kev'])
    args = parser.parse_args(['kev', 'fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST,
                              '--kev-dir', str(world.kev_dir), '--json'])
    cancel = threading.Event()
    cancel.set()
    code = kev_cli.run(args, cancel)
    doc = json.loads(capsys.readouterr().out)
    assert (code, doc['status'], doc['command'], doc['result']) == (5, 'cancelled', 'kev fetch', None)
    assert world.calls == []


def test_no_kev_network_file_hides_a_control_or_invisible_character():
    """The editor that wrote these files once turned typed escapes into the raw characters (FAB-0 found the same)."""
    names = ('src/patchtrace/kev/transport.py', 'src/patchtrace/kev/service.py', 'src/patchtrace/kev/cli.py',
             'src/patchtrace/cli_commands/kev.py', 'tests/test_kev_transport.py', 'tests/test_kev_service.py',
             'tests/test_kev_cli.py')
    for name in names:
        text = (ROOT / name).read_text(encoding='utf-8')
        odd = sorted({hex(ord(char)) for char in text if ord(char) > 126 or (ord(char) < 32 and char != '\n')})
        assert odd == [], (name, odd)
