"""tools/live_kev_probe.py: classification, cross-checks, schema drift and the CLI path it relies on.

RECORDED/MOCKED, not live evidence: the transport is replaced by a fake opener that serves the committed KEV fixtures,
the hosts and the schema read are stubbed, and the CLI runs in this process. Only the scheduled or manual `live-kev`
workflow produces live results."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import sys
import time
from pathlib import Path

import pytest
from kev_helpers import SYNTHETIC, document, entry, fixture_bytes, render, socket_guard

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_live_status  # noqa: E402
import live_kev_probe as probe_mod  # noqa: E402

from patchtrace import cli  # noqa: E402
from patchtrace.kev import transport  # noqa: E402
from patchtrace.kev.contracts import PLAN_HEADERS, plan_for  # noqa: E402

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)

SITE, MIRROR = plan_for('cisa-site'), plan_for('cisa-github')
SITE_HOST, MIRROR_HOST = 'www.cisa.gov', 'raw.githubusercontent.com'
SCHEMA = probe_mod.VENDORED.read_bytes()
GOOD = fixture_bytes(SYNTHETIC)
WORKFLOW = ROOT / '.github' / 'workflows' / 'live-kev.yml'


class Response:
    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None):
        self.status, self._body, self.headers = status, body, dict(headers or {})

    def read1(self, size: int) -> bytes:
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self) -> None:
        pass


class Net:
    """A fake network: a route is bytes (answered 200 as text/plain), an int (a status), a ``(status, headers)`` tuple
    or an exception class or instance (raised). Every request is recorded."""

    def __init__(self, monkeypatch, routes: dict):
        self.routes, self.calls = routes, []
        monkeypatch.setattr(transport, 'urllib_open', self.open)

    def open(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        answer = self.routes.get(url, 404)
        if isinstance(answer, BaseException) or (isinstance(answer, type) and issubclass(answer, BaseException)):
            raise answer
        if isinstance(answer, bytes):
            return Response(200, answer, {'Content-Type': 'text/plain; charset=utf-8'})
        if isinstance(answer, tuple):
            return Response(answer[0], b'', answer[1])
        return Response(answer)

    @property
    def urls(self) -> list[str]:
        return [url for url, _ in self.calls]


def inprocess(argv, timeout):
    out, err = io.StringIO(), io.StringIO()
    start = time.monotonic()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return probe_mod.CliRun(code, out.getvalue(), err.getvalue(), time.monotonic() - start)


def up(_host):
    return True, 'stub: reachable'


def down_for(*hosts):
    return lambda host: (False, f'stub: {host} unreachable') if host in hosts else (True, 'stub: reachable')


def live_schema(body: bytes = SCHEMA, status: int = 200, error: str = ''):
    return lambda: probe_mod.SchemaFetch(status, body, error)


def run_probe(tmp_path, sources=('cisa-site', 'cisa-github'), **kw) -> dict:
    kw.setdefault('check_host', up)
    kw.setdefault('runner', inprocess)
    kw.setdefault('schema_reader', live_schema())
    return probe_mod.probe(list(sources), tmp_path, 60, **kw)


def catalog(version: str, released: str, *numbers: int, **extra) -> bytes:
    rows = [entry(number, **extra) for number in (numbers or (1, 2))]
    return render(document(rows, catalogVersion=version, dateReleased=released))


# --- blocked versus failed ------------------------------------------------------------------------------------

def _gone(code):
    return (code, {'Retry-After': '0'})


UNKNOWN_FIELD = catalog('2099.03.01', '2099-03-01T18:00:00Z', 1, 2, brandNewField='x')
REDIRECT = (302, {'Location': 'https://evil.example/known_exploited_vulnerabilities.json'})
CASES = {
    # id: (site answer, mirror answer, hosts down, status, site result, mirror result, text the reason must hold)
    'both-ok': (GOOD, GOOD, (), 'passed', 'ok', 'ok', 'cisa-site and cisa-github fetched through the CLI'),
    'site-host-down': (GOOD, GOOD, (SITE_HOST,), 'blocked', 'blocked', 'ok', 'www.cisa.gov unreachable'),
    'both-hosts-down': (GOOD, GOOD, (SITE_HOST, MIRROR_HOST), 'blocked', 'blocked', 'blocked', 'unreachable'),
    'site-connection-refused': (ConnectionError, GOOD, (), 'blocked', 'blocked', 'ok', 'PT-KEV-NETWORK'),
    'site-timeout': (TimeoutError, GOOD, (), 'blocked', 'blocked', 'ok', 'PT-KEV-NETWORK'),
    'site-unavailable-503': (_gone(503), GOOD, (), 'blocked', 'blocked', 'ok', 'PT-KEV-NETWORK'),
    'site-access-denied-403': (403, GOOD, (), 'blocked', 'blocked', 'ok', 'HTTP 403'),
    'site-rate-limited-429': (_gone(429), GOOD, (), 'blocked', 'blocked', 'ok', 'PT-KEV-NETWORK'),
    'site-not-found-404': (404, GOOD, (), 'failed', 'failed', 'ok', 'HTTP 404'),
    'site-server-error-500': (500, GOOD, (), 'failed', 'failed', 'ok', 'HTTP 500'),
    'site-redirects-elsewhere': (REDIRECT, GOOD, (), 'failed', 'failed', 'ok', 'PT-KEV-PROVIDER'),
    'site-serves-html': (b'<html><body>Access denied</body></html>', GOOD, (), 'failed', 'failed', 'ok', 'PT-KEV-FORMAT'),
    'site-count-mismatch': (render(document(count=99)), GOOD, (), 'failed', 'failed', 'ok', 'PT-KEV-VALIDATE'),
    'mirror-not-found-404': (GOOD, 404, (), 'failed', 'ok', 'failed', 'HTTP 404'),
    'unknown-field': (GOOD, UNKNOWN_FIELD, (), 'failed', 'ok', 'failed', 'brandNewField'),
    'failed-beats-blocked': (403, 404, (), 'failed', 'blocked', 'failed', 'cisa-github'),
}


@pytest.mark.parametrize('name', list(CASES), ids=list(CASES))
def test_probe_classifies_blocked_vs_failed(monkeypatch, tmp_path, name):
    site, mirror, down, status, site_result, mirror_result, text = CASES[name]
    net = Net(monkeypatch, {SITE.url: site, MIRROR.url: mirror})
    result = run_probe(tmp_path, check_host=down_for(*down))
    assert (result['status'], result['sources']['cisa-site']['result'], result['sources']['cisa-github']['result']) == (
        status, site_result, mirror_result), result['reason']
    assert text in result['reason'] and len(result['reason']) <= probe_mod.REASON_CHARS
    assert result['mocked'] is False and result['engine'] == 'kev-catalog'
    for host, url in ((SITE_HOST, SITE.url), (MIRROR_HOST, MIRROR.url)):
        assert (url in net.urls) is (host not in down)                 # a host that is down is never asked


def test_a_probe_that_does_not_finish_is_blocked_and_a_garbled_answer_is_failed(tmp_path):
    stalled = probe_mod.classify_fetch(probe_mod.CliRun(None, '', '', 300.0))
    assert stalled['result'] == 'blocked' and '300 s' in stalled['detail']
    for stdout in ('', 'not json', '[]', '{"contract": "something-else"}'):
        garbled = probe_mod.classify_fetch(probe_mod.CliRun(0, stdout, '', 1.0))
        assert garbled['result'] == 'failed' and 'JSON envelope' in garbled['detail']
    usage = json.dumps({'contract': 'enrichment-cli/1', 'status': 'failed', 'error': 'PT-KEV-CONSENT: consent must ...'})
    assert probe_mod.classify_fetch(probe_mod.CliRun(2, usage, '', 1.0))['result'] == 'failed'
    nothing = json.dumps({'contract': 'enrichment-cli/1', 'status': 'failed'})
    assert probe_mod.classify_fetch(probe_mod.CliRun(3, nothing, '', 1.0))['detail'].endswith('no error text')


def test_a_good_run_keeps_the_catalog_summary_and_the_cli_exit(monkeypatch, tmp_path):
    Net(monkeypatch, {SITE.url: GOOD, MIRROR.url: GOOD})
    result = run_probe(tmp_path)
    mirror = result['sources']['cisa-github']
    assert mirror['cli_exit'] == 0 and mirror['reachable'] is True
    assert mirror['catalog']['catalog_version'] == '2099.03.01' and mirror['catalog']['entry_count'] == 4
    assert mirror['catalog']['unknown_fields'] == [] and mirror['catalog']['warnings'] == []
    assert result['cross_check']['result'] == 'ok' and result['schema']['result'] == 'ok'
    assert result['canonical_probed'] is True and result['cli_seconds'] >= 0


def test_the_probe_sends_only_the_fixed_requests_and_each_source_gets_its_own_folder(monkeypatch, tmp_path):
    net = Net(monkeypatch, {SITE.url: GOOD, MIRROR.url: GOOD})
    run_probe(tmp_path)
    assert net.urls == [SITE.url, MIRROR.url]
    assert all(headers == PLAN_HEADERS for _, headers in net.calls)
    assert sorted(path.name for path in tmp_path.iterdir()) == ['cisa-github', 'cisa-site']


# --- the two catalogs together --------------------------------------------------------------------------------

def test_one_release_must_have_one_content(monkeypatch, tmp_path):
    same = ('2099.04.01', '2099-04-01T12:00:00Z')
    Net(monkeypatch, {SITE.url: catalog(*same, 1, 2), MIRROR.url: catalog(*same, 1, 3)})
    result = run_probe(tmp_path)
    assert result['status'] == 'failed' and result['cross_check']['content_digest_equal'] is False
    assert 'release 2099.04.01 has different content on the two sources' in result['reason']
    Net(monkeypatch, {SITE.url: catalog(*same, 1, 2), MIRROR.url: catalog(*same, 1, 2)})
    result = run_probe(tmp_path / 'again')
    assert result['status'] == 'passed' and result['cross_check']['content_digest_equal'] is True


@pytest.mark.parametrize('mirror_released, status, fragment', [
    ('2099-04-01T10:00:00Z', 'passed', 'not comparable'), ('2099-03-29T12:00:00Z', 'passed', '72.0 h apart'),
    ('2099-03-29T11:59:00Z', 'failed', '72.0 h apart'), ('2099-04-04T12:01:00Z', 'failed', '72.0 h apart')],
    ids=['two-hours-behind', 'exactly-72-hours-behind', 'a-minute-over', 'mirror-ahead-by-over-72-hours'])
def test_different_releases_are_not_comparable_but_not_days_apart(monkeypatch, tmp_path, mirror_released, status,
                                                                  fragment):
    Net(monkeypatch, {SITE.url: catalog('2099.04.01', '2099-04-01T12:00:00Z'),
                      MIRROR.url: catalog('2099.03.31', mirror_released)})
    result = run_probe(tmp_path)
    assert result['status'] == status and result['cross_check']['same_release'] is False
    assert 'releases differ' in result['cross_check']['detail'] and fragment in result['cross_check']['detail']
    assert 'releases differ' in result['reason']              # a pass says what was not compared, a failure says why


def test_the_mirror_only_fallback_probes_one_source_and_says_so(monkeypatch, tmp_path):
    net = Net(monkeypatch, {SITE.url: 500, MIRROR.url: GOOD})
    result = run_probe(tmp_path, sources=('cisa-github',))
    assert net.urls == [MIRROR.url] and result['status'] == 'passed'
    assert result['canonical_probed'] is False and result['cross_check']['result'] == 'skipped'
    assert result['reason'].endswith('(mirror only: the canonical address was not probed)')
    assert 'cisa-site' not in result['sources']


def test_a_canonical_only_probe_has_no_schema_to_read(monkeypatch, tmp_path):
    Net(monkeypatch, {SITE.url: GOOD})

    def must_not_read():
        raise AssertionError('the schema is read from the mirror, which was not asked for')
    result = run_probe(tmp_path, sources=('cisa-site',), schema_reader=must_not_read)
    assert result['status'] == 'passed' and result['schema']['result'] == 'skipped'


# --- schema drift ---------------------------------------------------------------------------------------------

def edited(change) -> bytes:
    document_ = json.loads(SCHEMA)
    change(document_)
    return json.dumps(document_, indent=2).encode('utf-8')


def _add_entry_property(doc):
    doc['$defs']['vulnerability']['properties']['epssScore'] = {'type': 'number'}


def _add_top_property(doc):
    doc['properties']['sourceUrl'] = {'type': 'string'}


def _require_notes(doc):
    doc['$defs']['vulnerability']['required'].append('notes')


def _drop_due_date(doc):
    doc['$defs']['vulnerability']['required'].remove('dueDate')


def _loosen_cve_pattern(doc):
    doc['$defs']['vulnerability']['properties']['cveID']['pattern'] = '^CVE-[0-9]{4}-[0-9]+$'


def _loosen_cwe_pattern(doc):
    doc['$defs']['vulnerability']['properties']['cwes']['items']['pattern'] = '^CWE-[0-9]+$'


def _rename_defs(doc):
    doc['definitions'] = doc.pop('$defs')


DRIFT = {
    'identical': (SCHEMA, 'ok', 'identical to the vendored copy'),
    'reformatted': (json.dumps(json.loads(SCHEMA), indent=4).encode(), 'ok', 'only the formatting differs'),
    'entry-property-added': (edited(_add_entry_property), 'failed', 'entry properties: added epssScore'),
    'top-property-added': (edited(_add_top_property), 'failed', 'properties: added sourceUrl'),
    'required-added': (edited(_require_notes), 'failed', 'entry required keys: added notes'),
    'required-removed': (edited(_drop_due_date), 'failed', 'entry required keys: removed dueDate'),
    'cve-pattern': (edited(_loosen_cve_pattern), 'failed', "cveID pattern changed from '^CVE-[0-9]{4}-[0-9]{4,19}$'"),
    'cwe-pattern': (edited(_loosen_cwe_pattern), 'failed', 'cwes pattern changed'),
    'defs-renamed': (edited(_rename_defs), 'failed', 'not a recognisable KEV schema (KeyError)'),
    'html': (b'<html>moved</html>', 'failed', 'not a recognisable KEV schema (JSONDecodeError)'),
    'empty': (b'', 'failed', 'not a recognisable KEV schema'),
    'not-utf8': (b'\xff\xfe{', 'failed', 'not a recognisable KEV schema (UnicodeDecodeError)'),
    'a-list': (b'[]', 'failed', 'not a recognisable KEV schema (TypeError)'),
}


@pytest.mark.parametrize('name', list(DRIFT), ids=list(DRIFT))
def test_probe_detects_schema_drift(monkeypatch, tmp_path, name):
    body, outcome, text = DRIFT[name]
    Net(monkeypatch, {SITE.url: GOOD, MIRROR.url: GOOD})
    result = run_probe(tmp_path, schema_reader=live_schema(body))
    assert result['schema']['result'] == outcome and text in result['schema']['detail']
    assert result['status'] == ('failed' if outcome == 'failed' else 'passed') and text in result['reason']
    assert result['schema']['live_sha256'] == hashlib.sha256(body).hexdigest()
    assert result['schema']['vendored_sha256'] == hashlib.sha256(SCHEMA).hexdigest()
    assert result['schema']['identical'] is (body == SCHEMA)


@pytest.mark.parametrize('fetched, outcome, text', [
    (probe_mod.SchemaFetch(404, b'', 'HTTP 404'), 'failed', 'HTTP 404'),
    (probe_mod.SchemaFetch(500, b'', 'HTTP 500'), 'failed', 'HTTP 500'),
    (probe_mod.SchemaFetch(200, b'', 'larger than 65536 bytes'), 'failed', 'larger than'),
    (probe_mod.SchemaFetch(403, b'', 'HTTP 403'), 'blocked', 'HTTP 403'),
    (probe_mod.SchemaFetch(429, b'', 'HTTP 429'), 'blocked', 'HTTP 429'),
    (probe_mod.SchemaFetch(None, b'', 'TimeoutError: timed out'), 'blocked', 'TimeoutError'),
    (probe_mod.SchemaFetch(None, b'', ''), 'blocked', 'no answer')],
    ids=['404', '500', 'too-large', '403', '429', 'timeout', 'no-answer'])
def test_a_schema_that_cannot_be_read_is_blocked_or_failed_by_why(monkeypatch, tmp_path, fetched, outcome, text):
    assert probe_mod.check_schema(fetched, SCHEMA)['result'] == outcome
    Net(monkeypatch, {SITE.url: GOOD, MIRROR.url: GOOD})
    result = run_probe(tmp_path, schema_reader=lambda: fetched)
    assert result['schema']['result'] == outcome and text in result['schema']['detail']
    assert result['status'] == outcome and text in result['reason']


def test_the_vendored_schema_is_pinned_to_what_the_probe_extracts():
    assert hashlib.sha256(SCHEMA).hexdigest() == '0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7'
    facts = probe_mod.schema_facts(SCHEMA)
    assert facts['required keys'] == ['catalogVersion', 'count', 'dateReleased', 'vulnerabilities']
    assert facts['entry required keys'] == sorted(['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
                                                   'shortDescription', 'requiredAction', 'dueDate'])
    assert len(facts['entry properties']) == 12 and facts['cwes pattern'] == '^CWE-([0-9])+$'
    assert facts['cveID pattern'] == '^CVE-[0-9]{4}-[0-9]{4,19}$'
    assert probe_mod.schema_drift(SCHEMA, SCHEMA) == []


def test_fetch_live_schema_reads_whole_answers_and_reports_the_rest(monkeypatch):
    net = Net(monkeypatch, {probe_mod.SCHEMA_URL: SCHEMA})
    assert probe_mod.fetch_live_schema() == probe_mod.SchemaFetch(200, SCHEMA, '')
    assert net.calls == [(probe_mod.SCHEMA_URL, PLAN_HEADERS)]
    for route, expected in ((404, (404, 'HTTP 404')), ((302, {'Location': 'https://evil.example/s.json'}), (302, 'HTTP 302')),
                            (ConnectionError('refused'), (None, 'ConnectionError: refused')),
                            (b'x' * (probe_mod.MAX_SCHEMA_BYTES + 1), (200, 'larger than 65536 bytes'))):
        Net(monkeypatch, {probe_mod.SCHEMA_URL: route})
        fetched = probe_mod.fetch_live_schema()
        assert (fetched.status, fetched.error) == expected and fetched.body == b''
    Net(monkeypatch, {probe_mod.SCHEMA_URL: b'x' * probe_mod.MAX_SCHEMA_BYTES})
    assert len(probe_mod.fetch_live_schema().body) == probe_mod.MAX_SCHEMA_BYTES


def test_fetch_live_schema_gives_up_on_time_and_on_a_broken_read(monkeypatch):
    Net(monkeypatch, {probe_mod.SCHEMA_URL: SCHEMA})
    late = probe_mod.fetch_live_schema(timeout=0.0)
    assert late.status is None and 'not finished' in late.error

    class Broken(Response):
        def read1(self, size):
            raise ConnectionResetError('reset')
    monkeypatch.setattr(transport, 'urllib_open', lambda url, headers, timeout: Broken(200))
    reset = probe_mod.fetch_live_schema()
    assert reset.status is None and 'ConnectionResetError' in reset.error


# --- the command line and the status file ---------------------------------------------------------------------

def test_run_cli_runs_this_checkouts_cli_and_reports_a_timeout_as_none():
    done = probe_mod.run_cli(['kev', 'plan', '--source', 'cisa-github', '--json'], 120)
    assert done.exit_code == 0 and json.loads(done.stdout)['result']['plan']['host'] == MIRROR_HOST
    assert probe_mod.run_cli(['kev', 'plan', '--source', 'cisa-github', '--json'], 0.001).exit_code is None


def test_run_cli_puts_this_checkouts_source_first_and_keeps_the_callers_path(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(command=command, env=kwargs['env'], cwd=kwargs['cwd'])
        return type('Done', (), {'returncode': 0, 'stdout': '{}', 'stderr': ''})()
    monkeypatch.setenv('PYTHONPATH', 'elsewhere')
    monkeypatch.setattr(probe_mod.subprocess, 'run', fake_run)
    assert probe_mod.run_cli(['kev', 'status'], 5).exit_code == 0
    assert seen['env']['PYTHONPATH'] == str(ROOT / 'src') + probe_mod.os.pathsep + 'elsewhere'
    assert seen['command'][1:] == ['-m', 'patchtrace', 'kev', 'status'] and seen['cwd'] == ROOT


def test_a_long_reason_is_cut_to_what_the_status_table_can_show(monkeypatch, tmp_path):
    assert probe_mod.REASON_CHARS < 300                                    # check_live_status.py cuts a cell at 300
    Net(monkeypatch, {SITE.url: GOOD, MIRROR.url: GOOD})
    many = edited(lambda doc: doc['$defs']['vulnerability']['properties'].update(
        {f'additionalField{number}': {'type': 'string'} for number in range(40)}))
    result = run_probe(tmp_path, schema_reader=live_schema(many))
    assert result['status'] == 'failed' and len(result['schema']['detail']) > probe_mod.REASON_CHARS
    assert len(result['reason']) == probe_mod.REASON_CHARS and result['reason'].startswith('schema: schema drift: ')


def test_main_writes_a_blocked_status_file_and_says_so_loudly(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(probe_mod, 'reachable', down_for(SITE_HOST, MIRROR_HOST))
    out = tmp_path / 'live-status' / 'kev-catalog.json'
    assert probe_mod.main(['--out', str(out), '--work', str(tmp_path / 'w')]) == 0
    rows = check_live_status.load(out.parent)
    assert [(row['engine'], row['status']) for row in rows] == [('kev-catalog', 'blocked')]
    assert 'LIVE ACCEPTANCE BLOCKED' in capsys.readouterr().err
    assert not (tmp_path / 'w' / 'cisa-site').exists()                      # nothing was fetched


def test_main_exits_one_when_the_probe_fails_and_zero_when_it_passes(monkeypatch, tmp_path, capsys):
    net = Net(monkeypatch, {SITE.url: 404, MIRROR.url: GOOD, probe_mod.SCHEMA_URL: SCHEMA})
    monkeypatch.setattr(probe_mod, 'reachable', up)
    monkeypatch.setattr(probe_mod, 'run_cli', inprocess)
    out = tmp_path / 'failed.json'
    assert probe_mod.main(['--out', str(out), '--work', str(tmp_path / 'a')]) == 1
    assert json.loads(out.read_text(encoding='utf-8'))['status'] == 'failed'
    net.routes[SITE.url] = GOOD
    out = tmp_path / 'passed.json'
    assert probe_mod.main(['--out', str(out), '--work', str(tmp_path / 'b')]) == 0
    status = json.loads(out.read_text(encoding='utf-8'))
    assert status['status'] == 'passed' and status['mocked'] is False and status['canonical_probed'] is True
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == {
        'engine': 'kev-catalog', 'status': 'passed', 'reason': status['reason']}
    rows = check_live_status.load(out.parent)
    assert sorted((row['file'], row['engine'], row['status']) for row in rows) == [
        ('failed.json', 'kev-catalog', 'failed'), ('passed.json', 'kev-catalog', 'passed')]
    assert '| passed.json | kev-catalog | passed |' in check_live_status.render(rows)


def test_main_with_the_mirror_only_fallback_never_asks_the_canonical_address(monkeypatch, tmp_path):
    net = Net(monkeypatch, {SITE.url: 500, MIRROR.url: GOOD, probe_mod.SCHEMA_URL: SCHEMA})
    monkeypatch.setattr(probe_mod, 'reachable', up)
    monkeypatch.setattr(probe_mod, 'run_cli', inprocess)
    out = tmp_path / 'mirror.json'
    assert probe_mod.main(['--sources', 'cisa-github', '--out', str(out), '--work', str(tmp_path / 'w')]) == 0
    assert SITE.url not in net.urls and json.loads(out.read_text(encoding='utf-8'))['canonical_probed'] is False


@pytest.mark.parametrize('sources', ['cisa-mirror', '', ',', 'cisa-site,cisa-site', 'cisa-site,www.cisa.gov'],
                         ids=['unknown', 'empty', 'comma', 'twice', 'host-name'])
def test_main_rejects_sources_it_does_not_know(tmp_path, sources):
    with pytest.raises(SystemExit) as info:
        probe_mod.main(['--sources', sources, '--out', str(tmp_path / 'x.json')])
    assert info.value.code == 2 and not (tmp_path / 'x.json').exists()


# --- the workflow ---------------------------------------------------------------------------------------------

def test_the_workflow_is_advisory_scheduled_and_manual_only():
    text = '\n'.join(line for line in WORKFLOW.read_text(encoding='utf-8').splitlines()
                     if not line.lstrip().startswith('#')) + '\n'
    triggers = re.search(r'^on:\n((?:  .*\n|    .*\n|\n)+?)(?=\S)', text, re.MULTILINE).group(1)
    assert re.findall(r'^  ([a-z_]+):', triggers, re.MULTILINE) == ['workflow_dispatch', 'schedule']
    assert 'pull_request' not in text and 'push:' not in text
    assert re.search(r'^permissions:\n  contents: read\n', text, re.MULTILINE)
    assert 'python tools/live_kev_probe.py --sources "$sources" --out build/live-status/kev-catalog.json' in text
    assert '--only-binary=:all:' in text and 'check_live_status.py' in text and 'if: always()' in text


def test_the_workflow_passes_its_only_input_through_the_environment_and_maps_both_values():
    text = WORKFLOW.read_text(encoding='utf-8')
    expressions = [line.strip() for line in text.splitlines() if '${{' in line]
    assert expressions == ['PROBE_SOURCES: ${{ inputs.sources }}']             # never inside a run: script
    assert re.search(r'options: \[both, mirror\]', text) and "= 'mirror'" in text
    assert "sources='cisa-site,cisa-github'" in text and "sources='cisa-github'" in text
    assert str(probe_mod.ENGINE) in text


def test_no_probe_file_hides_a_control_or_invisible_character():
    for path in (ROOT / 'tools' / 'live_kev_probe.py', WORKFLOW, Path(__file__)):
        text = path.read_text(encoding='utf-8')
        odd = sorted({hex(ord(char)) for char in text if ord(char) > 126 or (ord(char) < 32 and char != '\n')})
        assert odd == [], (path.name, odd)
