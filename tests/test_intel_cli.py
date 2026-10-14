"""``patchtrace intelligence import|fetch|explain`` (SPEC-28 sections J and L).

The ``enrichment-cli/1`` envelope, exit codes 0/2/3/4/5, no Qt import, and consent-gated network use. Every network
test drives the real transport with a FAKE opener (an autouse guard makes any real socket connect fail), so none
of this is live evidence. Fixtures are SYNTHETIC; the sample project's artifacts are the hash-mapped synthetic PEs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence import cli as intel_cli
from patchtrace.intelligence import reports
from patchtrace.intelligence.contracts import IntelError, IntelligenceReport
from patchtrace.intelligence.csaf import transport as tr
from patchtrace.intelligence.csaf.identity import project_identities
from patchtrace.intelligence.explain import build_report
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.service import ProjectService

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
SRC = str(Path(cli.__file__).resolve().parents[1])
CVE = 'CVE-2099-10001'
STAMP = '2099-03-01T00:00:00Z'
REV1_FILE = FIXTURES / 'synthetic-advisory-rev1.json'
REV1, REV2 = REV1_FILE.read_bytes(), (FIXTURES / 'synthetic-advisory-rev2.json').read_bytes()
VEX = (FIXTURES / 'synthetic-vex.json').read_bytes()
BASE = 'https://msrc.microsoft.com/csaf'
ADV = f'{BASE}/advisories/2099/pt-synth_cve-2099-10001.json'
VEX_URL = f'{BASE}/vex/2099/pt-synth-vex_cve-2099-10001.json'
UNSAFE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn'})
BS = chr(92)  # a backslash, for the visible \uXXXX markers the CLI prints


@pytest.fixture(autouse=True)
def hermetic(monkeypatch):
    """No test may reach a real network, and the clock is fixed."""
    def refuse(*_args, **_kwargs):
        raise AssertionError('a test tried to open a real socket')
    monkeypatch.setattr(socket.socket, 'connect', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(intel_cli, '_now', lambda: STAMP)


@pytest.fixture
def project(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        return service.root


def run(args, capsys):
    code = cli.main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def one_doc(out: str) -> dict:
    assert out.endswith('\n') and out.count('\n') == 1, out[:300]
    doc = json.loads(out)
    assert doc['contract'] == 'enrichment-cli/1'
    return doc


def unsafe(text: str) -> list[str]:
    return [c for c in text if c != '\n' and unicodedata.category(c) in UNSAFE]


def stored(project: Path):
    with ProjectService.open(project) as service:
        store = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                              service.project.revision)
        return store.advisories()


def imported(project, capsys, file=REV1_FILE, cve=CVE) -> dict:
    code, out, _ = run(['intelligence', 'import', project, file, '--cve', cve, '--json'], capsys)
    assert code == 0
    return one_doc(out)


# ---------------------------------------------------------------------------------------------- the hook

def test_the_hook_registers_the_command_everywhere_the_rules_require():
    assert 'intelligence' in cli.COMMANDS and cli.HANDLERS['intelligence'] is intel_cli.dispatch
    assert cli._command_name(argparse.Namespace(command='intelligence', action='explain')) == 'intelligence explain'
    spec = importlib.util.spec_from_file_location('frozen_smoke', Path(__file__).parents[1] / 'tools' /
                                                  'frozen_smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    assert 'intelligence' in smoke.COMMANDS
    assert {'import', 'fetch', 'explain'} <= set(intel_cli.ACTIONS)


def test_actions_are_an_extension_point(monkeypatch, capsys):
    seen = []

    def register(actions, common):
        common(actions.add_parser('ping', help='test action')).add_argument('word')

    def run_ping(args, cancel):
        seen.append(args.word)
        return 0
    monkeypatch.setitem(intel_cli.ACTIONS, 'ping', intel_cli.Action('ping', register, run_ping))
    assert cli.main(['intelligence', 'ping', 'hello']) == 0 and seen == ['hello']
    assert cli.main(['intelligence', 'bogus']) == 2 and 'invalid choice' in capsys.readouterr().err


def test_importing_the_cli_modules_stays_stdlib_only():
    code = 'import sys\nimport patchtrace.cli\nprint(sorted(m for m in ("pydantic", "PySide6") if m in sys.modules))'
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONPATH=SRC))
    assert result.returncode == 0 and result.stdout.strip() == '[]', result.stderr


def test_the_default_transport_is_the_hardened_one_and_the_import_cap_is_the_transport_cap():
    transport = intel_cli._make_transport(tr.CsafConsent.for_hosts(['msrc.microsoft.com']), cancel=None, cache=None,
                                          offline=False, announce=None)
    assert transport.opener is tr.urllib_open and transport.requests == []
    assert intel_cli.MAX_IMPORT_BYTES == tr.CAPS['document']


@pytest.mark.parametrize('action', ['import', 'fetch', 'explain'])
def test_help_never_imports_qt(action):
    code = ('import sys\nfrom patchtrace import cli\nrc = cli.main(["intelligence", sys.argv[1], "--help"])\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))]\n'
            'print("BAD", bad, file=sys.stderr)\nraise SystemExit(90 if bad else (rc or 0))\n')
    result = subprocess.run([sys.executable, '-c', code, action], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONPATH=SRC))
    assert result.returncode == 0, result.stderr
    assert 'usage:' in result.stdout and '--cve' in result.stdout


# ---------------------------------------------------------------------------------------------- import

def test_import_stores_the_exact_bytes_and_reports_provenance(project, tmp_path, capsys):
    doc = one_doc(run(['intelligence', 'import', project, REV1_FILE, '--cve', CVE, '--json'], capsys)[1])
    result = doc['result']
    assert (doc['command'], doc['status'], doc['warnings']) == ('intelligence import', 'complete', [])
    sha = hashlib.sha256(REV1).hexdigest()
    assert result['source']['sha256'] == sha and result['source']['origin'] == 'local-import'
    assert result['source']['uri'] is None and result['source']['file_name'] == 'synthetic-advisory-rev1.json'
    assert result['source']['retrieved_at'] == STAMP and result['cves'] == ['CVE-2099-10001', 'CVE-2099-10002']
    assert (result['superseded'], result['retrievals']) == (False, 1)
    assert (project / result['source']['raw_path']).read_bytes() == REV1
    assert str(tmp_path) not in json.dumps(doc)  # local paths are never stored or echoed in the record


def test_importing_the_same_bytes_again_adds_a_retrieval_not_a_copy(project, monkeypatch, capsys):
    imported(project, capsys)
    monkeypatch.setattr(intel_cli, '_now', lambda: '2099-04-01T00:00:00Z')
    assert imported(project, capsys)['result']['retrievals'] == 2
    advisories, warnings = stored(project)
    assert len(advisories) == 1 and warnings == []


def test_import_text_mode_prints_a_short_summary(project, capsys):
    code, out, err = run(['intelligence', 'import', project, REV1_FILE, '--cve', CVE], capsys)
    assert code == 0 and err == '' and out.count('\n') == 1
    assert 'imported PT-SYNTH_CVE-2099-10001 revision 1' in out and 'current' in out


def test_import_text_mode_never_prints_raw_controls(project, tmp_path, capsys):
    doc = json.loads(REV1)
    doc['document']['tracking']['id'] = 'PT-' + chr(0x202E) + 'EVIL\u001b[31m-1'
    path = tmp_path / 'weird.json'
    path.write_text(json.dumps(doc), encoding='utf-8')
    code, out, err = run(['intelligence', 'import', project, path, '--cve', CVE], capsys)
    assert code == 0 and not unsafe(out + err)
    assert f'PT-{BS}u202eEVIL{BS}u001b[31m-1' in out


def write_json(tmp_path: Path, name: str, content) -> Path:
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    return path


def invalid_csaf() -> dict:
    doc = json.loads(REV1)
    doc['vulnerabilities'][0]['product_status']['fixed'].append('PT-UNDEFINED')
    return doc


def surrogate_csaf() -> dict:
    doc = json.loads(REV1)
    doc['vulnerabilities'][0]['notes'][0]['text'] = 'lone \ud800 surrogate'
    return doc


REFUSED = {
    'not-json': b'this is not json',
    'duplicate-key': b'{"document": 1, "document": 2}',
    'byte-order-mark': b'\xef\xbb\xbf' + REV1,
    'empty': b'',
    'invalid-csaf': invalid_csaf,
    'lone-surrogate': surrogate_csaf,
    'cve-not-listed': REV1,
}


@pytest.mark.parametrize('case', REFUSED)
def test_a_refused_local_file_exits_2_and_writes_nothing(case, project, tmp_path, capsys):
    content = REFUSED[case]
    content = content() if callable(content) else content
    path = write_json(tmp_path, 'candidate.json', content)
    cve = 'CVE-2099-99999' if case == 'cve-not-listed' else CVE
    code, out, err = run(['intelligence', 'import', project, path, '--cve', cve, '--json'], capsys)
    assert code == 2 and 'Traceback' not in err and 'error: ' in err
    doc = one_doc(out)
    assert doc['status'] == 'failed' and doc['result'] is None and doc['error']
    assert not (project / 'intelligence').exists() and stored(project) == ([], [])


def test_further_validation_findings_are_listed_on_stderr(project, tmp_path, capsys):
    doc = json.loads(REV1)
    doc['vulnerabilities'][0]['product_status']['fixed'] += ['PT-UNDEFINED-1', 'PT-UNDEFINED-2']
    path = write_json(tmp_path, 'two-errors.json', doc)
    code, out, err = run(['intelligence', 'import', project, path, '--cve', CVE], capsys)
    assert code == 2 and out == '' and 'PT-INTEL-VALIDATE: 2 validation error(s)' in err
    assert 'also [6.1.1] /vulnerabilities/0/product_status/fixed/5: product id PT-UNDEFINED-2' in err
    assert err.count('PT-UNDEFINED-1') == 1 and err.count('PT-UNDEFINED-2') == 1  # the first is in the error line


@pytest.mark.parametrize('case', ['missing', 'directory', 'oversize'])
def test_unusable_input_paths_exit_2(case, project, tmp_path, monkeypatch, capsys):
    path = {'missing': tmp_path / 'absent.json', 'directory': tmp_path,
            'oversize': write_json(tmp_path, 'big.json', REV1)}[case]
    if case == 'oversize':
        monkeypatch.setattr(intel_cli, 'MAX_IMPORT_BYTES', 100)
    code, _, err = run(['intelligence', 'import', project, path, '--cve', CVE], capsys)
    assert code == 2 and 'Traceback' not in err and not (project / 'intelligence').exists()


def test_a_missing_project_and_a_bad_cve_exit_2(project, tmp_path, capsys):
    assert run(['intelligence', 'import', tmp_path / 'nothing', REV1_FILE, '--cve', CVE], capsys)[0] == 2
    fullwidth = 'CVE-2099-' + chr(0xFF11) * 5  # digits that the Unicode-aware \d would accept
    for bad in ('not-a-cve', 'CVE-99-1', 'CVE-2099-1234567890123456789012', fullwidth):
        code, _, err = run(['intelligence', 'import', project, REV1_FILE, '--cve', bad], capsys)
        assert code == 2 and 'Traceback' not in err
    assert imported(project, capsys, cve='cve-2099-10001')['command'] == 'intelligence import'  # case is normalised


def test_cancellation_exits_5(project, monkeypatch, capsys):
    def interrupted(self, *_args, **_kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(AdvisoryStore, 'add', interrupted)
    code, out, _ = run(['intelligence', 'import', project, REV1_FILE, '--cve', CVE, '--json'], capsys)
    assert code == 5 and one_doc(out)['status'] == 'cancelled'

    def cancelled(self, *_args, **_kwargs):
        raise IntelError('PT-INTEL-CANCEL', 'import cancelled', recoverable=True)
    monkeypatch.setattr(AdvisoryStore, 'add', cancelled)
    code, out, _ = run(['intelligence', 'import', project, REV1_FILE, '--cve', CVE, '--json'], capsys)
    assert code == 5 and one_doc(out)['status'] == 'cancelled'


def test_a_storage_failure_is_a_runtime_error(project, monkeypatch, capsys):
    def broken(self, *_args, **_kwargs):
        raise IntelError('PT-INTEL-STORAGE', 'cannot write')
    monkeypatch.setattr(AdvisoryStore, 'add', broken)
    code, _, err = run(['intelligence', 'import', project, REV1_FILE, '--cve', CVE], capsys)
    assert code == 3 and 'PT-INTEL-STORAGE' in err


# ---------------------------------------------------------------------------------------------- explain

def test_explain_json_is_the_in_process_report(project, capsys):
    imported(project, capsys)
    code, out, err = run(['intelligence', 'explain', project, '--cve', CVE, '--json'], capsys)
    doc = one_doc(out)
    assert code == 0 and err == '' and (doc['command'], doc['status']) == ('intelligence explain', 'complete')
    assert doc['result']['export'] is None
    with ProjectService.open(project) as service:
        advisories, _ = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                                      service.project.revision).for_cve(CVE)
        expected = build_report(CVE, advisories, *project_identities(service.project.artifacts, service.root))
    assert doc['result']['report'] == expected.model_dump(mode='json')
    assert IntelligenceReport.model_validate_json(json.dumps(doc['result']['report'])) == expected


@pytest.mark.parametrize('name', ['report.md', 'report.json', 'REPORT.MD'])
def test_explain_export_writes_exactly_the_rendered_bytes(name, project, tmp_path, capsys):
    imported(project, capsys)
    target = tmp_path / name
    code, out, _ = run(['intelligence', 'explain', project, '--cve', CVE, '--export', target, '--json'], capsys)
    result = one_doc(out)['result']
    assert code == 0
    export, data = result['export'], target.read_bytes()
    fmt = 'json' if name.endswith('.json') else 'md'
    report = IntelligenceReport.model_validate_json(json.dumps(result['report']))
    assert data == reports.render(report, fmt) and b'\r' not in data
    assert export == {'format': fmt, 'path': str(target), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith('.partial')] == []


def test_explain_export_problems_are_found_before_any_work(project, tmp_path, monkeypatch, capsys):
    imported(project, capsys)

    def never(*_args, **_kwargs):
        raise AssertionError('work started before the export target was checked')
    monkeypatch.setattr('patchtrace.intelligence.explain.build_report', never)
    for target in (tmp_path / 'report.txt', tmp_path / 'report', tmp_path / 'missing' / 'report.md', tmp_path):
        code, _, err = run(['intelligence', 'explain', project, '--cve', CVE, '--export', target], capsys)
        assert code == 2 and 'Traceback' not in err
    assert not (tmp_path / 'report.txt').exists()


def test_explain_without_a_stored_advisory_is_a_legitimate_no_result(project, capsys):
    code, out, err = run(['intelligence', 'explain', project, '--cve', CVE, '--json'], capsys)
    doc = one_doc(out)
    assert code == 4 and err == '' and doc['status'] == 'complete'
    assert doc['result'] == {'cve': CVE, 'report': None, 'export': None}
    imported(project, capsys)
    code, out, _ = run(['intelligence', 'explain', project, '--cve', 'CVE-2099-77777'], capsys)
    assert code == 4 and 'no stored advisory lists CVE-2099-77777' in out


def test_explain_labels_analyst_assertions(project, capsys):
    imported(project, capsys)
    code, out, _ = run(['intelligence', 'explain', project, '--cve', CVE, '--older-product', 'PT-100-1',
                        '--older-product', 'PT-100-1', '--newer-product', 'PT-100-2', '--json'], capsys)
    report = one_doc(out)['result']['report']
    older, newer = report['applicability']['older'], report['applicability']['newer']
    assert code == 0 and older['identity']['asserted_product_ids'] == ['PT-100-1']
    assert 'asserted-product-id' in {m['basis'] for m in older['mappings']}
    assert newer['identity']['asserted_product_ids'] == ['PT-100-2']


def test_explain_argument_validation(project, capsys):
    imported(project, capsys)
    many = [x for i in range(65) for x in ('--older-product', f'P{i}')]
    for extra in (many, ['--older-product', ''], ['--newer-product', 'PT\x1b[31m'], ['--older-product', 'x' * 1001]):
        code, _, err = run(['intelligence', 'explain', project, '--cve', CVE, *extra], capsys)
        assert code == 2 and 'Traceback' not in err, extra[:2]


def test_explain_text_mode_is_a_sanitised_summary(project, tmp_path, capsys):
    imported(project, capsys, file=FIXTURES / 'injection' / 'hostile-advisory.json')
    code, out, err = run(['intelligence', 'explain', project, '--cve', CVE], capsys)
    assert code == 0 and err == '' and not unsafe(out)
    assert out.startswith('CVE-2099-10001: 1 stored source(s), 1 current') and 'resolution: affected' in out
    assert 'resolution: fixed' in out and 'does not show' in out


def test_explain_with_a_damaged_source_is_partial_and_says_so(project, capsys):
    imported(project, capsys)
    imported(project, capsys, file=FIXTURES / 'synthetic-advisory-rev2.json')
    advisories, _ = stored(project)
    first = advisories[0]  # revision 1: its facts and its exact bytes both become unusable, so it is skipped
    (project / 'intelligence' / 'csaf' / 'facts' / f'{first.facts.facts_id}.json').write_text('{}', encoding='utf-8')
    (project / first.source.raw_path).write_bytes(b'tampered')
    code, out, _ = run(['intelligence', 'explain', project, '--cve', CVE, '--json'], capsys)
    doc = one_doc(out)
    assert code == 3 and doc['status'] == 'partial' and doc['result']['report'] is not None
    assert any('PT-INTEL-INTEGRITY' in w for w in doc['warnings'])
    assert [s['source']['revision'] for s in doc['result']['report']['sources']] == ['2']


def test_store_warnings_never_reach_the_terminal_raw(project, tmp_path, capsys):
    doc = json.loads(REV1)
    doc['document']['tracking']['id'] = 'PT-' + chr(0x202E) + 'EVIL\u001b[31m-1'
    path = write_json(tmp_path, 'weird.json', doc)
    imported(project, capsys, file=path)
    (advisories, _) = stored(project)
    (project / 'intelligence' / 'csaf' / 'facts' / f'{advisories[0].facts.facts_id}.json').write_text(
        '{"tampered": true}', encoding='utf-8')
    code, out, err = run(['intelligence', 'explain', project, '--cve', CVE], capsys)
    assert code == 3 and 'warning: ' in err and not unsafe(out + err)
    assert f'{BS}u202e' in err and f'{BS}u001b' in err
    code, out, _ = run(['intelligence', 'explain', project, '--cve', CVE, '--json'], capsys)
    assert out.isascii() and any(chr(0x202E) in w for w in json.loads(out)['warnings'])  # JSON escapes, data intact


def test_explain_cancellation_exits_5(project, monkeypatch, capsys):
    imported(project, capsys)

    def cancelled(*_args, **_kwargs):
        raise IntelError('PT-INTEL-CANCEL', 'explain cancelled', recoverable=True)
    monkeypatch.setattr('patchtrace.intelligence.explain.build_report', cancelled)
    code, out, _ = run(['intelligence', 'explain', project, '--cve', CVE, '--json'], capsys)
    assert code == 5 and one_doc(out)['status'] == 'cancelled'


# ---------------------------------------------------------------------------------------------- fetch (FAKE opener)

class Response:
    def __init__(self, status, body=b''):
        self.status, self._body, self.headers = status, body, {}

    def read(self, size):
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self):
        pass


def routes(**overrides) -> dict[str, tuple[int, bytes]]:
    table = {
        f'{BASE}/provider-metadata.json': (200, (FIXTURES / 'discovery' / 'provider-metadata.json').read_bytes()),
        f'{BASE}/advisories/index.txt': (200, (FIXTURES / 'discovery' / 'index-advisories.txt').read_bytes()),
        f'{BASE}/vex/index.txt': (200, (FIXTURES / 'discovery' / 'index-vex.txt').read_bytes()),
        ADV: (200, REV2),
        f'{ADV}.sha256': (200, f'{hashlib.sha256(REV2).hexdigest()}  pt-synth_cve-2099-10001.json\n'.encode()),
        VEX_URL: (200, VEX),
    }
    table.update(overrides)
    return table


@pytest.fixture
def fake_net(monkeypatch):
    """install(routes, on_open=None) -> list of (url, headers) the fake server saw; replaces the CLI's transport
    factory. ``on_open(cancel)`` runs on every request with the CLI's cancellation event."""
    def install(table, on_open=None):
        calls: list[tuple[str, dict]] = []
        state: dict = {}

        def opener(url, headers, timeout):
            calls.append((url, dict(headers)))
            if on_open is not None:
                on_open(state['cancel'])
            status, body = table.get(url, (404, b''))
            if isinstance(status, Exception):
                raise status
            return Response(status, body)

        def factory(consent, *, cancel, cache, offline, announce):
            state['cancel'] = cancel
            return tr.CsafTransport(consent, opener=opener, cancel=cancel, cache=cache, offline=offline,
                                    announce=announce, sleep=lambda s, c: None,
                                    now=lambda: datetime(2099, 3, 1, tzinfo=UTC))
        monkeypatch.setattr(intel_cli, '_make_transport', factory)
        return calls
    return install


CONSENT = ['--consent-hosts', 'msrc.microsoft.com']


def fetch(project, capsys, *extra, cve=CVE):
    code, out, err = run(['intelligence', 'fetch', project, '--cve', cve, '--json', *extra], capsys)
    return code, out, err


def test_fetch_downloads_validates_and_stores_with_provenance(project, fake_net, capsys):
    calls = fake_net(routes())
    code, out, err = fetch(project, capsys, *CONSENT)
    doc = one_doc(out)
    assert code == 0 and (doc['command'], doc['status']) == ('intelligence fetch', 'complete')
    urls = [url for url, _ in calls]
    assert urls[:3] == [f'{BASE}/provider-metadata.json', f'{BASE}/advisories/index.txt', f'{BASE}/vex/index.txt']
    assert {ADV, f'{ADV}.sha256', VEX_URL} <= set(urls) and all(u.startswith(f'{BASE}/') for u in urls)
    assert all(set(headers) == {'Accept', 'User-Agent'} and headers['User-Agent'] == 'PatchTrace'
               for _, headers in calls)
    assert [line for line in err.splitlines() if line.startswith('request: GET ')] == [f'request: GET {u}' for u in urls]
    advisories, warnings = stored(project)
    assert warnings == [] and {a.source.origin for a in advisories} == {'https-fetch'}
    states = {a.source.uri: a.source.authenticity_state for a in advisories}
    assert states == {ADV: 'tls-allowlisted-host-hash-match', VEX_URL: 'tls-allowlisted-host'}
    assert [row['source']['uri'] for row in doc['result']['stored']] == [ADV, VEX_URL]
    assert doc['result']['requests'] == urls and doc['result']['offline'] is False
    assert any('no .sha256 file' in w for w in doc['warnings'])
    with ProjectService.open(project) as service:  # nothing about the project or the binaries was requested
        secrets = [str(project), service.project.id, *[a.sha256 for a in service.project.artifacts]]
    assert not [s for s in secrets if any(s in url or s in json.dumps(h) for url, h in calls)]


def test_fetched_advisories_feed_the_offline_explain(project, fake_net, capsys):
    fake_net(routes())
    assert fetch(project, capsys, *CONSENT)[0] == 0
    code, out, _ = run(['intelligence', 'explain', project, '--cve', CVE, '--json'], capsys)
    report = one_doc(out)['result']['report']
    assert code == 0 and {s['source']['origin'] for s in report['sources']} == {'https-fetch'}
    assert report['applicability']['older']['resolution'] == 'affected'


@pytest.mark.parametrize('flags', [[], ['--consent-hosts', ''], ['--consent-hosts', 'evil.example'],
                                   ['--consent-hosts', 'msrc.microsoft.com,evil.example'],
                                   ['--consent-hosts', 'nvd.nist.gov']],
                         ids=['absent', 'empty', 'foreign', 'extra-host', 'other-provider'])
def test_no_request_is_made_without_exact_consent(flags, project, fake_net, capsys):
    calls = fake_net(routes())
    code, _, err = fetch(project, capsys, *flags)
    assert code == 2 and 'Traceback' not in err and calls == []
    assert stored(project) == ([], [])


@pytest.mark.parametrize('url', ['https://evil.example/csaf/provider-metadata.json',
                                 'http://msrc.microsoft.com/csaf/provider-metadata.json',
                                 'https://msrc.microsoft.com/other/provider-metadata.json',
                                 'https://msrc.microsoft.com/csaf/provider-metadata.json?x=1',
                                 'https://msrc.microsoft.com/csaf/other.json'],
                         ids=['host', 'http', 'path', 'query', 'name'])
def test_a_provider_metadata_url_outside_the_allowlist_is_refused_before_any_request(url, project, fake_net, capsys):
    calls = fake_net(routes())
    code, _, err = fetch(project, capsys, *CONSENT, '--provider-metadata', url)
    assert code == 2 and calls == [] and 'Traceback' not in err


def test_a_custom_provider_metadata_inside_the_allowlist_is_used(project, fake_net, capsys):
    custom = 'https://msrc.microsoft.com/.well-known/csaf/provider-metadata.json'
    table = routes()
    table[custom] = table[f'{BASE}/provider-metadata.json']
    calls = fake_net(table)
    assert fetch(project, capsys, *CONSENT, '--provider-metadata', custom)[0] == 0
    assert calls[0][0] == custom


def test_no_index_candidate_is_a_legitimate_no_result_and_nothing_is_guessed(project, fake_net, capsys):
    calls = fake_net(routes())
    code, out, _ = fetch(project, capsys, *CONSENT, cve='CVE-2099-10002')
    doc = one_doc(out)
    assert code == 4 and doc['status'] == 'complete' and doc['result']['candidates'] == []
    assert not [url for url, _ in calls if '10002' in url] and stored(project) == ([], [])


def test_an_integrity_mismatch_stores_nothing(project, fake_net, capsys):
    fake_net(routes(**{f'{ADV}.sha256': (200, b'0' * 64)}))
    code, out, err = fetch(project, capsys, *CONSENT)
    assert code == 3 and 'PT-INTEL-INTEGRITY' in err and one_doc(out)['status'] == 'failed'
    assert stored(project) == ([], []) and not (project / 'intelligence').exists()


def test_candidates_that_are_all_unacceptable_fail_with_the_reasons(project, fake_net, capsys):
    other = json.loads(VEX)
    other['vulnerabilities'][0]['cve'] = 'CVE-2099-77777'
    fake_net(routes(**{ADV: (200, b'{"document": {}, "document": {}}'), f'{ADV}.sha256': (404, b''),
                       VEX_URL: (200, json.dumps(other).encode())}))
    code, out, _ = fetch(project, capsys, *CONSENT)
    doc = one_doc(out)
    assert code == 3 and doc['status'] == 'failed' and doc['result']['stored'] == []
    assert any('duplicate key' in w for w in doc['warnings'])
    assert any('does not list CVE-2099-10001' in w for w in doc['warnings'])
    assert stored(project) == ([], [])


def test_one_acceptable_candidate_is_kept_and_the_other_is_a_warning(project, fake_net, capsys):
    fake_net(routes(**{VEX_URL: (200, b'not json')}))
    code, out, _ = fetch(project, capsys, *CONSENT)
    doc = one_doc(out)
    assert code == 0 and [r['source']['uri'] for r in doc['result']['stored']] == [ADV]
    assert any('rejected' in w for w in doc['warnings'])


@pytest.mark.parametrize('failure', [(500, b''), (ConnectionError('refused'), b'')], ids=['http-500', 'refused'])
def test_provider_and_network_failures_are_runtime_errors(failure, project, fake_net, capsys):
    fake_net(routes(**{f'{BASE}/provider-metadata.json': failure}))
    code, out, err = fetch(project, capsys, *CONSENT)
    assert code == 3 and 'Traceback' not in err and one_doc(out)['status'] == 'failed'
    assert 'PT-INTEL-PROVIDER' in err or 'PT-INTEL-NETWORK' in err


def test_a_provider_that_offers_only_rolie_feeds_is_unsupported(project, fake_net, capsys):
    meta = json.loads((FIXTURES / 'discovery' / 'provider-metadata.json').read_text(encoding='utf-8'))
    meta['distributions'] = [d for d in meta['distributions'] if 'rolie' in d]
    fake_net(routes(**{f'{BASE}/provider-metadata.json': (200, json.dumps(meta).encode())}))
    code, out, err = fetch(project, capsys, *CONSENT)
    assert code == 3 and 'PT-INTEL-UNSUPPORTED' in err and one_doc(out)['status'] == 'failed'


def test_a_missing_default_metadata_location_hints_at_the_override(project, fake_net, capsys):
    fake_net(routes(**{f'{BASE}/provider-metadata.json': (404, b'')}))
    code, _, err = fetch(project, capsys, *CONSENT)
    assert code == 3 and 'PT-INTEL-NOTFOUND' in err and '--provider-metadata' in err


def test_offline_mode_reads_only_the_cache_and_needs_no_consent(project, fake_net, tmp_path, capsys):
    cache = tmp_path / 'cache'
    calls = fake_net(routes())
    assert fetch(project, capsys, *CONSENT, '--cache-dir', cache)[0] == 0 and calls
    calls.clear()

    def forbidden(_cancel):
        raise AssertionError('offline mode opened the network')
    fake_net(routes(), on_open=forbidden)
    code, out, err = fetch(project, capsys, '--offline', '--cache-dir', cache)
    doc = one_doc(out)
    assert code == 0 and doc['result']['offline'] is True and doc['result']['requests'] == []
    assert len(doc['result']['stored']) == 2 and 'request: GET' not in err
    assert {r['retrievals'] for r in doc['result']['stored']} == {1}  # a replay from the cache is no new acquisition


def test_a_cache_path_that_is_a_file_is_refused(project, fake_net, tmp_path, capsys):
    calls = fake_net(routes())
    occupied = write_json(tmp_path, 'cache', b'not a directory')
    for extra in (['--cache-dir', occupied], ['--offline', '--cache-dir', occupied]):
        code, _, err = fetch(project, capsys, *CONSENT, *extra)
        assert code == 2 and 'Traceback' not in err and calls == []


def test_offline_mode_needs_an_existing_cache_directory(project, fake_net, tmp_path, capsys):
    calls = fake_net(routes())
    assert fetch(project, capsys, '--offline')[0] == 2
    assert fetch(project, capsys, '--offline', '--cache-dir', tmp_path / 'absent')[0] == 2
    empty = tmp_path / 'empty'
    empty.mkdir()
    code, _, err = fetch(project, capsys, '--offline', '--cache-dir', empty)
    assert code == 3 and 'offline cache' in err and calls == []


def test_fetch_cancellation_exits_5(project, fake_net, capsys):
    fake_net(routes(), on_open=lambda cancel: cancel.set())  # the first request cancels the run
    code, out, _ = fetch(project, capsys, *CONSENT)
    assert code == 5 and one_doc(out)['status'] == 'cancelled' and stored(project) == ([], [])


# ---------------------------------------------------------------------------------------------- real processes

def process(*args, cwd=None):
    return subprocess.run([sys.executable, '-m', 'patchtrace', *map(str, args)], capture_output=True, text=True,
                          encoding='utf-8', env=dict(os.environ, PYTHONPATH=SRC), cwd=cwd, timeout=120)


def test_exit_codes_and_single_json_documents_through_real_processes(project, tmp_path):
    ok = process('intelligence', 'import', project, REV1_FILE, '--cve', CVE, '--json')
    assert ok.returncode == 0 and one_doc(ok.stdout)['status'] == 'complete' and 'Traceback' not in ok.stderr
    explained = process('intelligence', 'explain', project, '--cve', CVE, '--json')
    assert explained.returncode == 0 and one_doc(explained.stdout)['result']['report']['cve'] == CVE
    exported = tmp_path / 'report.md'
    assert process('intelligence', 'explain', project, '--cve', CVE, '--export', exported).returncode == 0
    assert exported.read_bytes().startswith(b'# Advisory report for `CVE-2099-10001`\n')
    nothing = process('intelligence', 'explain', project, '--cve', 'CVE-2099-77777', '--json')
    assert nothing.returncode == 4 and one_doc(nothing.stdout)['result']['report'] is None
    bad = process('intelligence', 'import', project, REV1_FILE, '--cve', 'nope', '--json')
    assert bad.returncode == 2 and 'Traceback' not in bad.stderr and bad.stdout == ''
    refused = process('intelligence', 'fetch', project, '--cve', CVE, '--json')
    assert refused.returncode == 2 and 'Traceback' not in refused.stderr
    empty = tmp_path / 'empty'
    empty.mkdir()
    runtime = process('intelligence', 'fetch', project, '--cve', CVE, '--offline', '--cache-dir', empty, '--json')
    assert runtime.returncode == 3 and one_doc(runtime.stdout)['status'] == 'failed'
    assert 'Traceback' not in runtime.stderr


def test_cancellation_exits_5_through_a_real_process(project):
    code = ('import sys\nfrom patchtrace import cli\nfrom patchtrace.intelligence.storage import AdvisoryStore\n'
            'def interrupted(*_args, **_kwargs):\n    raise KeyboardInterrupt\n'
            'AdvisoryStore.add = interrupted\n'
            'raise SystemExit(cli.main(["intelligence", "import", sys.argv[1], sys.argv[2], "--cve", sys.argv[3],'
            ' "--json"]))\n')
    result = subprocess.run([sys.executable, '-c', code, str(project), str(REV1_FILE), CVE], capture_output=True,
                            text=True, encoding='utf-8', env=dict(os.environ, PYTHONPATH=SRC), timeout=120)
    assert result.returncode == 5 and one_doc(result.stdout)['status'] == 'cancelled'
    assert 'Traceback' not in result.stderr and stored(project) == ([], [])


def test_no_action_imports_qt(project, tmp_path):
    code = ('import sys\nfrom patchtrace import cli\nproject, file, empty = sys.argv[1:4]\n'
            'codes = [cli.main(["intelligence", "import", project, file, "--cve", "CVE-2099-10001", "--json"]),\n'
            '         cli.main(["intelligence", "explain", project, "--cve", "CVE-2099-10001", "--json"]),\n'
            '         cli.main(["intelligence", "fetch", project, "--cve", "CVE-2099-10001", "--offline",\n'
            '                   "--cache-dir", empty, "--json"])]\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))]\n'
            'print("BAD", bad, codes, file=sys.stderr)\nraise SystemExit(90 if bad else 0)\n')
    empty = tmp_path / 'empty'
    empty.mkdir()
    result = subprocess.run([sys.executable, '-c', code, str(project), str(REV1_FILE), str(empty)],
                            capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC))
    assert result.returncode == 0 and 'BAD []' in result.stderr, result.stderr
