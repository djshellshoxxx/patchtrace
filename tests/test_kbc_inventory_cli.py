"""PW-01 CLI journeys using real parser/store/service and authored offline inputs.

Transport tests inject response bytes; they are not live Microsoft acceptance.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import FixedClock, Kb
from kbc_k5_support import record as winbindex_record

from patchtrace.kbcorrelation import cli, inventory_service, wiring
from patchtrace.kbcorrelation.service import KbService, Outcome
from patchtrace.kbcorrelation.sources import inventory_fetch
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
CSV = b'File name,File version,File size,Architecture\r\nExampleNet.SYS,1.2.3.4,128,x64\r\n'
PAGE = 'https://support.microsoft.com/help/5099001'
CSV_URL = 'https://download.microsoft.com/download/a/b/c/files.csv'
GO = 'https://go.microsoft.com/fwlink/?linkid=1234567'
HTML = (f'<p>File information for this cumulative update '
        f'<a href="{GO}">file information</a>.</p>'
        '<p>Servicing stack update (SSU) '
        '<a href="https://go.microsoft.com/fwlink/?linkid=9876543">file information</a>.</p>').encode()


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@pytest.fixture
def csv_file(tmp_path):
    path = tmp_path / 'inventory.csv'
    path.write_bytes(CSV)
    return path


def import_csv(kb, path, *flags):
    code, document, error = kb('inventory', 'import', str(path), '--kb', '5099001', *flags)
    assert code == 0, (document, error)
    return document['result']


@pytest.mark.parametrize('verb', ['', 'import', 'list', 'show', 'select', 'links', 'plan', 'fetch'])
@pytest.mark.parametrize('flag', ['--help', '-h'])
def test_help_never_initializes_service_ports(monkeypatch, capsys, verb, flag):
    def forbidden(*_args):
        pytest.fail('help initialized service ports')

    monkeypatch.setattr(cli.Context, '_env', forbidden)
    argv = ['inventory', *([verb] if verb else []), flag]
    assert cli.main(argv) == 0
    output = capsys.readouterr()
    assert 'usage:' in output.out and not output.err
    if verb == 'fetch':
        assert '--consent-host' in output.out and '--consent-plan' in output.out and '--plan-file' in output.out
    if not verb:
        assert all(name in output.out for name in ('import', 'list', 'show', 'select', 'links', 'plan', 'fetch'))


def test_top_level_help_lists_inventory(capsys):
    assert cli.main(['--help']) == 0
    assert 'inventory' in capsys.readouterr().out


def test_cli_help_imports_no_qt_and_initializes_no_network():
    source = Path(__file__).resolve().parents[1] / 'src'
    script = '''
import socket
import sys
def forbidden(*args, **kwargs):
    raise AssertionError('help requested network')
class ForbiddenSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        forbidden()
socket.socket = ForbiddenSocket
socket.getaddrinfo = socket.create_connection = forbidden
from patchtrace.kbcorrelation import cli
assert cli.main(['inventory', 'fetch', '--help']) == 0
assert not any(name.startswith(('PySide6', 'PyQt')) for name in sys.modules)
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=False,
                            env={**os.environ, 'PYTHONPATH': str(source)}, timeout=20)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('argv', [
    [], ['unknown'], ['import', 'input.csv'], ['show'], ['select', 'a' * 64, 'b' * 64],
    ['links', 'page.html'], ['plan'], ['fetch', '--plan-file', 'plan.json'],
    ['list', '--limit', 'zero'], ['show', 'a' * 64, '--architecture', 'guess'],
])
def test_invalid_grammar_is_one_exit_2_envelope_without_writes(kb, argv):
    code, document, error = kb('inventory', *argv)
    assert code == 2 and document['contract'] == 'enrichment-cli/1' and document['status'] == 'failed'
    assert document['command'].startswith('kb inventory') and error.startswith('error:')
    assert not kb.workspace.exists()


def test_empty_listing_is_read_only_and_exit_4(kb):
    code, document, error = kb('inventory', 'list')
    assert code == 4 and document['command'] == 'kb inventory list' and not error
    assert document['result']['inventories'] == [] and document['result']['total'] == 0
    assert not kb.workspace.exists()


def test_import_preserves_bytes_context_and_unverified_assertion(kb, csv_file):
    result = import_csv(kb, csv_file, '--asserted-source', CSV_URL, '--offline', '--locale', 'invariant')
    inventory = result['inventory']
    assert inventory['context']['kb'] == 'KB5099001' and inventory['context']['locale'] == 'invariant'
    assert inventory['source']['sha256'] == hashlib.sha256(CSV).hexdigest()
    assert inventory['source']['authenticity'] == 'unverified-local-file' and inventory['source']['uri'] is None
    assert inventory['asserted_source'] == CSV_URL and inventory['retrieval'] is None
    assert inventory['accepted_count'] == 1 and not inventory['truncated'] and not result['already_present']
    repeated = import_csv(kb, csv_file, '--asserted-source', CSV_URL, '--offline', '--locale', 'invariant')
    assert repeated['import_id'] == result['import_id'] and repeated['already_present']
    with WorkspaceStore(kb.workspace) as ws:
        assert ws.read_object(inventory['source']['sha256']) == CSV
    code, document, error = kb('inventory', 'list')
    assert code == 0 and document['result']['total'] == 1 and not error


def test_show_filters_rows_and_preserves_reference_and_integer_precision(kb, tmp_path):
    path = tmp_path / 'large-size.csv'
    path.write_bytes(('File name;File version;File size;Architecture\r\n'
                      'Big.DLL;1.2.3.4;9.007.199.254.740.993;x64\r\n'
                      'other.dll;1.2.3.4;128;arm64\r\n').encode('utf-16'))
    imported = import_csv(kb, path, '--delimiter', 'semicolon', '--locale', 'de-DE')
    code, document, error = kb('inventory', 'show', imported['import_id'], '--name', 'BIG.',
                              '--architecture', 'amd64', '--state', 'metadata-only', '--limit', '1')
    assert code == 0 and not error and document['command'] == 'kb inventory show'
    result = document['result']
    assert result['filtered_count'] == 1 and not result['entries_truncated']
    entry = result['entries'][0]
    assert entry['size_bytes'] == 9_007_199_254_740_993 and entry['basename'] == 'big.dll'
    assert entry['reference']['logical_record'] == entry['reference']['line_start'] == 2
    assert entry['reference']['raw_sha256'] == imported['inventory']['source']['sha256']
    assert result['inventory']['source']['authenticity'] == 'unverified-local-file'


def test_partial_import_counts_duplicates_conflicts_rejections_and_remains_inspectable(kb, tmp_path):
    path = tmp_path / 'partial.csv'
    path.write_bytes(CSV + CSV.split(b'\r\n')[1] + b'\r\n'
                     b'ExampleNet.SYS,1.2.3.5,129,x64\r\n../bad.sys,1.2.3.4,5,x64\r\n')
    code, document, error = kb('inventory', 'import', str(path), '--kb', 'KB5099001')
    assert code == 3 and document['status'] == 'partial' and not error
    summary = document['result']['inventory']
    assert (summary['accepted_count'], summary['rejected_count'], summary['duplicate_count']) == (3, 1, 1)
    assert summary['conflict_count'] > 0 and not summary['truncated']
    code, shown, _ = kb('inventory', 'show', summary['import_id'])
    assert code == 3 and len(shown['result']['entries']) == 3
    assert shown['result']['inventory']['diagnostics']


@pytest.mark.parametrize('extra', [('--limit', '0'), ('--limit', '101'), ('--offset', '-1')])
def test_list_page_limits_are_typed_input_errors(kb, extra):
    code, document, _ = kb('inventory', 'list', *extra)
    assert code == 2 and 'PT-KBC-INPUT' in document['error'] and not kb.workspace.exists()


@pytest.mark.parametrize('extra', [('--name', 'x' * 129), ('--limit', '501'), ('--offset', '-1')])
def test_show_filters_are_bounded_before_reading_cache(kb, extra):
    code, document, _ = kb('inventory', 'show', 'a' * 64, *extra)
    assert code == 2 and 'PT-KBC-INPUT' in document['error'] and not kb.workspace.exists()


def test_local_parse_failure_keeps_prior_inventory(kb, csv_file, tmp_path):
    prior = import_csv(kb, csv_file)
    bad = tmp_path / 'bad.csv'
    bad.write_bytes(b'File name,File version\n"unfinished')
    code, document, error = kb('inventory', 'import', str(bad), '--kb', 'KB5099001')
    assert code == 2 and document['result']['issue']['code'].startswith('PT-KBC-') and 'Traceback' not in error
    code, document, _ = kb('inventory', 'list')
    assert code == 0 and [row['import_id'] for row in document['result']['inventories']] == [prior['import_id']]


def test_invalid_context_never_creates_workspace(kb, csv_file):
    code, document, error = kb('inventory', 'import', str(csv_file), '--kb', 'KB12')
    assert code == 2 and 'PT-KBC-INPUT' in document['error'] and not kb.workspace.exists()
    assert 'Traceback' not in error


def test_support_html_links_are_offline_separate_claims_and_keep_rejection_reasons(kb, tmp_path):
    path = tmp_path / 'support.html'
    path.write_bytes(HTML)
    code, document, error = kb('inventory', 'links', str(path), '--page-url', PAGE)
    assert code == 0 and not error and document['command'] == 'kb inventory links'
    result = document['result']
    assert result['source']['authenticity'] == 'unverified-local-file' and result['source']['uri'] is None
    links = result['extraction']['links']
    assert [link['url'] for link in links if link['accepted']] == [GO]
    assert any(link['reason'] == 'servicing-stack' for link in links if not link['accepted'])
    code, listing, _ = kb('inventory', 'list', '--kind', 'support-page')
    assert code == 0 and listing['result']['total'] == 1
    code, replayed, _ = kb('inventory', 'show', result['import_id'])
    assert code == 0 and replayed['result']['extraction'] == result['extraction']


def test_offline_import_to_explicit_selection_and_saved_pair_candidates(kb, tmp_path, csv_file):
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(
        b'Example OS 24H2 x64', b'Windows 11 Version 24H2 for x64-based Systems')
    advisory = tmp_path / 'advisory.json'
    advisory.write_bytes(raw)
    assert kb('index', 'import', str(advisory))[0] == 0
    code, search = kb.search()
    assert code == 0
    inv = search['result']['investigation_id']
    product = next(row['scope_id'] for row in search['result']['scopes'] if row['architecture'] == 'amd64')
    revision = search['result']['revision']
    imported = import_csv(kb, csv_file)
    code, shown, _ = kb('inventory', 'show', imported['import_id'])
    assert code == 0
    entry_id = shown['result']['entries'][0]['entry_id']
    arguments = ('inventory', 'select', imported['import_id'], entry_id, '--investigation', inv,
                 '--product', product, '--expected-revision', str(revision))
    code, rejected, _ = kb(*arguments)
    assert code == 2 and 'scope assertion' in rejected['error']
    code, selected, error = kb(*arguments, '--assert-scope')
    assert code == 0 and not error and selected['result']['revision'] > revision
    assert selected['result']['hint']['inventory_refs'][0]['entry_id'] == entry_id
    code, hints, _ = kb('components', inv)
    assert code == 0 and [item['basename'] for item in hints['result']['hints']] == ['examplenet.sys']
    assert hints['result']['hints'][0]['tier'] == 'E'
    index_file = tmp_path / 'winbindex.json'
    index_file.write_text(json.dumps(winbindex_record('examplenet.sys')), encoding='utf-8')
    assert kb('index', 'import', str(index_file), '--winbindex', 'examplenet.sys', '--data-date', '2099-02-12')[0] == 0
    code, pairs, error = kb('pairs', inv)
    assert code == 0 and not error and pairs['result']['pairs']
    assert {pair['file_name'] for pair in pairs['result']['pairs']} == {'examplenet.sys'}
    assert all(pair['older_sha256'] != pair['newer_sha256'] for pair in pairs['result']['pairs'])
    code, stale, _ = kb(*arguments, '--assert-scope')
    assert code == 3 and 'PT-KBC-STALE' in stale['error']
    assert not list(tmp_path.rglob('project.sqlite3'))


def test_plan_redirect_budget_is_an_input_error_and_never_creates_workspace(kb):
    flags = [item for index in range(5) for item in ('--redirect-url', CSV_URL + f'?step={index}')]
    code, document, error = kb('inventory', 'plan', CSV_URL, *flags)
    assert code == 2 and document['result']['issue']['code'] == 'PT-KBC-LIMIT'
    assert 'four redirects' in error and not kb.workspace.exists()


class Response:
    def __init__(self, status=200, body=CSV, headers=None):
        self.status, self.headers = status, headers or {}
        self.body, self.closed = io.BytesIO(body), False

    def read(self, size):
        return self.body.read(size)

    read1 = read

    def close(self):
        self.closed = True


def injected_transport(monkeypatch, responses):
    calls = []

    def opener(_method, url, _headers, _timeout):
        calls.append(url)
        return responses[url]

    def fetch(plan, **kwargs):
        return inventory_fetch.fetch_source(plan, **{**kwargs, 'opener': opener})

    monkeypatch.setattr(inventory_service, 'fetch_source', fetch)
    return calls


def saved_plan(kb, tmp_path, url=CSV_URL, *flags):
    code, envelope, error = kb('inventory', 'plan', url, *flags)
    assert code == 0 and not error and envelope['command'] == 'kb inventory plan'
    path = tmp_path / 'plan.json'
    path.write_text(json.dumps(envelope), encoding='utf-8')
    return path, envelope['result']['plan']


def consent_args(path, plan):
    return ('inventory', 'fetch', '--plan-file', str(path), '--consent-plan', plan['plan_sha'],
            *(item for host in plan['hosts'] for item in ('--consent-host', host)))


def test_saved_plan_envelope_fetch_runs_consent_and_stores_exact_receipt(kb, tmp_path, monkeypatch):
    path, plan = saved_plan(kb, tmp_path)
    response = Response()
    calls = injected_transport(monkeypatch, {CSV_URL: response})
    code, document, error = kb(*consent_args(path, plan), '--kb', 'KB5099001')
    assert code == 0 and not error and calls == [CSV_URL] and response.closed
    inventory = document['result']['inventory']
    assert inventory['source']['authenticity'] == 'tls-allowlisted-host'
    assert inventory['retrieval']['plan_sha'] == plan['plan_sha']
    assert inventory['retrieval']['redirect_chain'] == [CSV_URL]
    assert inventory['source']['sha256'] == hashlib.sha256(CSV).hexdigest()


@pytest.mark.parametrize('variation', ['offline', 'wrong-digest', 'extra-host', 'no-kb', 'unused-context'])
def test_fetch_refusals_happen_before_transport_or_workspace(kb, tmp_path, monkeypatch, variation):
    path, plan = saved_plan(kb, tmp_path)
    calls = injected_transport(monkeypatch, {CSV_URL: Response()})
    flags = list(consent_args(path, plan))
    if variation != 'no-kb' and variation != 'unused-context':
        flags += ['--kb', 'KB5099001']
    if variation == 'offline':
        flags.append('--offline')
    elif variation == 'wrong-digest':
        flags[flags.index('--consent-plan') + 1] = 'f' * 64
    elif variation == 'extra-host':
        flags += ['--consent-host', 'msdl.microsoft.com']
    elif variation == 'unused-context':
        flags += ['--architecture', 'amd64']
    code, document, error = kb(*flags)
    assert code == 2 and document['status'] == 'failed' and not calls and not kb.workspace.exists()
    assert error.startswith('error:') and 'Traceback' not in error


def test_support_fetch_requires_no_csv_context_and_does_not_follow_links(kb, tmp_path, monkeypatch):
    path, plan = saved_plan(kb, tmp_path, PAGE, '--kind', 'support-page')
    calls = injected_transport(monkeypatch, {PAGE: Response(body=HTML)})
    code, document, error = kb(*consent_args(path, plan))
    assert code == 0 and not error and calls == [PAGE]
    assert document['result']['source']['kind'] == 'kb-support-html'
    assert document['result']['extraction']['links'][0]['url'] == GO


def test_changed_redirect_returns_preview_and_preserves_supplied_stderr(tmp_path, monkeypatch, capsys):
    plan = inventory_fetch.build_plan(GO)
    path = tmp_path / 'plan.json'
    path.write_text(plan.to_json(), encoding='utf-8')
    calls = injected_transport(monkeypatch, {GO: Response(302, headers={'Location': CSV_URL})})
    stdout, stderr = io.StringIO(), io.StringIO()
    flags = [*consent_args(path, plan.as_dict()), '--kb', 'KB5099001', '--workspace', str(tmp_path / 'ws'), '--json']
    code = cli.main(list(flags), env=wiring.build_env(clock=FixedClock()), stdout=stdout, stderr=stderr)
    document = json.loads(stdout.getvalue())
    assert code == 2 and calls == [GO] and document['result']['proposed_plan']['urls'] == [GO, CSV_URL]
    assert document['result']['proposed_plan']['plan_sha'] != plan.plan_sha
    assert CSV_URL in document['result']['preview'] and 'PT-KBC-CONSENT' in stderr.getvalue()
    assert not capsys.readouterr().err and not (tmp_path / 'ws').exists()


@pytest.mark.parametrize('exception,exit_code,status', [
    (SourceError('PT-KBC-CANCEL', 'cancelled'), 5, 'cancelled'),
    (KbcStoreError('PT-KBC-CANCEL', 'cancelled'), 5, 'cancelled'),
    (KbcStoreError('PT-KBC-VERIFY', 'damaged cache'), 3, 'failed'),
    (SourceError('PT-KBC-UNSUPPORTED', 'unsupported source'), 2, 'failed'),
])
def test_typed_failures_keep_codes_and_use_supplied_stderr(monkeypatch, tmp_path, capsys, exception, exit_code, status):
    def fail(*_args, **_kwargs):
        raise exception

    monkeypatch.setattr(KbService, 'inventories', fail)
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli.main(['inventory', 'list', '--json', '--workspace', str(tmp_path / 'ws')],
                    env=wiring.build_env(clock=FixedClock()), stdout=stdout, stderr=stderr)
    document = json.loads(stdout.getvalue())
    assert code == exit_code and document['status'] == status and document['result']['issue']['code'] == exception.code
    assert exception.code in stderr.getvalue() and not capsys.readouterr().err


def test_plain_errors_strip_terminal_and_bidi_controls(monkeypatch, tmp_path, capsys):
    def fail(*_args, **_kwargs):
        return Outcome(2, 'failed', {'contract': 'kbcorrelation/1'}, '\x1b[31mtext\u202e',
                       error='PT-KBC-INPUT: bad\x1b[31m\u202e')

    monkeypatch.setattr(KbService, 'inventories', fail)
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli.main(['inventory', 'list', '--workspace', str(tmp_path / 'ws')],
                    env=wiring.build_env(clock=FixedClock()), stdout=stdout, stderr=stderr)
    assert code == 2 and '\x1b' not in stdout.getvalue() + stderr.getvalue()
    assert '\u202e' not in stdout.getvalue() + stderr.getvalue() and not capsys.readouterr().err
