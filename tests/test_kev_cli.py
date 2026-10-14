"""kev/1 CLI (Qt-free dispatcher): one JSON document, exit codes, exact consent host, no network except fetch."""
from __future__ import annotations

import datetime
import io
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace.kev import cli, limits

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
NOW = datetime.datetime(2099, 3, 2, 8, 30, tzinfo=datetime.UTC)
SITE_HOST, MIRROR_HOST = 'www.cisa.gov', 'raw.githubusercontent.com'


def build(version='v1', released='2099-03-01T12:00:00Z', n=3) -> bytes:
    data = json.loads((FIXTURES / 'kev-synthetic-2099.json').read_text(encoding='utf-8'))
    template = data['vulnerabilities'][0]
    data['catalogVersion'], data['dateReleased'] = version, released
    data['vulnerabilities'] = [{**template, 'cveID': f'CVE-2099-{10000 + i}'} for i in range(n)]
    data['count'] = n
    return json.dumps(data).encode('utf-8')


class Reply:
    def __init__(self, status=200, body=b'', headers=None):
        self.status, self.headers, self._body = status, dict(headers or {}), body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


def serving(*replies):
    queue, urls = list(replies), []

    def opener(url, headers, timeout):
        urls.append(url)
        return queue.pop(0)
    opener.urls = urls
    return opener


def run(tmp_path, *argv, opener=None, now=NOW, extra_dir=True):
    out, err = io.StringIO(), io.StringIO()
    args = [*argv, *(['--kev-dir', str(tmp_path / 'kev')] if extra_dir else [])]
    kwargs = {'opener': opener} if opener else {}
    code = cli.main(args, now=lambda: now, sleep=lambda *_a: None, stdout=out, stderr=err, **kwargs)
    return code, out.getvalue(), err.getvalue()


def doc(text: str) -> dict:
    return json.loads(text)  # raises unless stdout is exactly one JSON document


def seed(tmp_path, **kwargs) -> Path:
    path = tmp_path / 'seed.json'
    path.write_bytes(build(**kwargs))
    code, _out, err = run(tmp_path, 'import', str(path), '--json')
    assert code == 0, err
    return path


def test_plan_does_no_network(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError('network touched')

    monkeypatch.setattr(socket, 'getaddrinfo', boom)
    monkeypatch.setattr(socket.socket, 'connect', boom)
    code, out, _ = run(tmp_path, 'plan', '--source', 'cisa-site', '--json')
    result = doc(out)['result']
    assert code == 0 and result['record'] == 'plan'
    assert result['plan']['url'] == limits.SOURCE_URLS['cisa-site']
    assert result['plan']['headers'] == {'accept': 'application/json', 'user_agent': 'PatchTrace'}
    assert not (tmp_path / 'kev').exists()


@pytest.mark.parametrize('argv,code,status', [
    (['status'], 4, 'unavailable'),
    (['plan', '--source', 'cisa-github'], 0, 'ok'),
    (['lookup', 'CVE-2099-10000'], 4, 'unavailable'),
    (['diff'], 4, 'failed'),
    (['fetch', '--source', 'cisa-site'], 2, 'failed'),
    (['fetch'], 2, 'failed'),
    (['import', '{missing}'], 2, 'failed'),
    (['prune', '--keep', '1'], 2, 'failed'),
    (['lookup'], 2, 'failed'),
    (['nonsense'], 2, 'failed'),
], ids=['status-empty', 'plan', 'lookup-empty', 'diff-empty', 'fetch-no-consent', 'fetch-no-source', 'import-missing',
        'prune-no-yes', 'lookup-no-ids', 'unknown-verb'])
def test_cli_json_is_one_document_with_exit_codes(tmp_path, argv, code, status):
    argv = [str(tmp_path / 'absent.json') if a == '{missing}' else a for a in argv]
    got, out, _err = run(tmp_path, *argv, '--json')
    document = doc(out)
    assert got == code
    assert document['contract'] == 'enrichment-cli/1' and document['command'] == 'kev'
    assert document['status'] == status
    if status == 'failed':
        assert document['result'] is None and document['error']['code'].startswith('PT-KEV-')


@pytest.mark.parametrize('hosts', [[], [MIRROR_HOST], ['cisa.gov'], [f'{SITE_HOST}.evil.example'], [SITE_HOST, MIRROR_HOST]],
                         ids=['none', 'other', 'bare', 'suffix', 'both'])
def test_cli_fetch_requires_exact_consent_host(tmp_path, hosts):
    opener = serving(Reply(body=build()))
    argv = ['fetch', '--source', 'cisa-site', *[a for h in hosts for a in ('--consent-hosts', h)], '--json']
    code, out, _ = run(tmp_path, *argv, opener=opener)
    assert code == 2 and doc(out)['error']['code'] == 'PT-KEV-CONSENT'
    assert opener.urls == []


@pytest.mark.parametrize('source,host', [('cisa-site', SITE_HOST), ('cisa-github', MIRROR_HOST)], ids=['site', 'mirror'])
def test_fetch_prints_request_first_and_installs(tmp_path, source, host):
    opener = serving(Reply(body=build()))
    code, out, err = run(tmp_path, 'fetch', '--source', source, '--consent-hosts', host, '--json', opener=opener)
    document = doc(out)
    assert code == 0 and document['status'] == 'ok'
    assert err.splitlines()[0] == f'GET {limits.SOURCE_URLS[source]}'
    assert opener.urls == [limits.SOURCE_URLS[source]]
    assert document['result']['installed'] is True
    assert document['result']['catalog']['catalog_version'] == 'v1'
    again, out2, _ = run(tmp_path, 'status', '--json')
    assert again == 0 and doc(out2)['result']['catalog']['snapshot_id'] == document['result']['catalog']['snapshot_id']


def test_fetch_older_mirror_is_partial(tmp_path):
    seed(tmp_path, version='v2', released='2099-03-05T12:00:00Z')
    opener = serving(Reply(body=build('v1', '2099-03-01T12:00:00Z', n=1)))
    code, out, _ = run(tmp_path, 'fetch', '--source', 'cisa-github', '--consent-hosts', MIRROR_HOST, '--json',
                       opener=opener, now=datetime.datetime(2099, 3, 6, tzinfo=datetime.UTC))
    document = doc(out)
    assert code == 0 and document['status'] == 'partial' and document['result']['installed'] is False
    assert 'older than the one in use' in document['warnings'][0]


def test_fetch_failures_exit_3_and_keep_catalog(tmp_path):
    seed(tmp_path)
    for replies, expected in (([Reply(503)] * 3, 'PT-KEV-NETWORK'), ([Reply(404)], 'PT-KEV-PROVIDER'),
                              ([Reply(body=b'<html>')], 'PT-KEV-FORMAT')):
        code, out, _ = run(tmp_path, 'fetch', '--source', 'cisa-site', '--consent-hosts', SITE_HOST, '--json',
                           opener=serving(*replies))
        assert code == 3 and doc(out)['error']['code'] == expected
    assert run(tmp_path, 'status', '--json')[0] == 0


def test_fetch_shrink_needs_accept_flag(tmp_path):
    seed(tmp_path, n=20)
    argv = ['fetch', '--source', 'cisa-site', '--consent-hosts', SITE_HOST, '--json']
    small = build('v2', '2099-03-05T12:00:00Z', n=5)
    code, out, _ = run(tmp_path, *argv, opener=serving(Reply(body=small)))
    assert code == 3 and doc(out)['error']['code'] == 'PT-KEV-SHRINK'
    code, out, _ = run(tmp_path, *argv, '--accept-shrink', opener=serving(Reply(body=small)))
    assert code == 0 and doc(out)['result']['catalog']['entry_count'] == 5


def test_import_csv_is_unsupported(tmp_path):
    csv = tmp_path / 'k.csv'
    csv.write_text('cveID,vendorProject\nCVE-2099-1,x\n', encoding='utf-8')
    code, out, _ = run(tmp_path, 'import', str(csv), '--json')
    assert code == 2 and doc(out)['error']['code'] == 'PT-KEV-UNSUPPORTED'


def test_status_and_lookup_freshness(tmp_path):
    seed(tmp_path)
    later = NOW + datetime.timedelta(days=20)
    code, out, _ = run(tmp_path, 'status', '--json', now=later)
    document = doc(out)
    assert code == 0 and document['status'] == 'partial' and document['result']['freshness'] == 'stale'
    code, out, _ = run(tmp_path, 'status', '--json', '--max-age-days', '0')
    assert code == 0 and 'older than --max-age-days' in doc(out)['warnings'][0]
    code, out, _ = run(tmp_path, 'lookup', 'CVE-2099-10000', 'CVE-2099-19999', 'cve-２０９９-1', '--json', now=later)
    document = doc(out)
    rows = {r['cve_id']: r for r in document['result']['lookups']}
    assert code == 0 and document['status'] == 'partial'
    assert rows['CVE-2099-10000']['kev'] == 'Listed - ransomware known'
    assert rows['CVE-2099-19999']['status'] == 'not-listed' and rows['CVE-2099-19999']['kev'] == 'Not listed'
    assert [r['status'] for r in rows.values()].count('invalid-id') == 1
    assert any('days old' in w for w in document['warnings']) and any('not valid CVE IDs' in w for w in document['warnings'])


def test_lookup_fresh_catalog_is_ok(tmp_path):
    seed(tmp_path)
    code, out, _ = run(tmp_path, 'lookup', 'CVE-2099-10001', '--json')
    assert code == 0 and doc(out)['status'] == 'ok'


def test_lookup_reads_cve_snapshot_files_and_catalog_file(tmp_path):
    snap = tmp_path / 'snap.json'
    snap.write_text(json.dumps({'cve_id': 'CVE-2099-10002'}), encoding='utf-8')
    catalog = tmp_path / 'cat.json'
    catalog.write_bytes(build())
    code, out, _ = run(tmp_path, 'lookup', '--from-cve-snapshot', str(snap), '--catalog', str(catalog), '--json')
    document = doc(out)
    assert code == 0 and document['result']['lookups'][0]['status'] == 'listed'
    assert not (tmp_path / 'kev').exists()


def test_lookup_markdown_escapes_hostile_ids(tmp_path):
    seed(tmp_path)
    code, out, err = run(tmp_path, 'lookup', 'CVE-2099-10000', '<img src=x>|[a](b)', '--md')
    assert code == 0 and 'not valid CVE IDs' in err
    assert out.startswith('### Exploitation context (CISA KEV)')
    assert not re.search(r'(?<!\\)<', out) and '\\<img' in out and '\\|' in out and '\\[a\\]' in out
    assert 'Not listed does not mean not exploited.' in out
    code, out, _ = run(tmp_path, 'lookup', 'CVE-2099-10000', '--md', '--json')
    assert doc(out)['result']['markdown'].startswith('### Exploitation context (CISA KEV)')


def test_diff_and_prune(tmp_path):
    seed(tmp_path, n=2)
    code, _out, _ = run(tmp_path, 'diff', '--json')
    assert code == 4
    seed(tmp_path, version='v2', released='2099-03-05T12:00:00Z', n=3)
    code, out, _ = run(tmp_path, 'diff', '--json')
    document = doc(out)
    assert code == 0 and document['result']['delta']['added'] == ['CVE-2099-10002']
    assert document['result']['lines'][0].startswith('1 new, 0 changed, 0 removed since catalog v1')
    code, out, _ = run(tmp_path, 'prune', '--keep', '1', '--yes', '--json')
    assert code == 0 and len(doc(out)['result']['removed']) == 1 and doc(out)['result']['kept'] == 1


def test_plain_text_output_has_no_json(tmp_path):
    seed(tmp_path)
    code, out, _ = run(tmp_path, 'status')
    assert code == 0 and out.startswith('KEV catalog v1 - released 2099-03-01 12:00 UTC - 3 entries')


def test_cli_imports_without_qt():
    src = Path(__file__).resolve().parents[1] / 'src'
    code = 'import sys, patchtrace.kev.cli; sys.exit(1 if "PySide6" in sys.modules else 0)'
    run_ = subprocess.run([sys.executable, '-c', code], env={**os.environ, 'PYTHONPATH': str(src)}, timeout=60)
    assert run_.returncode == 0


def test_default_dir_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    out = io.StringIO()
    assert cli.main(['status', '--json'], stdout=out, stderr=io.StringIO()) == 4
    assert not (tmp_path / 'local').exists()
