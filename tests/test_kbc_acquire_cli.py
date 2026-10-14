"""K7 glue: `kb acquire` and `kb index import --winbindex` (KB-integration-plan 8.1) through the production wiring with
a fake transport. Synthetic records and PE files; sockets denied; nothing is executed."""
from __future__ import annotations

import gzip
import hashlib
import json
import tempfile

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock, Kb
from kbc_k5_support import record

from patchtrace.acquisition import transport as tr
from patchtrace.acquisition import winbindex as wb
from patchtrace.acquisition import workflow as wf
from patchtrace.acquisition.contracts import symbol_server_url
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.sample import synthetic_pe

pytestmark = pytest.mark.usefixtures('no_sockets')
NET = 'examplenet.sys'
OLDER, NEWER = synthetic_pe(0), synthetic_pe(1)
SHA_O, SHA_N = hashlib.sha256(OLDER).hexdigest(), hashlib.sha256(NEWER).hexdigest()
VSIZE = 131072
URL_O, URL_N = (symbol_server_url(NET, 0x100 + i, VSIZE) for i in range(2))
HOSTS = 'msdl.microsoft.com'


class Resp:
    def __init__(self, status, body=b'', headers=None):
        self.status, self.headers, self._body = status, headers or {}, body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


class Server:
    """Symbol server: 302 to a blob for known URLs, 404 otherwise; the blob serves the bytes."""

    def __init__(self, bodies):
        self.calls, self.bodies = [], bodies

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        if url.startswith('https://s.blob.core.windows.net/'):
            return Resp(200, self.bodies['https://msdl.microsoft.com/' + url.split('/', 3)[3]])
        if url not in self.bodies:
            return Resp(404)
        return Resp(302, headers={'Location': 'https://s.blob.core.windows.net/' + url.split('/', 3)[3]})


def acquirer(server):
    return wf.Acquirer(lambda cancel: tr.Transport(opener=server, cancel=cancel, sleep=lambda s, c: None))


def net_record() -> dict:
    """examplenet.sys with its two builds replaced by the synthetic PE files, so downloads can verify."""
    doc = record(NET)
    for old, sha, i in (('1' * 64, SHA_O, 0), ('2' * 64, SHA_N, 1)):
        entry = doc.pop(old)
        entry['fileInfo'].update(sha256=sha, size=len(OLDER if i == 0 else NEWER), timestamp=0x100 + i,
                                 virtualSize=VSIZE)
        doc[sha] = entry
    return doc


def make_kb(tmp_path, capsys, bodies=None) -> tuple[Kb, Server]:
    server = Server({URL_O: OLDER, URL_N: NEWER} if bodies is None else bodies)
    env = wiring.build_env(clock=FixedClock(), acquirer=acquirer(server))
    return Kb(tmp_path, capsys, env=env), server


def cvrf() -> bytes:
    return h.read_fixture_bytes('cvrf-2099-Feb.json').replace(
        b'Example OS 24H2 x64', b'Windows 11 Version 24H2 for x64-based Systems')


@pytest.fixture
def staging_root(tmp_path, monkeypatch):
    base = tmp_path / 'tmp'
    base.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(base))
    return base


@pytest.fixture
def ready(tmp_path, capsys):
    kb, server = make_kb(tmp_path, capsys)
    raw = cvrf()
    with WorkspaceStore(kb.workspace) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)
    source = tmp_path / 'net.json'
    source.write_text(json.dumps(net_record()), encoding='utf-8')
    code, doc, _ = kb('index', 'import', '--winbindex', NET, '--data-date', '2099-02-12', str(source))
    assert code == 0 and doc['result']['winbindex']['rows'] >= 2
    code, found = kb.search('CVE-2099-20001')
    assert code == 0
    scopes = found['result']['scopes']
    client = next(s for s in scopes if s['family'] == 'windows-client' and s['architecture'] == 'amd64')
    flags = ('--product', client['scope_id'], '--file', NET)
    return kb, server, found['result']['investigation_id'], flags, tmp_path / 'proj'


def plan_of(kb, inv, flags, project):
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags)
    assert code == 2
    return doc['result']['plan']


# ---------------------------------------------------------------------------------------------------- kb acquire

def test_without_consent_the_exact_plan_is_printed_and_nothing_is_requested(ready):
    kb, server, inv, flags, project = ready
    code, doc, err = kb('acquire', inv, '--project', str(project), *flags)
    plan = doc['result']['plan']
    assert code == 2 and doc['status'] == 'failed' and 'PT-KBC-CONSENT' in doc['error'] and 'consent' in err
    assert plan['hosts'] == [HOSTS] and plan['network_requests'] == 2 and len(plan['plan_sha']) == 64
    assert plan['requests'] == [{'method': 'GET', 'target': URL_O}, {'method': 'GET', 'target': URL_N}]
    text = kb('acquire', inv, '--project', str(project), *flags, as_json=False)[1]
    assert plan['plan_sha'] in text and f'--consent-hosts {HOSTS}' in text and URL_O in text
    assert server.calls == [] and not project.exists()


@pytest.mark.parametrize('hosts, sha, offline', [
    ('winbindex.m417z.com', None, False), (HOSTS + ',evil.example', None, False), (HOSTS, 'f' * 64, False),
    (HOSTS, None, True)], ids=['wrong-host', 'extra-host', 'other-plan', 'offline'])
def test_consent_that_is_not_for_exactly_this_plan_requests_nothing(ready, hosts, sha, offline):
    kb, server, inv, flags, project = ready
    good = plan_of(kb, inv, flags, project)['plan_sha']
    extra = ['--offline'] if offline else []
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', hosts,
                      '--consent-plan', sha or good, *extra)
    assert code == 2 and doc['result']['plan']['plan_sha'] == good
    assert server.calls == [] and not project.exists()


def test_consented_acquire_downloads_verifies_and_attaches_a_project(ready, staging_root):
    kb, server, inv, flags, project = ready
    sha = plan_of(kb, inv, flags, project)['plan_sha']
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', HOSTS,
                      '--consent-plan', sha, '--name', 'afd test')
    assert code in (0, 3), doc
    symbol = [u for _, u in server.calls if u.startswith('https://msdl.microsoft.com/')]
    assert {m for m, _ in server.calls} == {'GET'} and symbol == [URL_O, URL_N]  # each then follows its blob redirect
    assert len(server.calls) == 4
    acquisition = doc['result']['acquisition']
    assert acquisition['plan_sha'] == sha
    assert [(d['side'], d['sha256'], d['redirect_host']) for d in acquisition['downloads']] == [
        ('older', SHA_O, 's.blob.core.windows.net'), ('newer', SHA_N, 's.blob.core.windows.net')]
    assert (project / 'project.sqlite3').is_file() and not any(staging_root.iterdir())
    # attach path: the advisory context is in the project, or "attach --repair" finishes it, idempotently
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and doc['status'] == 'complete'
    code, doc, _ = kb('explain', str(project))
    assert code == 0 and doc['result']['cves']


def test_a_download_that_is_not_the_indexed_build_is_refused_and_leaves_nothing(ready, staging_root):
    kb, server, inv, flags, project = ready
    server.bodies[URL_N] = synthetic_pe(7)
    sha = plan_of(kb, inv, flags, project)['plan_sha']
    code, doc, err = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', HOSTS,
                        '--consent-plan', sha)
    assert code == 3 and 'PT-KBC-VERIFY' in doc['error'] and 'PT-KBC-VERIFY' in err
    assert not project.exists() and not any(staging_root.iterdir())


def test_a_non_empty_project_directory_is_refused_before_any_request(ready):
    kb, server, inv, flags, project = ready
    sha = plan_of(kb, inv, flags, project)['plan_sha']
    project.mkdir()
    (project / 'keep.txt').write_text('x', encoding='utf-8')
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', HOSTS,
                      '--consent-plan', sha)
    assert code == 2 and 'PT-KBC-INPUT' in doc['error'] and server.calls == []


def test_unknown_pair_is_an_argument_error_and_no_candidate_is_unavailable(ready):
    kb, server, inv, flags, project = ready
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--pair', 'ffffffffffff')
    assert code == 2 and 'PT-KBC-INPUT' in doc['error']
    server_scope = next(s for s in kb.search('CVE-2099-20001')[1]['result']['scopes'] if s['family'] == 'windows-server')
    code, doc, _ = kb('acquire', inv, '--project', str(project), '--product', server_scope['scope_id'], '--file', NET)
    assert (code, doc['status']) == (4, 'unavailable') and server.calls == []


def test_the_pair_flag_selects_a_candidate_by_prefix(ready):
    kb, _, inv, flags, project = ready
    pair_id = kb('pairs', inv, *flags)[1]['result']['pairs'][0]['pair_id']
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--pair', pair_id[:12])
    assert code == 2 and doc['result']['pair']['pair_id'] == pair_id and doc['result']['plan']


# ---------------------------------------------------------------------------------------------------- kb index import

def folder(kb):
    return kb.workspace / wiring.INDEX_DIR


def write(tmp_path, name, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_winbindex_record_is_stored_where_the_file_index_reads_it(tmp_path, capsys):
    kb = Kb(tmp_path, capsys)
    body = json.dumps(record(NET)).encode('utf-8')
    code, doc, _ = kb('index', 'import', '--winbindex', 'ExampleNet.SYS', '--data-date', '2099-02-12',
                      write(tmp_path, 'in.json', body))
    summary = doc['result']['winbindex']
    assert code == 0 and doc['result']['index_changed'] is True
    assert summary['stored_as'] == f'winbindex/{NET}@2099-02-12.json' and summary['replaced'] is False
    assert (folder(kb) / f'{NET}@2099-02-12.json').read_bytes() == body
    assert summary['sha256'] == hashlib.sha256(body).hexdigest() and summary['rows'] >= 2
    index = wiring.WorkspaceFileIndex(kb.workspace)
    assert index.available() and {r['sha256'] for r in index.rows_for(NET, '')} >= {'1' * 64, '2' * 64}
    assert [p.name for p in folder(kb).iterdir()] == [f'{NET}@2099-02-12.json']


def test_gzip_record_replaces_the_plain_one_of_the_same_date(tmp_path, capsys):
    kb = Kb(tmp_path, capsys)
    body = json.dumps(record(NET)).encode('utf-8')
    kb('index', 'import', '--winbindex', NET, '--data-date', '2099-02-12', write(tmp_path, 'in.json', body))
    code, doc, _ = kb('index', 'import', '--winbindex', NET, '--data-date', '2099-02-12',
                      write(tmp_path, 'in.json.gz', gzip.compress(body)))
    assert code == 0 and doc['result']['winbindex']['replaced'] is True
    assert [p.name for p in folder(kb).iterdir()] == [f'{NET}@2099-02-12.json.gz']


def test_the_default_data_date_is_the_clock_date(tmp_path, capsys):
    kb = Kb(tmp_path, capsys)
    code, doc, _ = kb('index', 'import', '--winbindex', NET, write(tmp_path, 'in.json', json.dumps(record(NET)).encode()))
    assert code == 0 and doc['result']['winbindex']['data_date'] == NOW[:10]


@pytest.mark.parametrize('data, name, date, extra', [
    (b'not json', NET, '2099-02-12', None), (b'[1, 2]', NET, '2099-02-12', None), (b'{}', NET, '2099-02-12', None),
    (b'{"' + b'a' * 64 + b'": 1}', NET, '2099-02-12', None), (json.dumps(record(NET)).encode(), 'a b.sys', None, None),
    (json.dumps(record(NET)).encode(), NET, '12-02-2099', None),
    (json.dumps(record(NET)).encode(), '../x.sys', '2099-02-12', None),
    (json.dumps(record(NET)).encode(), 'x.txt', '2099-02-12', None),
    (b'\x1f\x8b not gzip', NET, '2099-02-12', None)],
    ids=['not-json', 'not-object', 'no-rows', 'no-fileinfo', 'bad-name', 'bad-date', 'traversal', 'bad-extension',
         'bad-gzip'])
def test_a_record_that_does_not_validate_is_rejected_and_nothing_is_written(tmp_path, capsys, data, name, date, extra):
    kb = Kb(tmp_path, capsys)
    args = ['--data-date', date] if date else []
    code, doc, err = kb('index', 'import', '--winbindex', name, *args, write(tmp_path, 'in.json', data))
    assert code == 2 and doc['status'] == 'failed' and doc['result']['index_changed'] is False
    assert 'PT-KBC' in err and not folder(kb).exists()


def test_a_record_over_the_size_bound_is_rejected_unread(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(wb, 'MAX_COMPRESSED', 64)
    kb = Kb(tmp_path, capsys)
    code, doc, _ = kb('index', 'import', '--winbindex', NET, '--data-date', '2099-02-12',
                      write(tmp_path, 'in.json', json.dumps(record(NET)).encode()))
    assert code == 2 and 'PT-KBC-LIMIT' in doc['error'] and not folder(kb).exists()


def test_a_gzip_bomb_is_bounded_by_the_decompressed_cap(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', 1000)
    kb = Kb(tmp_path, capsys)
    code, doc, _ = kb('index', 'import', '--winbindex', NET, '--data-date', '2099-02-12',
                      write(tmp_path, 'in.json.gz', gzip.compress(b'{"' + b' ' * 5000 + b'": 1}')))
    assert code == 2 and 'PT-KBC-LIMIT' in doc['error'] and not folder(kb).exists()


def test_winbindex_import_argument_rules(tmp_path, capsys):
    kb = Kb(tmp_path, capsys)
    one, two = (write(tmp_path, n, json.dumps(record(NET)).encode()) for n in ('a.json', 'b.json'))
    assert kb('index', 'import', '--winbindex', NET, one, two)[0] == 2
    assert kb('index', 'import', '--data-date', '2099-02-12', one)[0] == 2
    assert kb('index', 'import', '--winbindex', NET, str(tmp_path / 'missing.json'))[0] == 2
    assert not folder(kb).exists()
