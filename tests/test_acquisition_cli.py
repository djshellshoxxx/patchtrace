"""SPEC-08 §5 CLI: `acquire search` / `acquire fetch` with an injected fake transport."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.acquisition import transport as tr
from patchtrace.sample import synthetic_pe

FIXTURE = Path(__file__).parent / 'fixtures' / 'winbindex' / 'afd.sys.json'
META = 'https://winbindex.m417z.com/data/by_filename_compressed/demo.sys.json.gz'
OLDER, NEWER = synthetic_pe(0), synthetic_pe(1)
SHA_O, SHA_N = hashlib.sha256(OLDER).hexdigest(), hashlib.sha256(NEWER).hexdigest()
SRC = str(Path(cli.__file__).resolve().parents[1])
CONSENT = ['--consent-hosts', 'winbindex.m417z.com,msdl.microsoft.com']


class Resp:
    def __init__(self, status, body=b'', headers=None):
        self.status, self.headers, self._body = status, headers or {}, body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


def demo_record(delta_only_newer=False):
    doc = {}
    for i, data in enumerate((OLDER, NEWER)):
        sha = hashlib.sha256(data).hexdigest()
        info = {'sha256': sha, 'size': len(data), 'machineType': 34404, 'timestamp': 0x100 + i}
        if delta_only_newer and i == 1:
            info |= {'lastSectionVirtualAddress': 0x3000, 'lastSectionPointerToRawData': len(data) - 0x200}
        else:
            info['virtualSize'] = 0x4000
        doc[sha] = {'fileInfo': info}
    return gzip.compress(json.dumps(doc).encode(), mtime=0)


class Server:
    """Fake Winbindex + msdl + blob. Records every request."""

    def __init__(self, record, msdl_status=None, valid_size=None):
        self.record, self.msdl_status, self.valid_size, self.calls = record, msdl_status, valid_size, []

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        if url.startswith('https://winbindex.m417z.com/'):
            return Resp(200, self.record) if self.record is not None else Resp(404)
        if url.startswith('https://msdl.microsoft.com/'):
            if method == 'HEAD':
                return Resp(302 if url.split('/')[-2].endswith(self.valid_size) else 404)
            if self.msdl_status:
                return Resp(self.msdl_status)
            return Resp(302, headers={'Location': 'https://s.blob.core.windows.net/b?sig=X&u=' + url})
        body = OLDER if '00000100' in url else NEWER
        return Resp(200, body)


@pytest.fixture
def server(monkeypatch):
    holder = {}

    def install(srv):
        holder['s'] = srv
        monkeypatch.setattr(cli, '_acquire_transport',
                            lambda factory, cancel: tr.Transport(opener=srv, cancel=cancel, sleep=lambda s, c: None))
        return srv
    return install


def run(args, capsys):
    code = cli.main(args)
    out, err = capsys.readouterr()
    return code, out, err


def test_search_lists_candidates_from_fixture(server, capsys):
    srv = server(Server(gzip.compress(FIXTURE.read_bytes())))
    code, out, err = run(['acquire', 'search', 'afd.sys', '--json', '--consent-hosts', 'winbindex.m417z.com'], capsys)
    assert code == 0, err
    doc = json.loads(out)
    assert doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'acquire search'
    assert len(doc['result']['candidates']) == 4 and doc['result']['downloadable'] == 4
    assert srv.calls == [('GET', 'https://winbindex.m417z.com/data/by_filename_compressed/afd.sys.json.gz')]
    assert 'request: GET https://winbindex' in err


def test_search_requires_exact_consent_and_valid_name(server, capsys):
    srv = server(Server(demo_record()))
    for consent in ([], ['--consent-hosts', 'winbindex.m417z.com,msdl.microsoft.com']):
        code, out, _ = run(['acquire', 'search', 'demo.sys', '--json', *consent], capsys)
        assert code == 2 and json.loads(out)['command'] == 'acquire search'
    code, _, _ = run(['acquire', 'search', 'Demo.SYS', '--consent-hosts', 'winbindex.m417z.com'], capsys)
    assert code == 2 and srv.calls == []


def test_search_no_record_or_nothing_downloadable_exits_4(server, capsys):
    server(Server(None))
    assert run(['acquire', 'search', 'demo.sys', '--consent-hosts', 'winbindex.m417z.com'], capsys)[0] == 4
    sha = '1' * 64
    server(Server(gzip.compress(json.dumps({sha: {'fileInfo': {'sha256': sha, 'size': 5, 'machineType': 34404,
                                                                'timestamp': 1}}}).encode())))
    code, out, _ = run(['acquire', 'search', 'demo.sys', '--json', '--consent-hosts', 'winbindex.m417z.com'], capsys)
    assert code == 4 and json.loads(out)['result']['candidates'][0]['download'] == 'unavailable'


def test_fetch_creates_project_with_provenance(server, capsys, tmp_path):
    srv = server(Server(demo_record()))
    code, out, err = run(['acquire', 'fetch', 'demo.sys', '--older', SHA_O, '--newer', SHA_N,
                          '--project', str(tmp_path / 'p'), '--json', *CONSENT], capsys)
    assert code == 0, err
    doc = json.loads(out)
    assert doc['command'] == 'acquire fetch'
    assert [a['sha256'] for a in doc['result']['artifacts']] == [SHA_O, SHA_N]
    assert (tmp_path / 'p' / 'project.sqlite3').exists()
    assert 'sig=' not in out and 'Authenticode' in doc['result']['authenticity']
    hosts = {c[1].split('/')[2] for c in srv.calls}
    assert hosts == {'winbindex.m417z.com', 'msdl.microsoft.com', 's.blob.core.windows.net'}
    from patchtrace.service import ProjectService
    with ProjectService.open(tmp_path / 'p') as service:
        assert len([a for a in service.project.annotations if a.text.startswith('acquisition/1')]) == 2


def test_fetch_resolves_delta_only_candidate_by_head(server, capsys, tmp_path):
    # NEWER size - raw = 0x200 -> end 0x3200 -> top 0x4000; probes 0x4000 then stops at 0x4000.
    srv = server(Server(demo_record(delta_only_newer=True), valid_size='4000'))
    code, _, err = run(['acquire', 'fetch', 'demo.sys', '--older', SHA_O, '--newer', SHA_N,
                        '--project', str(tmp_path / 'p'), *CONSENT], capsys)
    assert code == 0, err
    assert any(m == 'HEAD' for m, _ in srv.calls)


def test_fetch_404_is_no_results_and_leaves_no_project(server, capsys, tmp_path):
    server(Server(demo_record(), msdl_status=404))
    code, out, err = run(['acquire', 'fetch', 'demo.sys', '--older', SHA_O, '--newer', SHA_N,
                          '--project', str(tmp_path / 'p'), '--json', *CONSENT], capsys)
    assert code == 4 and 'not on the symbol server' in err
    assert not (tmp_path / 'p' / 'project.sqlite3').exists()


def test_fetch_argument_errors(server, capsys, tmp_path):
    srv = server(Server(demo_record()))
    base = ['acquire', 'fetch', 'demo.sys', '--project', str(tmp_path / 'p')]
    assert run([*base, '--older', SHA_O, '--newer', SHA_N, '--consent-hosts', 'winbindex.m417z.com'], capsys)[0] == 2
    assert run([*base, '--older', SHA_O, '--newer', SHA_O, *CONSENT], capsys)[0] == 2
    assert srv.calls == []
    assert run([*base, '--older', SHA_O, '--newer', 'f' * 64, *CONSENT], capsys)[0] == 2


def test_acquire_never_imports_qt(tmp_path):
    code = ('import sys\nsys.argv=["patchtrace","acquire","search","Bad.SYS","--json"]\n'
            'from patchtrace.__main__ import main\nrc=main()\n'
            'bad=[m for m in sys.modules if m.startswith(("PySide6","patchtrace.ui"))]\n'
            'raise SystemExit(90 if bad else rc)\n')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': SRC})
    assert result.returncode == 2, result.stderr
    assert json.loads(result.stdout)['command'] == 'acquire search'


def test_pure_modules_import_no_network_or_qt():
    code = ('import sys\nimport patchtrace.acquisition.contracts, patchtrace.acquisition.winbindex, '
            'patchtrace.acquisition.delta\n'
            'bad=[m for m in ("PySide6","subprocess","ssl","http.client","urllib.request") if m in sys.modules]\n'
            'print(bad); raise SystemExit(1 if bad else 0)\n')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': SRC})
    assert result.returncode == 0, result.stdout + result.stderr
