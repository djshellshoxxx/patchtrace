"""Offline tests for tools/research_qualification/winpairs.py (fixtures, injected fetcher; no network)."""
from __future__ import annotations

import gzip
import hashlib
import json

import pytest

from tools.research_qualification import winpairs as wp

BIN_A, BIN_B = b'MZ-old-binary', b'MZ-new-binary'


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entry(body: bytes, ts: int, vs: int, ver: str, kb: str = 'KB1000001', date: str = '2022-08-09',
          machine: int = 0x8664, **fi):
    info = {'size': len(body), 'sha256': sha(body), 'machineType': machine, 'timestamp': ts, 'virtualSize': vs,
            'version': ver, **fi}
    return {'fileInfo': info, 'windowsVersions': {'21H2': {kb: {'updateInfo': {'releaseDate': date}}}}}


def index(*entries):
    return {e['fileInfo']['sha256']: e for e in entries}


A = entry(BIN_A, 0x62F2A1B0, 0x4F000, '10.0.22000.100 (WinBuild)', 'KB1000001', '2022-08-09')
B = entry(BIN_B, 0x6320C3D4, 0x50000, '10.0.22000.200 (WinBuild)', 'KB1000002', '2022-09-13')
URL_A = 'https://msdl.microsoft.com/download/symbols/tcpip.sys/62F2A1B04f000/tcpip.sys'
URL_B = 'https://msdl.microsoft.com/download/symbols/tcpip.sys/6320C3D450000/tcpip.sys'
IDX_URL = 'https://winbindex.m417z.com/data/by_filename_compressed/tcpip.sys.json.gz'


class Fake:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, max_bytes, timeout):
        self.calls.append(url)
        r = self.routes.get(url)
        if r is None:
            return wp.Response(404)
        return r if isinstance(r, wp.Response) else wp.Response(200, r)


def routes(idx, extra=None):
    r = {IDX_URL: gzip.compress(json.dumps(idx).encode()), URL_A: BIN_A, URL_B: BIN_B}
    r.update(extra or {})
    return r


def case(cid='c1', older='tcpip.sys 10.0.22000.100', newer='tcpip.sys 10.0.22000.200'):
    return {'id': cid, 'older': {'ref': older}, 'newer': {'ref': newer}}


# ---- pure functions
def test_symbol_url_format_pads_timestamp_upper_size_lower_unpadded():
    assert wp.symbol_url('tcpip.sys', 0x1A2B, 0xABC) == \
        'https://msdl.microsoft.com/download/symbols/tcpip.sys/00001A2Babc/tcpip.sys'
    assert wp.symbol_url('afd.sys', 0x3BD9AC29, 0xB4000).endswith('/afd.sys/3BD9AC29b4000/afd.sys')


@pytest.mark.parametrize('bad', ['../x', 'a/b', '', 'a b', '.hidden', 'x\0y'])
def test_unsafe_names_rejected(bad):
    with pytest.raises(wp.WinpairsError):
        wp.index_url(bad)


def test_parse_ref_mines_version_kb_month():
    q = wp.parse_ref({'ref': 'afd.sys 10.0.26100.6899, KB5066835'})
    assert (q['file'], q['version'], q['kb']) == ('afd.sys', '10.0.26100.6899', 'KB5066835')
    assert wp.parse_ref({'ref': 'tcpip.sys, 2022-Sep Patch Tuesday'})['month'] == '2022-09'
    assert wp.parse_ref({'file': 'x.dll', 'ref': 'ignored', 'version': '1.2.3.4'})['file'] == 'x.dll'


def test_select_prefers_highest_version_when_pinned_multi_match():
    old = entry(b'1', 1, 0x1000, '10.0.22000.100 (a)')
    new = entry(b'2', 2, 0x1000, '10.0.22000.100 (b)')
    new['fileInfo']['timestamp'] = 5
    fi, _ = wp.select_entry(index(old, new), wp.parse_ref({'ref': 'f.sys 10.0.22000.100'}))
    assert fi['timestamp'] == 5


def test_select_refuses_unpinned_ambiguity():
    fi, why = wp.select_entry(index(A, B), wp.parse_ref({'ref': 'tcpip.sys'}))
    assert fi is None and 'ambiguous' in why


def test_select_filters_machine_and_requires_timestamp_and_size():
    arm = entry(b'3', 9, 0x1000, '10.0.22000.100 (x)', machine=0xAA64)
    nots = entry(b'4', 9, 0x1000, '10.0.22000.100 (y)')
    del nots['fileInfo']['timestamp']
    q = wp.parse_ref({'ref': 'tcpip.sys 10.0.22000.100'})
    assert wp.select_entry(index(arm, nots), q)[0] is None
    assert wp.select_entry(index(arm), {**q, 'machine': 'arm64'})[0] is not None


def test_select_by_kb_and_month_and_sha():
    q = wp.parse_ref({'ref': 'tcpip.sys, KB1000002'})
    assert wp.select_entry(index(A, B), q)[0]['sha256'] == sha(BIN_B)
    assert wp.select_entry(index(A, B), wp.parse_ref({'ref': 'tcpip.sys, 2022-Aug'}))[0]['sha256'] == sha(BIN_A)
    assert wp.select_entry(index(A, B), wp.parse_ref({'file': 'tcpip.sys', 'sha256': sha(BIN_B).upper()}))[0]


# ---- allowlist
@pytest.mark.parametrize('url', ['http://msdl.microsoft.com/x', 'https://evil.example/x', 'ftp://msdl.microsoft.com/x',
                                 'https://msdl.microsoft.com.evil.example/x', 'https://user@msdl.microsoft.com/x',
                                 'https://msdl.microsoft.com:8443/x', 'https://x.blob.core.windows.net/a'])
def test_check_url_rejects(url):
    with pytest.raises(wp.WinpairsError):
        wp.check_url(url)


def test_check_url_accepts_allowlisted_and_redirect_blob_only_on_redirect():
    wp.check_url(IDX_URL)
    wp.check_url(URL_A)
    wp.check_url('https://abc.blob.core.windows.net/b/x?sig=1', redirect=True)
    with pytest.raises(wp.WinpairsError):
        wp.check_url('https://evil.example/x', redirect=True)


def test_redirect_to_disallowed_host_blocked_and_allowed_blob_followed():
    blob = 'https://shard.blob.core.windows.net/b/x?sig=SECRET'
    ok = Fake({URL_A: wp.Response(302, location=blob), blob: b'data'})
    assert wp.fetch_checked(ok, URL_A, 100) == b'data'
    bad = Fake({URL_A: wp.Response(302, location='https://evil.example/x')})
    with pytest.raises(wp.WinpairsError):
        wp.fetch_checked(bad, URL_A, 100)
    assert bad.calls == [URL_A]
    with pytest.raises(wp.WinpairsError):
        wp.fetch_checked(Fake({}), 'http://msdl.microsoft.com/x', 100)


def test_size_cap_enforced_on_body():
    with pytest.raises(wp.WinpairsError, match='cap'):
        wp.fetch_checked(Fake({URL_A: b'x' * 11}), URL_A, 10)


def test_gzip_bomb_rejected(monkeypatch):
    monkeypatch.setattr(wp, 'MAX_INDEX_JSON_BYTES', 1000)
    with pytest.raises(wp.WinpairsError, match='too large'):
        wp.load_index(Fake({IDX_URL: gzip.compress(b'[' + b'0,' * 5000 + b'0]')}), 'tcpip.sys')


# ---- run()
def test_run_found_downloads_and_verifies(tmp_path):
    m = wp.run([case()], Fake(routes(index(A, B))), tmp_path)
    c = m['cases'][0]
    assert c['status'] == 'found' and m['schema'] == wp.OUT_SCHEMA
    assert c['older']['source_url'] == URL_A and c['newer']['source_url'] == URL_B
    assert c['older']['sha256_verified'] and c['older']['path'] == 'c1/older/tcpip.sys'
    assert (tmp_path / 'c1/newer/tcpip.sys').read_bytes() == BIN_B


def test_hash_mismatch_rejected_and_not_left_on_disk(tmp_path):
    m = wp.run([case()], Fake(routes(index(A, B), {URL_A: b'tampered'})), tmp_path)
    c = m['cases'][0]
    assert c['status'] == 'missing' and 'sha256 mismatch' in c['older']['reason']
    assert not (tmp_path / 'c1/older/tcpip.sys').exists()


def test_missing_binary_or_index_is_status_missing_not_error(tmp_path):
    m = wp.run([case(), case('c2', 'nope.sys 1.2.3.4', 'nope.sys 1.2.3.5')],
               Fake(routes(index(A, B), {URL_B: wp.Response(404)})), tmp_path)
    assert [c['status'] for c in m['cases']] == ['missing', 'missing']
    assert m['cases'][0]['newer']['status'] == 'missing' and m['cases'][0]['older']['status'] == 'found'
    assert wp.exit_code(m) == 1


def test_resolve_only_makes_no_binary_requests():
    f = Fake(routes(index(A, B)))
    m = wp.run([case()], f, None)
    assert m['cases'][0]['status'] == 'found' and f.calls == [IDX_URL]


def test_index_fetched_once_per_filename(tmp_path):
    f = Fake(routes(index(A, B)))
    wp.run([case('a'), case('b')], f, None)
    assert f.calls.count(IDX_URL) == 1


def test_manifest_has_no_redirect_url_or_query(tmp_path):
    blob = 'https://s.blob.core.windows.net/b/x?sig=SECRET'
    m = wp.run([case()], Fake(routes(index(A, B), {URL_A: wp.Response(302, location=blob), blob: BIN_A})), tmp_path)
    assert m['cases'][0]['status'] == 'found'
    assert 'SECRET' not in json.dumps(m) and 'blob.core' not in json.dumps(m)


# ---- CLI / exit codes / confinement
def write_manifest(tmp_path, cases):
    p = tmp_path / 'm.json'
    p.write_text(json.dumps({'schema': wp.IN_SCHEMA, 'cases': cases}))
    return p


def cli(tmp_path, f, *extra, manifest=None):
    return wp.main(['--manifest', str(manifest or write_manifest(tmp_path, [case()])), '--out-dir', str(tmp_path / 'o'),
                    '--pair-manifest', str(tmp_path / 'pm.json'), *extra], fetch=f)


def test_exit_0_when_found_and_manifest_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli(tmp_path, Fake(routes(index(A, B)))) == 0
    assert json.loads((tmp_path / 'pm.json').read_text())['cases'][0]['status'] == 'found'


def test_exit_0_when_only_some_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mp = write_manifest(tmp_path, [case(), case('c2', 'zz.sys 1.0.0.1', 'zz.sys 1.0.0.2')])
    assert cli(tmp_path, Fake(routes(index(A, B))), manifest=mp) == 0


def test_exit_1_when_all_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli(tmp_path, Fake({})) == 1


def test_exit_2_unknown_case_bad_schema_and_outside_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = Fake(routes(index(A, B)))
    assert cli(tmp_path, f, '--case', 'nope') == 2
    bad = tmp_path / 'bad.json'
    bad.write_text('{"schema": "other/1", "cases": []}')
    assert cli(tmp_path, f, manifest=bad) == 2
    assert wp.main(['--manifest', '/etc/passwd', '--out-dir', str(tmp_path), '--pair-manifest',
                    str(tmp_path / 'p.json')], fetch=f) == 2
    assert wp.main([], fetch=f) == 2


def test_case_filter_selects_subset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mp = write_manifest(tmp_path, [case('a'), case('b')])
    assert cli(tmp_path, Fake(routes(index(A, B))), '--case', 'b', '--resolve-only', manifest=mp) == 0
    assert [c['id'] for c in json.loads((tmp_path / 'pm.json').read_text())['cases']] == ['b']


def test_unsafe_case_id_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mp = write_manifest(tmp_path, [case('../evil')])
    assert cli(tmp_path, Fake(routes(index(A, B))), manifest=mp) == 2
