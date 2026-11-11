"""Offline tests for tools/research_qualification/pins_check.py and the committed windows-pins.json."""
from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest

from tools.research_qualification import pins_check as pc
from tools.research_qualification import winpairs as wp

PINS = Path(__file__).resolve().parents[1] / 'docs' / 'research' / 'accuracy-cases' / 'windows-pins.json'
SRC = {'url': 'https://winbindex.m417z.com/data/by_filename_compressed/tcpip.sys.json.gz', 'fetched': '2026-11-07'}


def side(ver, kb, sha, ts, date):
    return {'version': ver, 'kb': kb, 'sha256': sha * 64, 'timestamp': ts, 'virtual_size': 0x50000,
            'release_date': date, 'windows_version': '21H2', 'arch': 'amd64'}


def good_entry():
    return {'case_id': 'win-cve-1-tcpip', 'file': 'tcpip.sys', 'status': 'pinned', 'reason': 'why', 'caveats': [],
            'before': side('10.0.19041.1', 'KB1000001', 'a', 111, '2022-08-09'),
            'after': side('10.0.19041.2', 'KB1000002', 'b', 222, '2022-09-13'), 'source': SRC}


def doc(*entries):
    return {'schema': pc.SCHEMA, 'generated': '2026-11-07', 'entries': list(entries)}


def test_good_doc_validates():
    assert pc.validate(doc(good_entry())) == []


@pytest.mark.parametrize('mut, text', [
    (lambda e: e['after'].update(sha256=e['before']['sha256']), 'identical'),
    (lambda e: e['after'].update(version='10.0.19041.1'), 'does not change'),
    (lambda e: e['after'].update(sha256='XYZ'), 'sha256 must be'),
    (lambda e: e['after'].update(release_date='2022-08-01'), 'precede'),
    (lambda e: e['after'].update(arch='x86'), 'share arch'),
    (lambda e: e['before'].update(timestamp=-1), 'timestamp'),
    (lambda e: e['before'].update(kb='5000'), 'kb must be'),
    (lambda e: e.update(reason=' '), 'reason'),
    (lambda e: e.update(source={'url': 'http://x', 'fetched': 'today'}), 'source'),
    (lambda e: e.update(status='maybe'), 'status'),
])
def test_bad_entries_are_reported(mut, text):
    e = good_entry()
    mut(e)
    assert any(text in p for p in pc.validate(doc(e)))


def test_unpinned_requires_null_sides_and_duplicates_rejected():
    e = good_entry()
    e['status'] = 'unpinned'
    assert any('null' in p for p in pc.validate(doc(e)))
    e['before'] = e['after'] = None
    assert pc.validate(doc(e)) == []
    assert any('duplicate' in p for p in pc.validate(doc(e, copy.deepcopy(e))))


def test_fetch_check_must_agree_with_hashes():
    e = good_entry()
    e['fetch_check'] = {'before': {'sha256': 'a' * 64, 'sha256_matches': False},
                        'after': {'sha256': None, 'sha256_matches': False}}
    assert any('contradicts equal' in p for p in pc.validate(doc(e)))
    e['fetch_check']['before']['sha256_matches'] = True
    assert pc.validate(doc(e)) == []


def test_cross_check_against_manifest():
    manifest = {'schema': pc.CASE_SCHEMA, 'cases': [{'id': 'win-cve-1-tcpip', 'older': {'ref': 'TCPIP.sys, 2022-Aug'}},
                                                    {'id': 'other', 'older': {'ref': 'a.dll'}}]}
    files = pc.manifest_files(manifest)
    problems = pc.cross_check(doc(good_entry()), files)
    assert problems == ['case other has no pins entry']
    with pytest.raises(pc.PinsError):
        pc.manifest_files({'schema': 'nope', 'cases': []})


def test_cli_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / 'pins.json'
    p.write_text(json.dumps(doc(good_entry())))
    out = tmp_path / 'cases.json'
    assert pc.main(['--pins', str(p), '--emit-case-manifest', str(out)]) == 0
    assert json.loads(out.read_text())['cases'][0]['older']['sha256'] == 'a' * 64
    bad = good_entry()
    bad['after']['version'] = bad['before']['version']
    p.write_text(json.dumps(doc(bad)))
    assert pc.main(['--pins', str(p)]) == 1
    assert pc.main(['--pins', str(tmp_path / 'missing.json')]) == 2
    assert pc.main(['--pins', '/etc/hostname']) == 2
    assert pc.main([]) == 2
    capsys.readouterr()


def _fake_index(e):
    idx = {}
    for k in ('before', 'after'):
        s = e[k]
        upd = {'updateInfo': {'releaseDate': s['release_date']}} if s['release_date'] else {}
        idx[s['sha256']] = {'fileInfo': {'sha256': s['sha256'], 'machineType': 0x8664, 'timestamp': s['timestamp'],
                                         'virtualSize': s['virtual_size'], 'version': s['version'] + ' (WinBuild)'},
                            'windowsVersions': {s['windows_version']: {s['kb'] or 'BASE': upd}}}
    return idx


def test_winpairs_consumes_emitted_manifest():
    e = good_entry()
    cm = pc.to_case_manifest(doc(e))
    assert cm['schema'] == wp.IN_SCHEMA
    body = gzip.compress(json.dumps(_fake_index(e)).encode())

    def fetch(url, max_bytes, timeout):
        return wp.Response(200, body) if url.endswith('/tcpip.sys.json.gz') else wp.Response(404)

    out = wp.run(cm['cases'], fetch, None)
    c = out['cases'][0]
    assert c['status'] == 'found'
    assert c['older']['timestamp'] == 111 and c['newer']['virtual_size'] == 0x50000
    assert c['newer']['expected_sha256'] == 'b' * 64


def test_committed_pins_file():
    d = json.loads(PINS.read_text(encoding='utf-8'))
    assert pc.validate(d) == []
    assert len(d['entries']) == 31
    pinned = [e for e in d['entries'] if e['status'] == 'pinned']
    assert len(pinned) == 26
    cm = pc.to_case_manifest(d)
    assert len(cm['cases']) == 26

    def fetch(url, max_bytes, timeout):
        name = url.rsplit('/', 1)[-1].removesuffix('.json.gz')
        idx = {}
        for e in pinned:
            if e['file'].lower() == name:
                for sha, ent in _fake_index(e).items():  # one sha can be pinned by several cases: merge its KBs
                    cur = idx.setdefault(sha, ent)
                    for wv, kbs in ent['windowsVersions'].items():
                        cur['windowsVersions'].setdefault(wv, {}).update(kbs)
        return wp.Response(200, gzip.compress(json.dumps(idx).encode())) if idx else wp.Response(404)

    out = wp.run(cm['cases'], fetch, None)
    assert all(c['status'] == 'found' for c in out['cases'])
