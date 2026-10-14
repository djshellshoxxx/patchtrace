"""CSAF directory discovery (SPEC-28 section C) against a FAKE Microsoft-shaped server built from SYNTHETIC
fixtures. No URL is ever constructed from a CVE; file names are hints; integrity files are checked."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import discovery as dc
from patchtrace.intelligence.csaf import transport as tr

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
BASE = 'https://msrc.microsoft.com/csaf'
ADV = f'{BASE}/advisories/2099/pt-synth_cve-2099-10001.json'
VEX = f'{BASE}/vex/2099/pt-synth-vex_cve-2099-10001.json'


class Response:
    def __init__(self, status, body=b''):
        self.status, self._body, self.headers = status, body, {}

    def read(self, size):
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self):
        pass


def server_routes(**overrides) -> dict[str, tuple[int, bytes]]:
    rev2 = (FIXTURES / 'synthetic-advisory-rev2.json').read_bytes()
    vex = (FIXTURES / 'synthetic-vex.json').read_bytes()
    routes = {
        f'{BASE}/provider-metadata.json': (200, (FIXTURES / 'discovery' / 'provider-metadata.json').read_bytes()),
        f'{BASE}/advisories/index.txt': (200, (FIXTURES / 'discovery' / 'index-advisories.txt').read_bytes()),
        f'{BASE}/vex/index.txt': (200, (FIXTURES / 'discovery' / 'index-vex.txt').read_bytes()),
        ADV: (200, rev2),
        f'{ADV}.sha256': (200, f'{hashlib.sha256(rev2).hexdigest()}  pt-synth_cve-2099-10001.json\n'.encode()),
        VEX: (200, vex),
    }
    routes.update(overrides)
    return routes


def client(routes: dict) -> tuple[tr.CsafTransport, list[str]]:
    calls: list[str] = []

    def opener(url, headers, timeout):
        calls.append(url)
        status, body = routes.get(url, (404, b''))
        return Response(status, body)
    return tr.CsafTransport(tr.CsafConsent.for_hosts(['msrc.microsoft.com']), opener=opener,
                            sleep=lambda s, c: None, now=lambda: datetime(2099, 3, 1, tzinfo=UTC)), calls


def test_provider_metadata_directories_and_rolie_warning():
    raw = (FIXTURES / 'discovery' / 'provider-metadata.json').read_bytes()
    directories, warnings = dc.parse_provider_metadata(raw)
    assert directories == (f'{BASE}/advisories', f'{BASE}/vex')
    assert any('ROLIE' in w for w in warnings)


def test_provider_metadata_failures():
    meta = json.loads((FIXTURES / 'discovery' / 'provider-metadata.json').read_text(encoding='utf-8'))
    rolie_only = dict(meta, distributions=[meta['distributions'][2]])
    with pytest.raises(IntelError) as info:
        dc.parse_provider_metadata(json.dumps(rolie_only).encode())
    assert info.value.code == 'PT-INTEL-UNSUPPORTED'
    foreign = dict(meta, distributions=[{'directory_url': 'https://evil.example/csaf/advisories'}])
    with pytest.raises(IntelError) as info:
        dc.parse_provider_metadata(json.dumps(foreign).encode())
    assert info.value.code == 'PT-INTEL-PROVIDER'
    invalid = {k: v for k, v in meta.items() if k != 'role'}
    with pytest.raises(IntelError, match='provider metadata is invalid'):
        dc.parse_provider_metadata(json.dumps(invalid).encode())
    with pytest.raises(IntelError) as info:
        dc.parse_provider_metadata(b'{"a": 1, "a": 2}')
    assert info.value.code == 'PT-INTEL-FORMAT'


def test_index_lines_outside_the_filename_rule_are_skipped():
    raw = (FIXTURES / 'discovery' / 'index-advisories.txt').read_bytes()
    entries, skipped = dc.parse_index(raw, f'{BASE}/advisories')
    assert skipped == 4 and len(entries) == 4
    assert all(e.url.startswith(f'{BASE}/advisories/') and '..' not in e.url for e in entries)


def test_cve_token_boundaries():
    assert dc.matches_cve('2099/pt-synth_cve-2099-10001.json', 'CVE-2099-10001')
    assert not dc.matches_cve('2099/pt-synth_cve-2099-100010.json', 'CVE-2099-10001')
    assert not dc.matches_cve('2099/pt-synth_cve-2099-1000.json', 'CVE-2099-10001')


def test_discover_selects_index_entries_only_and_never_guesses():
    transport, calls = client(server_routes())
    found = dc.discover(transport, 'CVE-2099-10001')
    assert [c.url for c in found.candidates] == [ADV, VEX]
    assert found.skipped_lines == 4 and any('skipped' in w for w in found.warnings)
    assert calls == [f'{BASE}/provider-metadata.json', f'{BASE}/advisories/index.txt', f'{BASE}/vex/index.txt']
    # The second CVE of the same document is not in any file name: honest "not found by index name".
    transport, calls = client(server_routes())
    assert dc.discover(transport, 'CVE-2099-10002').candidates == ()
    assert not any('10002' in url for url in calls)


def test_fetch_documents_checks_integrity_and_content():
    transport, _ = client(server_routes())
    found = dc.discover(transport, 'CVE-2099-10001')
    documents, warnings = dc.fetch_documents(transport, found, 'CVE-2099-10001')
    states = {d.url: d.authenticity_state for d in documents}
    assert states == {ADV: 'tls-allowlisted-host-hash-match', VEX: 'tls-allowlisted-host'}
    assert any('no .sha256 file' in w for w in warnings)
    assert all(d.report.valid for d in documents)


def test_hash_mismatch_stops_the_fetch():
    transport, _ = client(server_routes(**{f'{ADV}.sha256': (200, b'0' * 64)}))
    found = dc.discover(transport, 'CVE-2099-10001')
    with pytest.raises(IntelError) as info:
        dc.fetch_documents(transport, found, 'CVE-2099-10001')
    assert info.value.code == 'PT-INTEL-INTEGRITY'


def test_candidates_that_fail_validation_or_lack_the_cve_are_reported_and_skipped():
    other = json.loads((FIXTURES / 'synthetic-vex.json').read_text(encoding='utf-8'))
    other['vulnerabilities'][0]['cve'] = 'CVE-2099-77777'
    routes = server_routes(**{VEX: (200, json.dumps(other).encode()),
                              ADV: (200, b'{"document": {}, "document": {}}'), f'{ADV}.sha256': (404, b'')})
    transport, _ = client(routes)
    found = dc.discover(transport, 'CVE-2099-10001')
    documents, warnings = dc.fetch_documents(transport, found, 'CVE-2099-10001')
    assert documents == []
    assert any('duplicate key' in w for w in warnings) and any('does not list CVE-2099-10001' in w for w in warnings)


def test_too_many_candidates_is_a_limit():
    lines = '\n'.join(f'2099/doc{i}_cve-2099-10001.json' for i in range(dc.MAX_CANDIDATES + 1)).encode()
    transport, _ = client(server_routes(**{f'{BASE}/advisories/index.txt': (200, lines)}))
    with pytest.raises(IntelError) as info:
        dc.discover(transport, 'CVE-2099-10001')
    assert info.value.code == 'PT-INTEL-LIMIT'


def test_provider_url_override_stays_inside_the_allowlist():
    assert dc.provider_url_ok(f'{BASE}/provider-metadata.json')
    for url in ('https://evil.example/csaf/provider-metadata.json', f'{BASE}/other.json'):
        with pytest.raises(IntelError):
            dc.provider_url_ok(url)
