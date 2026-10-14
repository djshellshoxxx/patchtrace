"""kev/1 service: plan without network, consented fetch, shrink and older-mirror rules, import, status, diff."""
from __future__ import annotations

import datetime
import hashlib
import json
import socket
from pathlib import Path

import pytest

from patchtrace.kev import service
from patchtrace.kev.contracts import KevError, KevPlan
from patchtrace.kev.store import KevStore
from patchtrace.kev.transport import Fetched

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
NOW = datetime.datetime(2099, 3, 2, 8, 30, tzinfo=datetime.UTC)


def build(version='v1', released='2099-03-01T12:00:00Z', n=3) -> bytes:
    data = json.loads((FIXTURES / 'kev-synthetic-2099.json').read_text(encoding='utf-8'))
    template = data['vulnerabilities'][0]
    data['catalogVersion'], data['dateReleased'] = version, released
    data['vulnerabilities'] = [{**template, 'cveID': f'CVE-2099-{10000 + i}'} for i in range(n)]
    data['count'] = n
    return json.dumps(data).encode('utf-8')


def fetcher(body: bytes):
    def fetch(plan: KevPlan) -> Fetched:
        return Fetched(url=plan.url, final_url=plan.url, body=body, sha256=hashlib.sha256(body).hexdigest(),
                       retrieved_at='2099-03-02T08:30:00Z')
    return fetch


@pytest.fixture
def store(tmp_path):
    return KevStore(tmp_path / 'kev', sleep=lambda _s: None)


def now() -> datetime.datetime:
    return NOW


def test_plan_does_no_network(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError('network touched')

    monkeypatch.setattr(socket, 'getaddrinfo', boom)
    monkeypatch.setattr(socket.socket, 'connect', boom)
    planned = service.plan('cisa-site')
    assert planned.url.startswith('https://www.cisa.gov/') and planned.method == 'GET'
    assert service.plan('cisa-github').host == 'raw.githubusercontent.com'
    with pytest.raises(KevError) as info:
        service.plan('somewhere-else')
    assert info.value.code == 'PT-KEV-INPUT'


@pytest.mark.parametrize('hosts', [[], ['raw.githubusercontent.com'], ['www.cisa.gov', 'raw.githubusercontent.com'],
                                   ['cisa.gov'], ['WWW.CISA.GOV.evil.example']],
                         ids=['none', 'other-host', 'both', 'bare-domain', 'suffix'])
def test_consent_hosts_must_equal_the_plan_host(hosts):
    with pytest.raises(KevError) as info:
        service.consent_for(service.plan('cisa-site'), hosts)
    assert info.value.code == 'PT-KEV-CONSENT'


def test_consent_hosts_are_case_insensitive_and_trimmed():
    consent = service.consent_for(service.plan('cisa-site'), [' WWW.cisa.gov '])
    assert consent.hosts == {'www.cisa.gov'}


def test_fetch_installs_and_records_consent(store):
    kev_plan = service.plan('cisa-github')
    outcome = service.fetch_catalog(store, kev_plan, fetcher(build()), now, surface='gui')
    meta = outcome.catalog.meta
    assert outcome.installed.current_changed
    assert (meta.source, meta.authenticity, meta.source_url) == ('cisa-github', 'tls-allowlisted-host', kev_plan.url)
    assert meta.consent.plan_sha == kev_plan.plan_sha and meta.consent.surface == 'gui'
    assert meta.consent.granted_at == '2099-03-02T08:30:00Z'
    assert store.load_current().catalog == outcome.catalog


def test_fetch_of_garbage_keeps_the_catalog_in_use(store):
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build()), now)
    with pytest.raises(KevError) as info:
        service.fetch_catalog(store, service.plan('cisa-site'), fetcher(b'<html>blocked</html>'), now)
    assert info.value.code == 'PT-KEV-FORMAT'
    assert store.load_current().catalog.meta.catalog_version == 'v1'


def test_shrink_is_refused_unless_accepted(store):
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build(n=20)), now)
    smaller = build('v2', '2099-03-05T12:00:00Z', n=10)
    with pytest.raises(KevError) as info:
        service.fetch_catalog(store, service.plan('cisa-site'), fetcher(smaller), now)
    assert info.value.code == 'PT-KEV-SHRINK'
    assert '10 fewer entries' in info.value.message
    assert store.load_current().catalog.meta.entry_count == 20
    forced = service.fetch_catalog(store, service.plan('cisa-site'), fetcher(smaller), now, accept_shrink=True)
    assert forced.installed.current_changed and store.load_current().catalog.meta.entry_count == 10


def test_a_ten_percent_drop_is_not_a_shrink(store):
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build(n=20)), now)
    ok = service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build('v2', '2099-03-05T12:00:00Z', n=18)),
                               now)
    assert ok.installed.current_changed


def test_older_mirror_is_kept_out(store):
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build('v2', '2099-03-05T12:00:00Z')), now)
    outcome = service.fetch_catalog(store, service.plan('cisa-github'),
                                    fetcher(build('v1', '2099-03-01T12:00:00Z', n=1)), now)
    assert not outcome.installed.current_changed
    assert store.load_current().catalog.meta.catalog_version == 'v2'


def test_import_file_records_basename_only(store, tmp_path):
    path = tmp_path / 'saved.json'
    path.write_bytes(build())
    outcome = service.import_file(store, path, now)
    assert outcome.catalog.meta.source == 'local-import'
    assert outcome.catalog.meta.authenticity == 'unverified-local-file'
    assert outcome.catalog.meta.file_name == 'saved.json'
    assert store.load_current().catalog == outcome.catalog


@pytest.mark.parametrize('content,expected', [
    (b'cveID,vendorProject\nCVE-2099-1,x\n', 'PT-KEV-UNSUPPORTED'),
    (b'not json', 'PT-KEV-FORMAT'),
], ids=['csv', 'junk'])
def test_import_refuses_bad_files(store, tmp_path, content, expected):
    path = tmp_path / 'bad'
    path.write_bytes(content)
    with pytest.raises(KevError) as info:
        service.import_file(store, path, now)
    assert info.value.code == expected
    assert store.load_current() is None


def test_import_missing_and_oversized_files(store, tmp_path):
    with pytest.raises(KevError) as info:
        service.import_file(store, tmp_path / 'absent.json', now)
    assert info.value.code == 'PT-KEV-INPUT'
    big = tmp_path / 'big.json'
    big.write_bytes(b'0' * 100)
    with pytest.raises(KevError) as info:
        service.read_file(big, 10)
    assert info.value.code == 'PT-KEV-LIMIT'


def test_status_reports_freshness_and_age_limit(store):
    empty = service.status(store, now)
    assert empty.loaded is None and empty.freshness == 'unknown'
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build()), now)
    fresh = service.status(store, now, max_age_days=3)
    assert (fresh.freshness, fresh.age_days, fresh.older_than_limit) == ('fresh', 1, False)
    later = service.status(store, lambda: NOW + datetime.timedelta(days=20), max_age_days=3)
    assert (later.freshness, later.older_than_limit) == ('stale', True)


def test_snapshot_file_ids_and_limits(tmp_path):
    one, many = tmp_path / 'one.json', tmp_path / 'many.json'
    one.write_text(json.dumps({'cve_id': 'CVE-2099-10001', 'other': 1}), encoding='utf-8')
    many.write_text(json.dumps([{'cve_id': 'CVE-2099-10002'}, {'cve_id': 'CVE-2099-10001'}, 7]), encoding='utf-8')
    assert service.gather_cves(['cve-2099-10003'], [one, many]) == \
        ['cve-2099-10003', 'CVE-2099-10001', 'CVE-2099-10002']
    bad = tmp_path / 'bad.json'
    bad.write_text('{"x": 1}', encoding='utf-8')
    with pytest.raises(KevError) as info:
        service.gather_cves([], [bad])
    assert info.value.code == 'PT-KEV-FORMAT'
    with pytest.raises(KevError) as info:
        service.gather_cves([f'CVE-2099-{n}' for n in range(10000, 15001)], [])
    assert info.value.code == 'PT-KEV-LIMIT'


def test_diff_defaults_to_previous_versus_current(store):
    with pytest.raises(KevError) as info:
        service.diff_snapshots(store, None, None)
    assert info.value.code == 'PT-KEV-NOTFOUND'
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build(n=2)), now)
    with pytest.raises(KevError):
        service.diff_snapshots(store, None, None)
    service.fetch_catalog(store, service.plan('cisa-site'), fetcher(build('v2', '2099-03-05T12:00:00Z', n=3)), now)
    delta, newer = service.diff_snapshots(store, None, None)
    assert (delta.added, delta.removed, delta.added_count) == (('CVE-2099-10002',), (), 1)
    assert newer.meta.catalog_version == 'v2' and delta.from_catalog_version == 'v1'
