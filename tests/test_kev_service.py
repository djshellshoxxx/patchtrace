"""kev/1 service: what the CLI and the dock do with a catalog folder (fetch, import, read, compare), over the real store
and a fake network. Nothing here opens a socket."""
from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from kev_helpers import NOW, SYNTHETIC, document, entry, fixture_bytes, parse_bytes, render, socket_guard

from patchtrace.kev import limits, service
from patchtrace.kev.contracts import KevError, plan_for
from patchtrace.kev.service import KevService

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)

SITE, MIRROR = plan_for('cisa-site'), plan_for('cisa-github')
MIRROR_HOST, SITE_HOST = 'raw.githubusercontent.com', 'www.cisa.gov'
STAMP = '2099-03-02T12:00:00Z'                  # NOW, as the contract writes it


class Response:
    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None):
        self.status, self._body, self.headers, self.closed = status, body, dict(headers or {}), False

    def read1(self, size: int) -> bytes:
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self) -> None:
        self.closed = True


def network(routes: dict, calls: list | None = None):
    """An opener: bytes answer 200 as ``text/plain`` (as the GitHub mirror does), an int is an HTTP status, a tuple is
    ``(status, headers)``."""
    def opener(url, headers, timeout):
        if calls is not None:
            calls.append((url, dict(headers)))
        answer = routes.get(url, 404)
        if isinstance(answer, bytes):
            return Response(200, answer, {'Content-Type': 'text/plain; charset=utf-8'})
        if isinstance(answer, tuple):
            return Response(answer[0], b'', answer[1])
        return Response(answer)
    return opener


def make(tmp_path: Path, routes: dict | None = None, *, calls: list | None = None, now: datetime = NOW) -> KevService:
    return KevService(tmp_path / 'kev', now=lambda: now, opener=network(routes or {}, calls),
                      sleep=lambda seconds, cancel: None)


def catalog_bytes(day: int = 1, entries: int = 10, **first) -> bytes:
    """A valid synthetic catalog released on 2098-02-<day>; ``first`` overrides fields of its first entry."""
    rows = [entry(1, **first), *(entry(n) for n in range(2, entries + 1))]
    return render(document(rows, dateReleased=f'2098-02-{day:02d}T12:00:00Z', catalogVersion=f'2098.02.{day:02d}'))


def refused(call, *args, **kw) -> KevError:
    with pytest.raises(KevError) as info:
        call(*args, **kw)
    return info.value


# --- fetch ----------------------------------------------------------------------------------------------------

def test_fetch_downloads_checks_and_installs_and_records_the_one_consent(tmp_path):
    raw, calls, lines = fixture_bytes(SYNTHETIC), [], []
    svc = make(tmp_path, {MIRROR.url: raw}, calls=calls)
    installed = svc.fetch('cisa-github', MIRROR_HOST, announce=lines.append)
    meta = installed.meta
    assert installed.result.outcome == 'installed' and installed.in_use == meta
    assert (meta.source, meta.source_url, meta.final_url) == ('cisa-github', MIRROR.url, MIRROR.url)
    assert (meta.authenticity, meta.retrieved_at, meta.raw_sha256) == (
        'tls-allowlisted-host', STAMP, hashlib.sha256(raw).hexdigest())
    assert meta.consent.model_dump() == {'operation': 'fetch-kev-catalog', 'source': 'cisa-github', 'url': MIRROR.url,
                                         'plan_sha': MIRROR.plan_sha, 'granted_at': STAMP, 'surface': 'cli'}
    assert calls == [(MIRROR.url, {'Accept': 'application/json', 'User-Agent': 'PatchTrace'})]
    assert lines == [f'GET {MIRROR.url}']
    assert svc.store.load_current().catalog.meta == meta                 # the consent survives the round trip


def test_fetch_from_the_site_uses_the_site_address_and_the_gui_surface_is_recorded(tmp_path):
    calls = []
    svc = make(tmp_path, {SITE.url: fixture_bytes(SYNTHETIC)}, calls=calls)
    installed = svc.fetch('cisa-site', SITE_HOST, surface='gui')
    assert [url for url, _ in calls] == [SITE.url]
    assert (installed.meta.source, installed.meta.consent.surface) == ('cisa-site', 'gui')


@pytest.mark.parametrize('hosts', ['', '   ', 'www.cisa.gov', 'raw.githubusercontent.com,www.cisa.gov', 'github.com',
                                   'raw.githubusercontent.com.', 'raw.githubusercontent.com:443', 'cisa.gov',
                                   'raw.githubusercontent.com www.cisa.gov'],
                         ids=['empty', 'blank', 'other-source', 'both', 'github', 'trailing-dot', 'port', 'bare',
                              'spaced'])
def test_fetch_needs_the_exact_consent_host_before_anything_happens(tmp_path, hosts):
    calls = []
    svc = make(tmp_path, {MIRROR.url: fixture_bytes(SYNTHETIC)}, calls=calls)
    error = refused(svc.fetch, 'cisa-github', hosts)
    assert error.code == 'PT-KEV-CONSENT' and error.exit_code == 2 and 'raw.githubusercontent.com' in error.message
    assert calls == [] and not (tmp_path / 'kev').exists()


def test_the_consent_host_is_matched_ignoring_case_and_padding(tmp_path):
    consent = service.consent_for(MIRROR, '  Raw.GitHubUserContent.com ')
    assert consent.urls == frozenset({MIRROR.url})
    assert refused(service.consent_for, SITE, 'raw.githubusercontent.com').code == 'PT-KEV-CONSENT'


def test_an_unknown_source_is_an_input_error(tmp_path):
    assert refused(make(tmp_path).fetch, 'cisa-mirror', MIRROR_HOST).code == 'PT-KEV-INPUT'
    assert refused(make(tmp_path).fetch, 'cisa-github', MIRROR_HOST, surface='web').code == 'PT-KEV-INPUT'


@pytest.mark.parametrize('answer, code', [(404, 'PT-KEV-PROVIDER'), (500, 'PT-KEV-PROVIDER'), (503, 'PT-KEV-NETWORK'),
                                          ((302, {'Location': 'https://evil.example/x.json'}), 'PT-KEV-PROVIDER')],
                         ids=['404', '500', '503-after-retries', 'cross-host-redirect'])
def test_a_refused_download_installs_nothing(tmp_path, answer, code):
    svc = make(tmp_path, {MIRROR.url: answer})
    assert refused(svc.fetch, 'cisa-github', MIRROR_HOST).code == code
    assert svc.store.load_current() is None


@pytest.mark.parametrize('body, code', [
    (b'<html><body>Access denied</body></html>', 'PT-KEV-FORMAT'),
    (b'', 'PT-KEV-FORMAT'),
    (fixture_bytes(SYNTHETIC)[:400], 'PT-KEV-FORMAT'),
    (b'cveID,vendorProject,product\n', 'PT-KEV-UNSUPPORTED'),
    (render(document(count=99)), 'PT-KEV-VALIDATE'),
    (b'[]', 'PT-KEV-FORMAT'),
], ids=['html', 'empty', 'truncated', 'csv', 'count-mismatch', 'array'])
def test_a_downloaded_file_that_fails_the_checks_never_replaces_the_catalog_in_use(tmp_path, body, code):
    good = catalog_bytes(5)
    svc = make(tmp_path, {MIRROR.url: good})
    kept = svc.fetch('cisa-github', MIRROR_HOST).meta
    svc = make(tmp_path, {MIRROR.url: body})
    assert refused(svc.fetch, 'cisa-github', MIRROR_HOST).code == code
    assert svc.store.load_current().catalog.meta == kept


def test_a_download_above_the_size_limit_is_refused(tmp_path):
    svc = make(tmp_path, {MIRROR.url: b' ' * (limits.MAX_CATALOG_BYTES + 1)})
    assert refused(svc.fetch, 'cisa-github', MIRROR_HOST).code == 'PT-KEV-LIMIT'
    assert svc.store.load_current() is None


def test_a_mirror_older_than_the_catalog_in_use_is_stored_and_the_newer_one_kept(tmp_path):
    newer = make(tmp_path, {MIRROR.url: catalog_bytes(5)}).fetch('cisa-github', MIRROR_HOST).meta
    installed = make(tmp_path, {MIRROR.url: catalog_bytes(3)}).fetch('cisa-github', MIRROR_HOST)
    assert installed.result.outcome == 'kept-newer'
    assert installed.meta.catalog_version == '2098.02.03' and installed.in_use == newer
    assert make(tmp_path).store.load_current().catalog.meta == newer


def test_fetching_the_catalog_in_use_again_changes_nothing(tmp_path):
    svc = make(tmp_path, {MIRROR.url: catalog_bytes(5)})
    first = svc.fetch('cisa-github', MIRROR_HOST)
    again = svc.fetch('cisa-github', MIRROR_HOST)
    assert again.result.outcome == 'unchanged' and again.in_use == first.meta


def test_a_catalog_that_shrinks_needs_an_explicit_accept(tmp_path):
    big = make(tmp_path, {MIRROR.url: catalog_bytes(1, 10)}).fetch('cisa-github', MIRROR_HOST).meta
    svc = make(tmp_path, {MIRROR.url: catalog_bytes(2, 8)})
    error = refused(svc.fetch, 'cisa-github', MIRROR_HOST)
    assert error.code == 'PT-KEV-SHRINK' and '2 fewer' in error.message
    assert svc.store.load_current().catalog.meta == big
    installed = svc.fetch('cisa-github', MIRROR_HOST, accept_shrink=True)
    assert installed.result.outcome == 'installed' and installed.in_use.entry_count == 8


def test_a_fetch_cancelled_up_front_stores_nothing(tmp_path):
    cancel, calls = threading.Event(), []
    cancel.set()
    svc = make(tmp_path, {MIRROR.url: catalog_bytes()}, calls=calls)
    error = refused(svc.fetch, 'cisa-github', MIRROR_HOST, cancel=cancel)
    assert error.code == 'PT-KEV-CANCEL' and error.exit_code == 5 and calls == []
    assert svc.store.load_current() is None


# --- import ---------------------------------------------------------------------------------------------------

def test_import_reads_a_local_file_and_makes_it_current(tmp_path):
    path = tmp_path / 'saved.json'
    path.write_bytes(fixture_bytes(SYNTHETIC))
    installed = make(tmp_path).import_file(path)
    meta = installed.meta
    assert installed.result.outcome == 'installed' and installed.in_use == meta
    assert (meta.source, meta.authenticity, meta.file_name, meta.retrieved_at) == (
        'local-import', 'unverified-local-file', 'saved.json', STAMP)
    assert (meta.source_url, meta.final_url, meta.consent) == (None, None, None)
    assert make(tmp_path).store.load_current().catalog.meta == meta


@pytest.mark.parametrize('name, label', [
    ('plain.json', 'plain.json'), ('x' + chr(0x202e) + 'y.json', 'xy.json'), ('a\\b.json', None), ('a/b.json', None),
    ('..', None), ('\x1b[31m', '[31m'), ('', None), (chr(0x200b), None), ('n' * 300, ('n' * 252) + '...')],
    ids=['plain', 'bidi', 'backslash', 'slash', 'dots', 'escape', 'empty', 'zero-width', 'long'])
def test_the_file_name_label_is_plain_text_or_left_out(name, label):
    assert service.file_label(name) == label


@pytest.mark.parametrize('content, code', [
    (b'cveID,vendorProject\nCVE-2099-1,x\n', 'PT-KEV-UNSUPPORTED'), (b'not json', 'PT-KEV-FORMAT'),
    (b'', 'PT-KEV-FORMAT'), (b' ' * (limits.MAX_CATALOG_BYTES + 1), 'PT-KEV-LIMIT')],
    ids=['csv', 'garbage', 'empty', 'too-large'])
def test_import_refuses_files_that_are_not_a_kev_catalog(tmp_path, content, code):
    path = tmp_path / 'f.json'
    path.write_bytes(content)
    svc = make(tmp_path)
    assert refused(svc.import_file, path).code == code
    assert svc.store.load_current() is None


def test_import_of_a_missing_file_or_a_folder_is_an_input_error(tmp_path):
    svc = make(tmp_path)
    assert refused(svc.import_file, tmp_path / 'absent.json').code == 'PT-KEV-INPUT'
    assert refused(svc.import_file, tmp_path).code == 'PT-KEV-INPUT'


def test_import_follows_the_same_shrink_and_older_rules_as_a_download(tmp_path):
    svc = make(tmp_path)
    paths = {}
    for name, (day, count) in {'big': (5, 10), 'small': (6, 8), 'old': (3, 10)}.items():
        paths[name] = tmp_path / f'{name}.json'
        paths[name].write_bytes(catalog_bytes(day, count))
    big = svc.import_file(paths['big']).meta
    assert refused(svc.import_file, paths['small']).code == 'PT-KEV-SHRINK'
    assert svc.import_file(paths['small'], accept_shrink=True).result.outcome == 'installed'
    older = svc.import_file(paths['old'])
    assert older.result.outcome == 'kept-newer' and older.in_use.catalog_version == '2098.02.06'
    assert big.catalog_version == '2098.02.05'


def test_read_catalog_parses_a_file_without_installing_it(tmp_path):
    path = tmp_path / 'look.json'
    path.write_bytes(fixture_bytes(SYNTHETIC))
    svc = make(tmp_path)
    catalog = svc.read_catalog(path)
    assert catalog.meta.entry_count == 4 and catalog.meta.source == 'local-import'
    assert svc.store.load_current() is None and not (tmp_path / 'kev').exists()
    assert refused(svc.read_catalog, tmp_path / 'absent.json').code == 'PT-KEV-INPUT'


# --- compare --------------------------------------------------------------------------------------------------

def stored(svc: KevService, day: int, entries: int, **first):
    """Put the synthetic catalog of that day into the store directly and return its description."""
    raw = catalog_bytes(day, entries, **first)
    catalog = parse_bytes(raw)
    svc.store.install(raw, catalog, now=STAMP)
    return catalog.meta


def test_diff_compares_the_catalog_in_use_with_the_one_before_it(tmp_path):
    svc = make(tmp_path)
    one, two, three = (stored(svc, day, 10 + day) for day in (1, 2, 3))
    comparison = svc.diff()
    assert (comparison.old.meta, comparison.new.meta) == (two, three)
    assert comparison.delta.added_count == 1 and comparison.delta.from_snapshot_id == two.snapshot_id
    earlier = svc.diff(to_id=two.snapshot_id)
    assert (earlier.old.meta, earlier.new.meta) == (one, two)
    explicit = svc.diff(from_id=one.snapshot_id)
    assert (explicit.old.meta, explicit.new.meta) == (one, three) and explicit.delta.added_count == 2
    same = svc.diff(from_id=three.snapshot_id, to_id=three.snapshot_id)
    assert (same.delta.added_count, same.delta.removed_count, same.delta.changed_count) == (0, 0, 0)


def test_diff_reports_a_changed_ransomware_flag(tmp_path):
    svc = make(tmp_path)
    stored(svc, 1, 10)
    stored(svc, 2, 10, knownRansomwareCampaignUse='Known')
    delta = svc.diff().delta
    assert [change.cve_id for change in delta.changed] == ['CVE-2098-00001']
    assert (delta.changed[0].before.ransomware_use, delta.changed[0].after.ransomware_use) == ('unknown', 'known')


def test_diff_needs_two_stored_catalogs_and_known_ids(tmp_path):
    svc = make(tmp_path)
    assert refused(svc.diff).code == 'PT-KEV-NOTFOUND'
    one = stored(svc, 1, 10)
    error = refused(svc.diff)
    assert error.code == 'PT-KEV-NOTFOUND' and error.exit_code == 4 and 'two' in error.message
    assert refused(svc.diff, from_id='f' * 64).code == 'PT-KEV-NOTFOUND'
    assert refused(svc.diff, to_id='f' * 64).code == 'PT-KEV-NOTFOUND'
    assert refused(svc.diff, from_id='../x').code == 'PT-KEV-INPUT'
    assert svc.diff(from_id=one.snapshot_id, to_id=one.snapshot_id).delta.added_count == 0


# --- clock ----------------------------------------------------------------------------------------------------

def test_stamp_writes_the_contract_format_in_utc_and_refuses_a_naive_time():
    assert service.stamp(datetime(2099, 3, 2, 8, 0, 5, 999999, tzinfo=UTC)) == '2099-03-02T08:00:05Z'
    assert service.stamp(datetime(2099, 3, 2, 8, 0, 0, tzinfo=timezone(timedelta(hours=2)))) == '2099-03-02T06:00:00Z'
    with pytest.raises(ValueError):
        service.stamp(datetime(2099, 3, 2, 8, 0, 0))
    assert service.utc_now().tzinfo is not None


def test_the_service_uses_the_module_defaults_when_nothing_is_injected(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(service.transport, 'urllib_open', network({MIRROR.url: catalog_bytes()}, calls))
    monkeypatch.setattr(service, 'utc_now', lambda: NOW)
    installed = KevService(tmp_path / 'kev').fetch('cisa-github', MIRROR_HOST)
    assert installed.meta.retrieved_at == STAMP and len(calls) == 1
