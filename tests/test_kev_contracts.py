"""kev/1 records: strict, frozen, derived identities, ASCII-only CVE IDs, honest consistency rules (plan section 7)."""
from __future__ import annotations

import pytest
from kev_helpers import SHA_A, SHA_B, SYNTHETIC, parse_fixture, socket_guard
from pydantic import ValidationError

from patchtrace.enrichment.identity import domain_id
from patchtrace.kev import limits
from patchtrace.kev.contracts import (
    CODES,
    EXIT_CODES,
    SOURCE_HOSTS,
    SOURCE_URLS,
    ConsentRecord,
    KevCatalogMeta,
    KevChange,
    KevContext,
    KevCurrent,
    KevDelta,
    KevEntry,
    KevEntrySlim,
    KevError,
    KevLookup,
    KevPlan,
    KevTracked,
    clean_text,
    entry_digest,
    is_cve_id,
    plan_for,
)

STAMP = '2099-03-02T08:00:00Z'
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)


@pytest.fixture(scope='module')
def catalog():
    return parse_fixture(SYNTHETIC)


def entry_fields(**overrides) -> dict:
    value = {'cve_id': 'CVE-2099-10001', 'vendor_project': 'Microsoft', 'product': 'Windows', 'name': 'Name',
             'date_added': '2099-02-10', 'due_date': '2099-02-13', 'short_description': 'Description.',
             'required_action': 'Action.', 'notes': '', 'cwes': ('CWE-787',), 'ransomware_use': 'known',
             'forensic_triage': 'yes'}
    value.update(overrides)
    return value


def make_entry(**overrides) -> KevEntry:
    fields = entry_fields(**overrides)
    return KevEntry(**fields, entry_digest=entry_digest(fields))


# --- the plan's numbers are the code's numbers --------------------------------------------------------------

def test_limits_match_the_plan():
    assert (limits.MAX_CATALOG_BYTES, limits.MAX_ENTRIES) == (16 * 1024 ** 2, 20_000)
    assert (limits.CONNECT_TIMEOUT_S, limits.REQUEST_TIMEOUT_S, limits.PLAN_TIMEOUT_S) == (10, 60, 120)
    assert (limits.ATTEMPTS, limits.RETRY_AFTER_MAX_S, limits.MAX_REDIRECTS) == (3, 60, 2)
    assert (limits.MAX_LOOKUP_CVES, limits.MAX_CONTEXT_CVES, limits.MAX_CONTEXT_ROW_BYTES) == (5_000, 256, 256 * 1024)
    assert (limits.FRESH_MAX_DAYS, limits.AGING_MAX_DAYS) == (3, 14)
    assert (limits.MAX_DELTA_IDS, limits.MAX_PANEL_ROWS, limits.SHRINK_KEEP_PERCENT) == (500, 5_000, 90)
    assert (limits.MAX_UNKNOWN_FIELDS, limits.MAX_WARNINGS, limits.MAX_WARNING_CHARS) == (16, 20, 200)
    assert (limits.PARSER_VERSION, limits.JOIN_VERSION) == (1, 1)


def test_every_number_is_a_positive_int():
    for name in dir(limits):
        value = getattr(limits, name)
        if name.isupper() and not isinstance(value, str):
            assert type(value) is int and value > 0, name


# --- CVE IDs: ASCII only (the sibling regexes use \d, plan F18) ---------------------------------------------

@pytest.mark.parametrize('text', ['CVE-2024-38063', 'CVE-1999-0001', 'CVE-2026-104935', 'CVE-2099-' + '1' * 19],
                         ids=['normal', 'four-digit', 'six-digit', 'nineteen-digit'])
def test_valid_cve_ids(text):
    assert is_cve_id(text)


@pytest.mark.parametrize('text', [
    '', 'cve-2024-38063', 'CVE-2024-38063\n', ' CVE-2024-38063', 'CVE-2024-123', 'CVE-24-38063',
    'CVE-2099-' + '1' * 20, 'CVE-２０２４-38063', 'CVE-2024-３８０６３', 'CVE-2024-٣٨٠٦٣', 'CVE‑2024-38063',
    'CVE-2024-38063;', None, 5],
    ids=['empty', 'lowercase', 'trailing-newline', 'leading-space', 'short-sequence', 'short-year', 'twenty-digit',
         'fullwidth-year', 'fullwidth-sequence', 'arabic-indic-sequence', 'non-breaking-hyphen', 'semicolon', 'none',
         'int'])
def test_invalid_cve_ids(text):
    assert not is_cve_id(text)


# --- entries ------------------------------------------------------------------------------------------------

def test_entry_is_frozen_strict_and_forbids_extra_fields():
    entry = make_entry()
    with pytest.raises(ValidationError):
        entry.product = 'other'                                          # frozen
    with pytest.raises(ValidationError):
        KevEntry(**entry_fields(), entry_digest=entry.entry_digest, extra=1)
    with pytest.raises(ValidationError):
        KevEntry(**entry_fields(cwes=['CWE-787']), entry_digest=entry.entry_digest)   # strict: a list is not a tuple
    assert entry.contract == 'kev/1'


def test_entry_digest_is_derived_from_the_fields():
    fields = entry_fields()
    digest = entry_digest(fields)
    assert KevEntry(**fields, entry_digest=digest).entry_digest == digest
    with pytest.raises(ValidationError, match='entry_digest'):
        KevEntry(**fields, entry_digest=SHA_A)
    assert entry_digest(entry_fields(product='Other')) != digest
    assert entry_digest(entry_fields(cwes=())) != digest


def test_slim_entry_keeps_the_digest_of_the_full_entry_and_drops_the_long_texts():
    entry = make_entry(notes='a ; b')
    slim = entry.slim()
    assert isinstance(slim, KevEntrySlim) and slim.entry_digest == entry.entry_digest
    assert not hasattr(slim, 'short_description') and not hasattr(slim, 'required_action')
    assert slim.model_dump(exclude={'contract'}).keys() == {
        'cve_id', 'vendor_project', 'product', 'name', 'date_added', 'due_date', 'cwes', 'ransomware_use',
        'forensic_triage', 'entry_digest'}


@pytest.mark.parametrize('overrides', [
    {'cve_id': 'CVE-２０２４-38063'}, {'date_added': '2099-02-30'}, {'date_added': '2099-2-10'},
    {'due_date': '2099-02-09'}, {'due_date': '２０９９-02-13'}, {'cwes': ('CWE-1234567',)}, {'cwes': ('NVD-CWE-Other',)},
    {'cwes': tuple(f'CWE-{n}' for n in range(17))}, {'ransomware_use': 'Known'}, {'forensic_triage': 'maybe'},
    {'product': ' Windows'}, {'product': 'Wind\nows'}, {'name': 'Esc\x1b[31m'}, {'name': 'rtl‮evil'},
    {'name': 'x' * 257}, {'vendor_project': 'x' * 129}, {'short_description': 'x' * 4097}, {'notes': 'x' * 4097},
    {'required_action': 'x' * 2049}, {'name': 'lone\ud800surrogate'}],
    ids=['fullwidth-cve', 'impossible-date', 'unpadded-date', 'due-before-added', 'fullwidth-date', 'long-cwe',
         'nvd-token', 'seventeen-cwes', 'wrong-case-ransomware', 'unknown-triage-word', 'padded-product',
         'newline-in-product', 'ansi-in-name', 'bidi-in-name', 'name-cap', 'vendor-cap', 'description-cap',
         'notes-cap', 'action-cap', 'surrogate'])
def test_entry_rejects(overrides):
    fields = entry_fields(**overrides)
    with pytest.raises(ValidationError):
        KevEntry(**fields, entry_digest=SHA_A)


def test_entry_keeps_visible_unusual_text():
    text = 'café � <?php echo 1; ?> ‑   quote’s'
    assert make_entry(short_description=text).short_description == text


# --- clean_text ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize(('raw', 'expected'), [
    ('  padded  ', 'padded'), ('a\nb\tc\r\nd', 'a b c  d'), ('x\x1b[31mred', 'x[31mred'), ('a‮b​c', 'abc'),
    ('lone\ud800', 'lone'), ('bell\x07', 'bell'), ('nel\x85here', 'nel here'), ('line sep', 'line sep'),
    ('c1\x9bcsi', 'c1csi'), (None, ''), ('ok � ok', 'ok � ok')],
    ids=['strip', 'whitespace-controls', 'ansi', 'bidi-and-zero-width', 'surrogate', 'bell', 'next-line',
         'line-separator', 'c1-csi', 'none', 'replacement-char-kept'])
def test_clean_text(raw, expected):
    assert clean_text(raw, 100) == expected


def test_clean_text_caps_the_length_with_an_ellipsis():
    assert clean_text('x' * 50, 20) == 'x' * 17 + '...' and len(clean_text('x' * 50, 20)) == 20
    assert clean_text('x' * 20, 20) == 'x' * 20


# --- catalog meta -------------------------------------------------------------------------------------------

def meta_fields(catalog, **overrides) -> dict:
    value = catalog.meta.model_dump()
    value.pop('contract')
    value['consent'] = None
    value.update(overrides)
    return value


def test_meta_snapshot_identity_derives_from_the_raw_hash_and_parser_version(catalog):
    meta = catalog.meta
    assert meta.snapshot_id == domain_id('kev-snapshot', 1, {'raw_sha256': meta.raw_sha256, 'parser_version': 1})
    assert meta.license == 'CC0-1.0' and meta.parser_version == 1 and meta.contract == 'kev/1'
    with pytest.raises(ValidationError, match='snapshot_id'):
        KevCatalogMeta(**meta_fields(catalog, snapshot_id=SHA_A))


def test_meta_counts_must_add_up(catalog):
    with pytest.raises(ValidationError, match='count'):
        KevCatalogMeta(**meta_fields(catalog, count=catalog.meta.count + 1))
    skipped = KevCatalogMeta(**meta_fields(catalog, count=catalog.meta.count + 2, skipped_entries=2))
    assert skipped.skipped_entries == 2


@pytest.mark.parametrize('overrides', [
    {'authenticity': 'tls-allowlisted-host'}, {'source_url': 'https://www.cisa.gov/x'},
    {'file_name': '../evil.json'}, {'file_name': 'dir\\evil.json'}, {'file_name': ''}, {'unknown_fields': ('b', 'a')},
    {'unknown_fields': ('a', 'a')}, {'unknown_fields': tuple(f'f{n:02d}' for n in range(17))},
    {'warnings': tuple('w' for _ in range(21))}, {'warnings': ('w' * 201,)}, {'date_released': '2099-13-01T00:00:00Z'},
    {'date_released': '2099-03-01T18:00:00.5Z'}, {'retrieved_at': '2099-03-02'}, {'catalog_version': ''},
    {'catalog_version': 'v' * 33}, {'entry_count': 0, 'count': 0}, {'raw_size': 0}, {'license': 'MIT'},
    {'parser_version': 2}],
    ids=['local-with-tls', 'local-with-url', 'path-traversal', 'backslash', 'empty-name', 'unsorted-unknown',
         'duplicate-unknown', 'too-many-unknown', 'too-many-warnings', 'long-warning', 'impossible-release',
         'fractional-release', 'date-only-retrieved', 'empty-version', 'long-version', 'zero-entries', 'zero-size',
         'other-licence', 'future-parser'])
def test_meta_rejects(catalog, overrides):
    with pytest.raises(ValidationError):
        KevCatalogMeta(**meta_fields(catalog, **overrides))


def fetch_fields(catalog, source='cisa-github', **overrides) -> dict:
    plan = plan_for(source)
    consent = ConsentRecord(operation='fetch-kev-catalog', source=source, url=plan.url, plan_sha=plan.plan_sha,
                            granted_at=STAMP, surface='cli')
    value = meta_fields(catalog, source=source, authenticity='tls-allowlisted-host', source_url=plan.url,
                        final_url=plan.url, consent=consent, file_name=None)
    value.update(overrides)
    return value


@pytest.mark.parametrize('source', ['cisa-site', 'cisa-github'])
def test_a_fetched_snapshot_needs_consent_tls_and_the_matching_host(catalog, source):
    meta = KevCatalogMeta(**fetch_fields(catalog, source))
    assert meta.consent.source == source and meta.authenticity == 'tls-allowlisted-host'


@pytest.mark.parametrize('overrides', [
    {'consent': None}, {'authenticity': 'unverified-local-file'}, {'file_name': 'a.json'}, {'final_url': None},
    {'source_url': 'https://evil.example/x.json'}, {'final_url': 'https://evil.example/x.json'},
    {'source_url': 'http://raw.githubusercontent.com/x.json'},
    {'final_url': 'https://raw.githubusercontent.com:8443/x'}, {'final_url': 'https://user@raw.githubusercontent.com/x'},
    {'final_url': 'https://raw.githubusercontent.com/x?a=1'}],
    ids=['no-consent', 'fetched-but-unverified', 'fetched-with-file-name', 'no-final-url', 'foreign-source-host',
         'foreign-final-host', 'plain-http', 'explicit-port', 'userinfo', 'query'])
def test_a_fetched_snapshot_rejects(catalog, overrides):
    with pytest.raises(ValidationError):
        KevCatalogMeta(**fetch_fields(catalog, **overrides))


def test_consent_must_name_the_same_source_and_url(catalog):
    other = plan_for('cisa-site')
    wrong = ConsentRecord(operation='fetch-kev-catalog', source='cisa-site', url=other.url, plan_sha=other.plan_sha,
                          granted_at=STAMP, surface='gui')
    with pytest.raises(ValidationError, match='consent'):
        KevCatalogMeta(**fetch_fields(catalog, 'cisa-github', consent=wrong))


def test_a_local_import_carries_no_url_and_no_consent(catalog):
    assert catalog.meta.source == 'local-import' and catalog.meta.consent is None
    assert catalog.meta.authenticity == 'unverified-local-file' and catalog.meta.source_url is None


# --- lookups ------------------------------------------------------------------------------------------------

def lookup_fields(**overrides) -> dict:
    value = {'cve_id': 'CVE-2099-10001', 'status': 'not-listed', 'snapshot_id': SHA_A, 'freshness': 'fresh',
             'age_days': 1}
    value.update(overrides)
    return value


@pytest.mark.parametrize('fields', [
    lookup_fields(),
    lookup_fields(status='listed', entry=make_entry()),
    lookup_fields(status='unavailable', snapshot_id=None, freshness='unknown', age_days=None),
    lookup_fields(cve_id='CVE-２０２４-1', status='invalid-id', snapshot_id=None, freshness='unknown', age_days=None),
    lookup_fields(cve_id='', status='invalid-id', snapshot_id=None, freshness='unknown', age_days=None),
    lookup_fields(cve_id='CVE-2099-10001', status='invalid-id', snapshot_id=None, freshness='unknown',
                  age_days=None)],                       # the echo of ' CVE-2099-10001': padding is not a verdict
    ids=['not-listed', 'listed', 'unavailable', 'invalid-id', 'empty-invalid-id', 'cleaned-echo-looks-valid'])
def test_valid_lookups(fields):
    assert KevLookup(**fields).status == fields['status']


@pytest.mark.parametrize('overrides', [
    {'status': 'listed'}, {'status': 'listed', 'entry': make_entry(cve_id='CVE-2099-10004')},
    {'status': 'not-listed', 'entry': make_entry()}, {'snapshot_id': None},
    {'status': 'unavailable'}, {'status': 'invalid-id'}, {'cve_id': 'CVE-２０２４-1'},
    {'status': 'invalid-id', 'cve_id': 'bad\x1b[0m', 'snapshot_id': None, 'freshness': 'unknown', 'age_days': None},
    {'status': 'invalid-id', 'cve_id': ' padded', 'snapshot_id': None, 'freshness': 'unknown', 'age_days': None},
    {'freshness': 'unknown'}, {'age_days': None}, {'freshness': 'soon'}, {'cve_id': 'x' * 65, 'status': 'invalid-id',
                                                                       'snapshot_id': None, 'freshness': 'unknown',
                                                                       'age_days': None}],
    ids=['listed-without-entry', 'listed-other-cve', 'not-listed-with-entry', 'no-snapshot',
         'unavailable-with-snapshot', 'invalid-with-snapshot', 'valid-status-invalid-id', 'unsafe-echo', 'padded-echo',
         'unknown-freshness-with-catalog', 'no-age', 'bad-freshness', 'long-echo'])
def test_inconsistent_lookups_are_rejected(overrides):
    with pytest.raises(ValidationError):
        KevLookup(**lookup_fields(**overrides))


# --- project row --------------------------------------------------------------------------------------------

def context_fields(**overrides) -> dict:
    listed = KevLookup(**lookup_fields(status='listed', entry=make_entry().slim()))
    other = KevLookup(**lookup_fields(cve_id='CVE-2099-10002'))
    value = {'created_at': STAMP, 'snapshot_id': SHA_A, 'catalog_version': '2099.03.01',
             'date_released': '2099-03-01T18:00:00Z', 'content_digest': SHA_B, 'source': 'local-import',
             'lookups': (listed, other), 'kb': 'KB5000001', 'release_date': '2099-02-11', 'orientation_verified': True}
    value.update(overrides)
    value.setdefault('context_id', domain_id('kev-context', 1, {
        'snapshot_id': value['snapshot_id'], 'cves': sorted(item.cve_id for item in value['lookups']),
        'join_version': 1}))
    return value


def test_context_row_identity_covers_the_snapshot_and_the_cves_only():
    row = KevContext(**context_fields())
    assert row.join_version == 1 and row.contract == 'kev/1'
    same = KevContext(**context_fields(created_at='2099-04-01T00:00:00Z', kb=None, release_date=None,
                                       orientation_verified=False))
    assert same.context_id == row.context_id                         # wall-clock time and the KB are not identity
    moved = tuple(item.model_copy(update={'snapshot_id': SHA_B}) for item in row.lookups)
    assert KevContext(**context_fields(snapshot_id=SHA_B, lookups=moved)).context_id != row.context_id
    fewer = KevContext(**context_fields(lookups=row.lookups[:1]))
    assert fewer.context_id != row.context_id                        # the CVE set is identity


@pytest.mark.parametrize('overrides', [
    {'context_id': SHA_A}, {'kb': 'KB123'}, {'kb': 'kb5000001'}, {'release_date': '2099-2-11'},
    {'lookups': ()},
    {'lookups': (KevLookup(**lookup_fields(status='listed', entry=make_entry())),)},
    {'lookups': (KevLookup(**lookup_fields(cve_id='CVE-2099-10002')), KevLookup(**lookup_fields()))},
    {'lookups': (KevLookup(**lookup_fields()), KevLookup(**lookup_fields()))},
    {'lookups': (KevLookup(**lookup_fields(status='unavailable', snapshot_id=None, freshness='unknown',
                                           age_days=None)),)},
    {'lookups': (KevLookup(**lookup_fields(snapshot_id=SHA_B)),)}],
    ids=['wrong-id', 'short-kb', 'lowercase-kb', 'unpadded-date', 'no-lookups', 'full-entry', 'unsorted', 'duplicate',
         'unavailable-lookup', 'other-snapshot'])
def test_context_row_rejects(overrides):
    fields = context_fields(**overrides)
    if 'context_id' not in overrides:
        fields['context_id'] = domain_id('kev-context', 1, {
            'snapshot_id': fields['snapshot_id'], 'cves': sorted(item.cve_id for item in fields['lookups']),
            'join_version': 1})
    with pytest.raises(ValidationError):
        KevContext(**fields)


def test_context_row_holds_at_most_256_lookups():
    many = tuple(KevLookup(**lookup_fields(cve_id=f'CVE-2099-{n:05d}')) for n in range(257))
    with pytest.raises(ValidationError):
        KevContext(**context_fields(lookups=many))
    assert len(KevContext(**context_fields(lookups=many[:256])).lookups) == 256


# --- delta --------------------------------------------------------------------------------------------------

def tracked(**overrides) -> KevTracked:
    value = {'ransomware_use': 'unknown', 'due_date': '2099-02-13', 'forensic_triage': 'no', 'cwes': ('CWE-20',)}
    value.update(overrides)
    return KevTracked(**value)


def test_delta_counts_and_lists_agree():
    change = KevChange(cve_id='CVE-2099-10001', before=tracked(), after=tracked(ransomware_use='known'))
    delta = KevDelta(from_snapshot_id=SHA_A, to_snapshot_id=SHA_B, added=('CVE-2099-10002',), removed=(),
                     changed=(change,), added_count=1, removed_count=0, changed_count=1)
    assert delta.contract == 'kev/1'
    ids = tuple(f'CVE-2099-{n:05d}' for n in range(500))
    capped = KevDelta(from_snapshot_id=SHA_A, to_snapshot_id=SHA_B, added=ids, removed=(), changed=(),
                      added_count=900, removed_count=0, changed_count=0)
    assert capped.added_count == 900 and len(capped.added) == 500


@pytest.mark.parametrize('overrides', [
    {'added_count': 0}, {'added_count': 2}, {'added': ('CVE-2099-10002', 'CVE-2099-10002'), 'added_count': 2},
    {'added': tuple(f'CVE-2099-{n:05d}' for n in range(501)), 'added_count': 501},
    {'added': ('CVE-２０９９-1',), 'added_count': 1}, {'removed_count': -1}],
    ids=['count-below-list', 'count-above-short-list', 'duplicate-ids', 'over-the-cap', 'fullwidth-id', 'negative'])
def test_delta_rejects(overrides):
    value = {'from_snapshot_id': SHA_A, 'to_snapshot_id': SHA_B, 'added': ('CVE-2099-10002',), 'removed': (),
             'changed': (), 'added_count': 1, 'removed_count': 0, 'changed_count': 0}
    value.update(overrides)
    with pytest.raises(ValidationError):
        KevDelta(**value)


def test_a_change_must_change_something():
    with pytest.raises(ValidationError):
        KevChange(cve_id='CVE-2099-10001', before=tracked(), after=tracked())


# --- plan, pointer, errors ----------------------------------------------------------------------------------

def test_plan_is_fixed_per_source_and_does_not_hash_the_size_hint():
    site, mirror = plan_for('cisa-site'), plan_for('cisa-github')
    assert site.url == 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    assert mirror.url == 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'
    assert (site.host, mirror.host) == ('www.cisa.gov', 'raw.githubusercontent.com')
    assert SOURCE_URLS == {'cisa-site': site.url, 'cisa-github': mirror.url}
    assert SOURCE_HOSTS == {'cisa-site': 'www.cisa.gov', 'cisa-github': 'raw.githubusercontent.com'}
    assert site.method == 'GET' and site.headers == {'Accept': 'application/json', 'User-Agent': 'PatchTrace'}
    assert site.max_bytes == 16 * 1024 ** 2 and site.operation == 'fetch-kev-catalog'
    assert site.plan_sha != mirror.plan_sha
    assert plan_for('cisa-site', expected_bytes_hint=5).plan_sha == site.plan_sha


@pytest.mark.parametrize('overrides', [
    {'url': 'https://www.cisa.gov/other.json'}, {'host': 'raw.githubusercontent.com'}, {'method': 'POST'},
    {'headers': {'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'}},
    {'headers': {'Accept': 'application/json', 'User-Agent': 'PatchTrace', 'Cookie': 'x'}},
    {'max_bytes': 32 * 1024 ** 2}, {'plan_sha': SHA_A}, {'operation': 'fetch-nvd'}],
    ids=['other-url', 'other-host', 'post', 'browser-user-agent', 'extra-header', 'larger-cap', 'wrong-sha',
         'other-operation'])
def test_plan_rejects(overrides):
    with pytest.raises(ValidationError):
        KevPlan(**{**plan_for('cisa-site').model_dump(exclude={'contract'}), **overrides})


def test_unknown_source_has_no_plan():
    with pytest.raises(KevError) as caught:
        plan_for('somewhere-else')
    assert caught.value.code == 'PT-KEV-INPUT'


def test_current_pointer_is_a_strict_record():
    pointer = KevCurrent(snapshot_id=SHA_A, raw_sha256=SHA_B, date_released='2099-03-01T18:00:00Z', set_at=STAMP)
    assert pointer.contract == 'kev/1'
    with pytest.raises(ValidationError):
        KevCurrent(snapshot_id=SHA_A, raw_sha256='xyz', date_released='2099-03-01T18:00:00Z', set_at=STAMP)


def test_error_codes_and_exit_codes():
    assert set(CODES) == {f'PT-KEV-{name}' for name in (
        'INPUT', 'CONSENT', 'NETWORK', 'PROVIDER', 'LIMIT', 'FORMAT', 'VALIDATE', 'SHRINK', 'STORAGE', 'UNSUPPORTED',
        'NOTFOUND', 'CANCEL')}
    expected = {2: ('INPUT', 'CONSENT', 'UNSUPPORTED'),
                3: ('NETWORK', 'PROVIDER', 'LIMIT', 'FORMAT', 'VALIDATE', 'SHRINK', 'STORAGE'),
                4: ('NOTFOUND',), 5: ('CANCEL',)}
    for exit_code, names in expected.items():
        for name in names:
            assert EXIT_CODES[f'PT-KEV-{name}'] == exit_code
    error = KevError('PT-KEV-FORMAT', 'the file is not valid JSON')
    assert error.exit_code == 3 and error.recoverable is True and error.code == 'PT-KEV-FORMAT'
    assert str(error) == 'PT-KEV-FORMAT: the file is not valid JSON'
    assert KevError('PT-KEV-STORAGE', 'm', recoverable=False).recoverable is False
    with pytest.raises(ValueError, match='error code'):
        KevError('PT-KEV-MADE-UP', 'x')
