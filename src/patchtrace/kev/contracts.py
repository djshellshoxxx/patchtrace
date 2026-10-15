"""Strict, frozen ``kev/1`` records, ``KevError`` and the in-memory ``KevCatalog`` (KEV-integration-plan section 7).

Pure: no Qt, network, sqlite3, clock or ranking code. KEV is context about one CVE. Nothing here carries a score, a rank
or a statement about a function: only what CISA's catalog says, how old the snapshot is and where its bytes came from.
Records forbid extra fields and coerce nothing; collections are tuples in a canonical order, so a dump is deterministic.
Text that came from the catalog is stored as single-line plain text: the parser removes unsafe characters at the
boundary and these records reject them, so no consumer can receive terminal escapes or bidirectional controls.
CVE IDs are ASCII only (``[0-9]``, never ``\\d``): the sibling CVE patterns accept other digit systems (plan F18).
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from ..enrichment.identity import domain_id
from . import limits

CONTRACT = 'kev/1'

# --- errors -------------------------------------------------------------------------------------------------
CODES = ('PT-KEV-INPUT', 'PT-KEV-CONSENT', 'PT-KEV-NETWORK', 'PT-KEV-PROVIDER', 'PT-KEV-LIMIT', 'PT-KEV-FORMAT',
         'PT-KEV-VALIDATE', 'PT-KEV-SHRINK', 'PT-KEV-STORAGE', 'PT-KEV-UNSUPPORTED', 'PT-KEV-NOTFOUND',
         'PT-KEV-CANCEL')
# enrichment-cli/1 exit codes: 2 invalid use, 3 runtime failure, 4 nothing to report (no catalog), 5 cancelled
EXIT_CODES = {'PT-KEV-INPUT': 2, 'PT-KEV-CONSENT': 2, 'PT-KEV-UNSUPPORTED': 2, 'PT-KEV-NETWORK': 3,
              'PT-KEV-PROVIDER': 3, 'PT-KEV-LIMIT': 3, 'PT-KEV-FORMAT': 3, 'PT-KEV-VALIDATE': 3, 'PT-KEV-SHRINK': 3,
              'PT-KEV-STORAGE': 3, 'PT-KEV-NOTFOUND': 4, 'PT-KEV-CANCEL': 5}


class KevError(Exception):
    """Typed failure. ``message`` is a fixed template with labels and numbers; untrusted text is never put into it."""

    def __init__(self, code: str, message: str, *, recoverable: bool = True):
        if code not in EXIT_CODES:
            raise ValueError(f'unknown kev error code {code!r}')
        self.code = code
        self.message = str(message)[:400]
        self.recoverable = recoverable
        super().__init__(f'{code}: {self.message}')

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]


# --- text hygiene -------------------------------------------------------------------------------------------
# C0 and C1 controls, soft hyphen, bidirectional and zero-width characters, line and paragraph separators, BOM, tag
# characters and lone surrogates: invisible, reordering or line-breaking in a UI. Built from code points so that this
# file holds no invisible character itself.
_UNSAFE_RANGES = ((0x00, 0x1F), (0x7F, 0x9F), (0xAD, 0xAD), (0x61C, 0x61C), (0x180E, 0x180E), (0x200B, 0x200F),
                  (0x2028, 0x202E), (0x2060, 0x206F), (0xD800, 0xDFFF), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB),
                  (0xE0000, 0xE007F))
_UNSAFE = re.compile('[' + ''.join(f'\\U{low:08x}-\\U{high:08x}' for low, high in _UNSAFE_RANGES) + ']')
_SEPARATORS = re.compile('[\\t\\n\\r\\x0b\\x0c\\x1c-\\x1f\\x85\\u2028\\u2029]')   # become a space, not nothing


def clean_text(value: object, limit: int | None) -> str:
    """Untrusted text as one plain line: separators become spaces, other unsafe characters go, ends are stripped and
    a longer text is cut to ``limit`` characters with an ellipsis (``None``: no cut)."""
    text = '' if value is None else str(value)
    if not (text.isascii() and text.isprintable()):
        text = _UNSAFE.sub('', _SEPARATORS.sub(' ', text))
    text = text.strip()
    return text if limit is None or len(text) <= limit else text[:max(0, limit - 3)] + '...'


def _plain_line(value: str) -> str:
    if value != value.strip() or _UNSAFE.search(value):
        raise ValueError('text must be one line of plain text without surrounding space or control characters')
    return value


def _real_date(value: str) -> str:
    try:
        date.fromisoformat(value)
    except ValueError:
        raise ValueError('date must be a real calendar date YYYY-MM-DD') from None
    return value


def utc(value: str) -> datetime:
    """``YYYY-MM-DDTHH:MM:SSZ`` as an aware UTC datetime (ValueError when it is not a real instant)."""
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC)


def _real_timestamp(value: str) -> str:
    try:
        utc(value)
    except ValueError:
        raise ValueError('timestamp must be a real UTC instant YYYY-MM-DDTHH:MM:SSZ') from None
    return value


_HTTPS = re.compile(r'https://([a-z0-9.-]{1,253})(/[A-Za-z0-9._~%/-]{0,400})?')   # no userinfo, port, query or fragment
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')


def is_cve_id(text: object) -> bool:
    """True only for an exact ASCII ``CVE-YYYY-NNNN`` (four to nineteen digits after the year); never strips."""
    return type(text) is str and _CVE.fullmatch(text) is not None


def https_host(url: str) -> str | None:
    match = _HTTPS.fullmatch(url)
    return match.group(1) if match else None


def _https_url(value: str) -> str:
    if https_host(value) is None:
        raise ValueError('URL must be https with a lower-case host and no userinfo, port, query or fragment')
    return value


def _base_name(value: str) -> str:
    if value in {'.', '..'} or '/' in value or '\\' in value or _UNSAFE.search(value):
        raise ValueError('file name must be a base name without path separators or control characters')
    return value


def _line(max_length: int, min_length: int = 0):
    return Annotated[str, Field(min_length=min_length, max_length=max_length), AfterValidator(_plain_line)]


CveId = Annotated[str, Field(pattern=r'^CVE-[0-9]{4}-[0-9]{4,19}$')]
CweId = Annotated[str, Field(pattern=r'^CWE-[0-9]{1,6}$')]
KbId = Annotated[str, Field(pattern=r'^KB[0-9]{4,10}$')]
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
IsoDate = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$'), AfterValidator(_real_date)]
Timestamp = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'),
                      AfterValidator(_real_timestamp)]
VERSION_PATTERN = rf'[!-~](?:[ -~]{{0,{limits.MAX_VERSION_CHARS - 2}}}[!-~])?'      # printable ASCII, no padding
Version = Annotated[str, Field(pattern=f'^{VERSION_PATTERN}$')]
HttpsUrl = Annotated[str, Field(max_length=512), AfterValidator(_https_url)]
BaseName = Annotated[str, Field(min_length=1, max_length=255), AfterValidator(_base_name)]
FieldName = _line(limits.MAX_UNKNOWN_NAME_CHARS, 1)
WarningText = _line(limits.MAX_WARNING_CHARS)
Note = _line(200)

Source = Literal['cisa-site', 'cisa-github', 'local-import']
FetchSource = Literal['cisa-site', 'cisa-github']
Authenticity = Literal['tls-allowlisted-host', 'unverified-local-file']
Surface = Literal['cli', 'gui']
RansomwareUse = Literal['known', 'unknown', 'absent', 'unrecognized']
ForensicTriage = Literal['yes', 'no', 'absent', 'unrecognized']
LookupStatus = Literal['listed', 'not-listed', 'unavailable', 'invalid-id']
Freshness = Literal['fresh', 'aging', 'stale', 'future', 'unknown']

# The two fixed download sources (plan 7, Transport). The first is the canonical feed, still to be proven by the live
# probe (K6); the second is CISA's own GitHub mirror. Nothing else is ever requested.
SOURCE_URLS = {'cisa-site': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
               'cisa-github': 'https://raw.githubusercontent.com/cisagov/kev-data/main/'
                              'known_exploited_vulnerabilities.json'}
SOURCE_HOSTS = {'cisa-site': 'www.cisa.gov', 'cisa-github': 'raw.githubusercontent.com'}
PLAN_HEADERS = {'Accept': 'application/json', 'User-Agent': 'PatchTrace'}
FETCH_OPERATION = 'fetch-kev-catalog'
DIGEST_FIELDS = ('cve_id', 'vendor_project', 'product', 'name', 'date_added', 'due_date', 'short_description',
                 'required_action', 'notes', 'cwes', 'ransomware_use', 'forensic_triage')


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Contract(Record):
    contract: Literal['kev/1'] = CONTRACT


# --- entries ------------------------------------------------------------------------------------------------

def entry_digest(fields: Mapping) -> str:
    """Identity of one entry's normalized content (the twelve fields in ``DIGEST_FIELDS``), nothing around it."""
    payload = {name: fields[name] for name in DIGEST_FIELDS}
    payload['cwes'] = list(payload['cwes'])
    return domain_id('kev-entry', 1, payload)


class _EntryCore(Contract):
    cve_id: CveId
    vendor_project: _line(limits.MAX_VENDOR_CHARS)
    product: _line(limits.MAX_PRODUCT_CHARS)
    name: _line(limits.MAX_NAME_CHARS)
    date_added: IsoDate
    due_date: IsoDate
    cwes: Annotated[tuple[CweId, ...], Field(max_length=limits.MAX_CWES)] = ()
    ransomware_use: RansomwareUse
    forensic_triage: ForensicTriage

    @model_validator(mode='after')
    def _dates(self):
        if self.due_date < self.date_added:          # fixed-width ISO dates order like strings
            raise ValueError('due_date is before date_added')
        return self


class KevEntrySlim(_EntryCore):
    """An entry without its three long texts: what a project row keeps. ``entry_digest`` is the full entry's."""
    entry_digest: Sha256


class KevEntry(_EntryCore):
    """One catalog entry in CISA's own words (cleaned to one line each), with the identity of its content."""
    short_description: _line(limits.MAX_DESCRIPTION_CHARS)
    required_action: _line(limits.MAX_ACTION_CHARS)
    notes: _line(limits.MAX_NOTES_CHARS) = ''
    entry_digest: Sha256

    @model_validator(mode='after')
    def _digest(self):
        if self.entry_digest != entry_digest({name: getattr(self, name) for name in DIGEST_FIELDS}):
            raise ValueError('entry_digest does not derive from the entry fields')
        return self

    def slim(self) -> KevEntrySlim:
        return KevEntrySlim(**{name: getattr(self, name) for name in KevEntrySlim.model_fields if name != 'contract'})


# --- catalog meta -------------------------------------------------------------------------------------------

class ConsentRecord(Record):
    """The one consent behind one fetch: nothing is remembered for later requests."""
    operation: Literal['fetch-kev-catalog']
    source: FetchSource
    url: HttpsUrl
    plan_sha: Sha256
    granted_at: Timestamp
    surface: Surface


class KevCatalogMeta(Contract):
    snapshot_id: Sha256
    raw_sha256: Sha256
    raw_size: Annotated[int, Field(ge=1, le=limits.MAX_CATALOG_BYTES)]
    content_digest: Sha256
    catalog_version: Version
    date_released: Timestamp
    count: Annotated[int, Field(ge=1, le=limits.MAX_ENTRIES)]
    entry_count: Annotated[int, Field(ge=1, le=limits.MAX_ENTRIES)]
    skipped_entries: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)] = 0
    source: Source
    source_url: HttpsUrl | None = None
    final_url: HttpsUrl | None = None
    retrieved_at: Timestamp
    authenticity: Authenticity
    parser_version: Literal[1] = limits.PARSER_VERSION
    unknown_fields: Annotated[tuple[FieldName, ...], Field(max_length=limits.MAX_UNKNOWN_FIELDS)] = ()
    warnings: Annotated[tuple[WarningText, ...], Field(max_length=limits.MAX_WARNINGS)] = ()
    license: Literal['CC0-1.0'] = 'CC0-1.0'
    consent: ConsentRecord | None = None
    file_name: BaseName | None = None

    @model_validator(mode='after')
    def _consistent(self):
        if self.snapshot_id != domain_id('kev-snapshot', 1, {'raw_sha256': self.raw_sha256,
                                                             'parser_version': self.parser_version}):
            raise ValueError('snapshot_id does not derive from raw_sha256 and parser_version')
        if self.count != self.entry_count + self.skipped_entries:
            raise ValueError('count must equal entry_count plus skipped_entries')
        if list(self.unknown_fields) != sorted(set(self.unknown_fields)):
            raise ValueError('unknown_fields must be sorted and unique')
        if self.source == 'local-import':
            if (self.authenticity != 'unverified-local-file' or self.source_url or self.final_url or self.consent):
                raise ValueError('a local import is unverified-local-file and carries no URL and no consent')
            return self
        if self.authenticity != 'tls-allowlisted-host' or self.file_name is not None:
            raise ValueError('a fetched catalog is tls-allowlisted-host and carries no local file name')
        if self.source_url is None or self.final_url is None or self.consent is None:
            raise ValueError('a fetched catalog needs source_url, final_url and the consent that allowed it')
        host = SOURCE_HOSTS[self.source]
        if https_host(self.source_url) != host or https_host(self.final_url) != host:
            raise ValueError(f'a {self.source} catalog must come from {host} only')
        if self.consent.source != self.source or self.consent.url != self.source_url:
            raise ValueError('consent must name the same source and URL')
        return self


# --- lookups and project rows -------------------------------------------------------------------------------

class KevLookup(Contract):
    """What one catalog says about one CVE ID. ``not-listed`` is never evidence of safety; ``unavailable`` and
    ``invalid-id`` say nothing about the CVE at all."""
    cve_id: Annotated[str, Field(max_length=limits.MAX_ECHO_CHARS)]
    status: LookupStatus
    entry: KevEntry | KevEntrySlim | None = None
    snapshot_id: Sha256 | None = None
    freshness: Freshness = 'unknown'
    age_days: int | None = None
    notes: Annotated[tuple[Note, ...], Field(max_length=8)] = ()

    @model_validator(mode='after')
    def _consistent(self):
        if self.status == 'invalid-id':             # the echo of what was typed: safe to show, never a verdict
            if _UNSAFE.search(self.cve_id) or self.cve_id != self.cve_id.strip():
                raise ValueError('an invalid-id lookup carries the typed text cleaned to one plain line')
        elif not is_cve_id(self.cve_id):
            raise ValueError('cve_id must be an ASCII CVE ID')
        answered = self.status in ('listed', 'not-listed')
        if answered != (self.snapshot_id is not None):
            raise ValueError('only a lookup answered by a catalog names its snapshot')
        if answered != (self.freshness != 'unknown') or answered != (self.age_days is not None):
            raise ValueError('freshness and age_days belong to a lookup answered by a catalog')
        if (self.status == 'listed') != (self.entry is not None):
            raise ValueError('a listed lookup carries its entry and no other lookup does')
        if self.entry is not None and self.entry.cve_id != self.cve_id:
            raise ValueError('the entry belongs to another CVE')
        return self


class KevContext(Contract):
    """Project row ``kev-context``: the KEV answers recorded for a set of CVEs, bound to one snapshot."""
    context_id: Sha256
    created_at: Timestamp
    snapshot_id: Sha256
    catalog_version: Version
    date_released: Timestamp
    content_digest: Sha256
    source: Source
    lookups: Annotated[tuple[KevLookup, ...], Field(min_length=1, max_length=limits.MAX_CONTEXT_CVES)]
    kb: KbId | None = None
    release_date: IsoDate | None = None
    orientation_verified: bool = False
    join_version: Literal[1] = limits.JOIN_VERSION

    @model_validator(mode='after')
    def _consistent(self):
        cves = [item.cve_id for item in self.lookups]
        if cves != sorted(set(cves)):
            raise ValueError('lookups must be sorted by CVE ID and unique')
        if self.context_id != domain_id('kev-context', 1, {'snapshot_id': self.snapshot_id, 'cves': cves,
                                                           'join_version': self.join_version}):
            raise ValueError('context_id does not derive from snapshot_id, the CVE IDs and join_version')
        for item in self.lookups:
            if item.status not in ('listed', 'not-listed') or item.snapshot_id != self.snapshot_id:
                raise ValueError('every lookup of a row must be answered by the row snapshot')
            if isinstance(item.entry, KevEntry):
                raise ValueError('a row keeps slim entries')
        return self


# --- snapshot delta -----------------------------------------------------------------------------------------

class KevTracked(Record):
    """The entry fields whose change matters to a reader of the delta."""
    ransomware_use: RansomwareUse
    due_date: IsoDate
    forensic_triage: ForensicTriage
    cwes: Annotated[tuple[CweId, ...], Field(max_length=limits.MAX_CWES)]


class KevChange(Record):
    cve_id: CveId
    before: KevTracked
    after: KevTracked

    @model_validator(mode='after')
    def _differs(self):
        if self.before == self.after:
            raise ValueError('a change must change a tracked field')
        return self


def _capped(ids, count: int, name: str) -> None:
    if count < len(ids) or (count > len(ids) and len(ids) != limits.MAX_DELTA_IDS):
        raise ValueError(f'{name} must equal the list length unless the list was cut at {limits.MAX_DELTA_IDS}')


class KevDelta(Contract):
    """Difference between two stored catalogs. Lists are cut at ``MAX_DELTA_IDS``; the counts are always the truth."""
    from_snapshot_id: Sha256
    to_snapshot_id: Sha256
    added: Annotated[tuple[CveId, ...], Field(max_length=limits.MAX_DELTA_IDS)]
    removed: Annotated[tuple[CveId, ...], Field(max_length=limits.MAX_DELTA_IDS)]
    changed: Annotated[tuple[KevChange, ...], Field(max_length=limits.MAX_DELTA_IDS)]
    added_count: Annotated[int, Field(ge=0)]
    removed_count: Annotated[int, Field(ge=0)]
    changed_count: Annotated[int, Field(ge=0)]

    @model_validator(mode='after')
    def _consistent(self):
        if len(set(self.added)) != len(self.added) or len(set(self.removed)) != len(self.removed):
            raise ValueError('a CVE ID is listed once per list')
        if len({item.cve_id for item in self.changed}) != len(self.changed):
            raise ValueError('a CVE ID is changed once')
        _capped(self.added, self.added_count, 'added_count')
        _capped(self.removed, self.removed_count, 'removed_count')
        _capped(self.changed, self.changed_count, 'changed_count')
        return self


# --- download plan and store pointer ------------------------------------------------------------------------

def _plan_sha(source: str, url: str, host: str, headers: Mapping[str, str], max_bytes: int) -> str:
    return domain_id('kev-plan', 1, {'operation': FETCH_OPERATION, 'source': source, 'url': url, 'host': host,
                                     'method': 'GET', 'headers': dict(headers), 'max_bytes': max_bytes})


class KevPlan(Contract):
    """The exact request a person is asked to allow. ``expected_bytes_hint`` is display only and not hashed."""
    operation: Literal['fetch-kev-catalog']
    source: FetchSource
    url: HttpsUrl
    host: str
    method: Literal['GET']
    headers: dict[str, str]
    max_bytes: int
    expected_bytes_hint: Annotated[int, Field(ge=0)] | None = None
    plan_sha: Sha256

    @model_validator(mode='after')
    def _fixed(self):
        if self.url != SOURCE_URLS[self.source] or self.host != SOURCE_HOSTS[self.source]:
            raise ValueError('a plan names the one fixed URL and host of its source')
        if self.headers != PLAN_HEADERS or self.max_bytes != limits.MAX_CATALOG_BYTES:
            raise ValueError('a plan sends the two fixed headers and caps the body at the catalog limit')
        if self.plan_sha != _plan_sha(self.source, self.url, self.host, self.headers, self.max_bytes):
            raise ValueError('plan_sha does not derive from the request')
        return self


def plan_for(source: str, *, expected_bytes_hint: int | None = limits.EXPECTED_DOWNLOAD_BYTES) -> KevPlan:
    if source not in SOURCE_URLS:
        raise KevError('PT-KEV-INPUT', 'the download source must be cisa-site or cisa-github')
    url, host = SOURCE_URLS[source], SOURCE_HOSTS[source]
    return KevPlan(operation=FETCH_OPERATION, source=source, url=url, host=host, method='GET',
                   headers=dict(PLAN_HEADERS), max_bytes=limits.MAX_CATALOG_BYTES,
                   expected_bytes_hint=expected_bytes_hint,
                   plan_sha=_plan_sha(source, url, host, PLAN_HEADERS, limits.MAX_CATALOG_BYTES))


class KevCurrent(Contract):
    """``current.json`` of the store: which snapshot is in use and since when."""
    snapshot_id: Sha256
    raw_sha256: Sha256
    date_released: Timestamp
    set_at: Timestamp


# --- the loaded catalog -------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, eq=False)
class KevCatalog:
    """A parsed catalog: its meta and its entries sorted by CVE ID, with an index by CVE ID. Not persisted."""
    meta: KevCatalogMeta
    entries: tuple[KevEntry, ...]
    by_cve: dict[str, KevEntry] = field(init=False, repr=False)
    released: datetime = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self.entries) != self.meta.entry_count:
            raise ValueError('entries do not match meta.entry_count')
        object.__setattr__(self, 'by_cve', {item.cve_id: item for item in self.entries})
        object.__setattr__(self, 'released', utc(self.meta.date_released))
