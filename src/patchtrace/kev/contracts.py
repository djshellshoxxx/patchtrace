"""Strict, frozen ``kev/1`` records and the ``PT-KEV-*`` error type (KEV-integration-plan section 7).

Pure: no Qt, network, urllib or sqlite3. Records forbid extra fields and coerce nothing; collections are tuples in a
canonical order so a dump is deterministic. Records loaded from storage must be parsed with ``model_validate_json``.
The upstream catalog is read by the tolerant mapper in ``parse``; only its normalised result is a stored contract.
"""
from __future__ import annotations

import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from ..enrichment.identity import domain_id
from . import limits

ERROR_CODES = ('PT-KEV-INPUT', 'PT-KEV-CONSENT', 'PT-KEV-NETWORK', 'PT-KEV-PROVIDER', 'PT-KEV-LIMIT', 'PT-KEV-FORMAT',
               'PT-KEV-VALIDATE', 'PT-KEV-SHRINK', 'PT-KEV-STORAGE', 'PT-KEV-UNSUPPORTED', 'PT-KEV-NOTFOUND',
               'PT-KEV-CANCEL')
# enrichment-cli/1 exit codes: 2 invalid use, 3 runtime failure, 4 nothing to report (no catalog), 5 cancelled.
EXIT_CODES = {'PT-KEV-INPUT': 2, 'PT-KEV-CONSENT': 2, 'PT-KEV-UNSUPPORTED': 2, 'PT-KEV-NETWORK': 3,
              'PT-KEV-PROVIDER': 3, 'PT-KEV-LIMIT': 3, 'PT-KEV-FORMAT': 3, 'PT-KEV-VALIDATE': 3, 'PT-KEV-SHRINK': 3,
              'PT-KEV-STORAGE': 3, 'PT-KEV-NOTFOUND': 4, 'PT-KEV-CANCEL': 5}


class KevError(Exception):
    """A redacted, recoverable-or-not failure. ``message`` is a fixed template: untrusted text never enters it."""

    def __init__(self, code: str, message: str, recoverable: bool = True) -> None:
        if code not in EXIT_CODES:
            raise ValueError(f'unknown KEV error code {code}')
        super().__init__(f'{code}: {message}')
        self.code, self.message, self.recoverable = code, message, recoverable

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]


def _encodable(value: str) -> str:
    try:
        value.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError('text holds a lone surrogate') from exc
    return value


def _calendar_date(value: str) -> str:
    try:
        datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError('not a calendar date') from exc
    return value


Text = Annotated[str, AfterValidator(_encodable)]
CveId = Annotated[str, Field(max_length=24, pattern=r'^CVE-[0-9]{4}-[0-9]{4,19}$')]
CweId = Annotated[str, Field(pattern=r'^CWE-[0-9]{1,6}$')]
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
IsoDate = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$'), AfterValidator(_calendar_date)]
Timestamp = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')]
Stripped = Annotated[str, StringConstraints(strip_whitespace=True), AfterValidator(_encodable)]
Name = Annotated[str, Field(max_length=64)]

Source = Literal['cisa-site', 'cisa-github', 'local-import']
FetchSource = Literal['cisa-site', 'cisa-github']
Authenticity = Literal['tls-allowlisted-host', 'unverified-local-file']
RansomwareUse = Literal['known', 'unknown', 'absent', 'unrecognized']
ForensicTriage = Literal['yes', 'no', 'absent', 'unrecognized']
LookupStatus = Literal['listed', 'not-listed', 'unavailable', 'invalid-id']
Freshness = Literal['fresh', 'aging', 'stale', 'future', 'unknown']


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Contract(Record):
    contract: Literal['kev/1'] = limits.CONTRACT


class KevEntrySlim(Contract):
    """An entry without the three long texts: what project rows keep."""

    cve_id: CveId
    vendor_project: Annotated[Stripped, Field(max_length=128)]
    product: Annotated[Stripped, Field(max_length=256)]
    name: Annotated[Text, Field(max_length=256)]
    date_added: IsoDate
    due_date: IsoDate
    cwes: Annotated[tuple[CweId, ...], Field(max_length=limits.MAX_CWES)]
    ransomware_use: RansomwareUse
    forensic_triage: ForensicTriage
    entry_digest: Sha256

    @model_validator(mode='after')
    def _due_not_before_added(self):
        if self.due_date < self.date_added:
            raise ValueError('due date precedes the date added')
        return self


class KevEntry(KevEntrySlim):
    short_description: Annotated[Text, Field(max_length=4096)]
    required_action: Annotated[Text, Field(max_length=2048)]
    notes: Annotated[Text, Field(max_length=4096)]

    def slim(self) -> KevEntrySlim:
        return KevEntrySlim(**self.model_dump(exclude={'short_description', 'required_action', 'notes'}))


class ConsentRecord(Contract):
    operation: Literal['fetch-kev-catalog']
    source: FetchSource
    url: Annotated[str, Field(max_length=2048)]
    plan_sha: Sha256
    granted_at: Timestamp
    surface: Literal['cli', 'gui']


class KevCatalogMeta(Contract):
    snapshot_id: Sha256
    raw_sha256: Sha256
    raw_size: Annotated[int, Field(ge=1, le=limits.MAX_BYTES)]
    content_digest: Sha256
    catalog_version: Annotated[Text, Field(min_length=1, max_length=32)]
    date_released: Timestamp
    count: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)]
    entry_count: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)]
    skipped_entries: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)]
    source: Source
    source_url: Annotated[str, Field(max_length=2048)] | None = None
    final_url: Annotated[str, Field(max_length=2048)] | None = None
    retrieved_at: Timestamp
    authenticity: Authenticity
    parser_version: Literal[1] = limits.PARSER_VERSION
    unknown_fields: Annotated[tuple[Annotated[Text, Field(max_length=64)], ...],
                              Field(max_length=limits.MAX_UNKNOWN_FIELDS)] = ()
    warnings: Annotated[tuple[Annotated[Text, Field(max_length=limits.MAX_WARNING_CHARS)], ...],
                        Field(max_length=limits.MAX_WARNINGS)] = ()
    license: Literal['CC0-1.0'] = limits.LICENSE
    consent: ConsentRecord | None = None
    file_name: Annotated[Text, Field(max_length=255, pattern=r'^[^/\\]*$')] | None = None

    @model_validator(mode='after')
    def _counts_add_up(self):
        if self.entry_count + self.skipped_entries != self.count:
            raise ValueError('entry_count plus skipped_entries must equal count')
        return self


class KevCatalog(Contract):
    """One parsed snapshot: metadata plus entries sorted by CVE ID."""

    meta: KevCatalogMeta
    entries: tuple[KevEntry, ...]

    @model_validator(mode='after')
    def _entries_match_meta(self):
        ids = [entry.cve_id for entry in self.entries]
        if len(ids) != self.meta.entry_count:
            raise ValueError('entry count differs from metadata')
        if ids != sorted(set(ids)):
            raise ValueError('entries must be unique and sorted by CVE ID')
        return self


class _LookupBase(Contract):
    cve_id: Annotated[Text, Field(min_length=1, max_length=64)]
    status: LookupStatus
    snapshot_id: Sha256 | None = None
    freshness: Freshness
    age_days: Annotated[int, Field(ge=0, le=100_000)] | None = None
    notes: Annotated[tuple[Annotated[Text, Field(max_length=200)], ...], Field(max_length=8)] = ()


class KevLookup(_LookupBase):
    entry: KevEntry | None = None

    @model_validator(mode='after')
    def _entry_iff_listed(self):
        if (self.entry is not None) != (self.status == 'listed'):
            raise ValueError('an entry is present exactly when the CVE is listed')
        return self


class KevContextLookup(_LookupBase):
    entry: KevEntrySlim | None = None

    @model_validator(mode='after')
    def _entry_iff_listed(self):
        if (self.entry is not None) != (self.status == 'listed'):
            raise ValueError('an entry is present exactly when the CVE is listed')
        return self


def context_id(snapshot_id: str, cves: tuple[str, ...] | list[str]) -> str:
    return domain_id('kev-context', 1, {'snapshot_id': snapshot_id, 'cves': sorted(cves),
                                        'join_version': limits.JOIN_VERSION})


class KevContext(Contract):
    """The project-attached ``kev-context`` row. Wall-clock time is never an input to its identity."""

    context_id: Sha256
    created_at: Timestamp
    snapshot_id: Sha256
    catalog_version: Annotated[Text, Field(min_length=1, max_length=32)]
    date_released: Timestamp
    content_digest: Sha256
    source: Source
    lookups: Annotated[tuple[KevContextLookup, ...], Field(max_length=limits.MAX_PROJECT_CVES)]
    kb: Annotated[str, Field(pattern=r'^KB[0-9]{6,8}$')] | None = None
    release_date: IsoDate | None = None
    orientation_verified: bool = False
    join_version: Literal[1] = limits.JOIN_VERSION

    @model_validator(mode='after')
    def _identity_matches(self):
        if self.context_id != context_id(self.snapshot_id, [lookup.cve_id for lookup in self.lookups]):
            raise ValueError('context_id does not match snapshot and CVEs')
        return self


class KevFacts(Record):
    """The entry fields whose change between snapshots is reported."""

    ransomware_use: RansomwareUse
    due_date: IsoDate
    forensic_triage: ForensicTriage
    cwes: Annotated[tuple[CweId, ...], Field(max_length=limits.MAX_CWES)]


class KevChange(Record):
    cve_id: CveId
    before: KevFacts
    after: KevFacts


class KevDelta(Contract):
    from_snapshot_id: Sha256
    to_snapshot_id: Sha256
    from_catalog_version: Annotated[Text, Field(min_length=1, max_length=32)]
    to_catalog_version: Annotated[Text, Field(min_length=1, max_length=32)]
    added: Annotated[tuple[CveId, ...], Field(max_length=limits.MAX_DELTA_IDS)]
    removed: Annotated[tuple[CveId, ...], Field(max_length=limits.MAX_DELTA_IDS)]
    changed: Annotated[tuple[KevChange, ...], Field(max_length=limits.MAX_DELTA_IDS)]
    added_count: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)]
    removed_count: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)]
    changed_count: Annotated[int, Field(ge=0, le=limits.MAX_ENTRIES)]


class KevHeaders(Record):
    accept: Literal['application/json'] = 'application/json'
    user_agent: Literal['PatchTrace'] = 'PatchTrace'


class KevPlan(Contract):
    """The exact request shown before consent. Building it does no network and no DNS."""

    operation: Literal['fetch-kev-catalog'] = 'fetch-kev-catalog'
    source: FetchSource
    url: Annotated[str, Field(max_length=2048)]
    host: Annotated[str, Field(max_length=253)]
    method: Literal['GET'] = 'GET'
    headers: KevHeaders = KevHeaders()
    max_bytes: Literal[16777216] = limits.MAX_BYTES
    expected_bytes_hint: Annotated[int, Field(ge=0)] = limits.EXPECTED_BYTES_HINT
    plan_sha: Sha256

    @classmethod
    def for_source(cls, source: str) -> KevPlan:
        if source not in limits.SOURCE_URLS:
            raise KevError('PT-KEV-INPUT', 'unknown download source')
        url = limits.SOURCE_URLS[source]
        host = url.split('/')[2]
        return cls(source=source, url=url, host=host, plan_sha=_plan_sha(source, url))

    @model_validator(mode='after')
    def _fixed_request(self):
        url = limits.SOURCE_URLS[self.source]
        if (self.url, self.host, self.plan_sha) != (url, url.split('/')[2], _plan_sha(self.source, url)):
            raise ValueError('plan differs from the fixed request for its source')
        return self


def _plan_sha(source: str, url: str) -> str:
    return domain_id('kev-plan', 1, {'operation': 'fetch-kev-catalog', 'source': source, 'url': url, 'method': 'GET',
                                     'accept': 'application/json', 'user_agent': 'PatchTrace',
                                     'max_bytes': limits.MAX_BYTES})
