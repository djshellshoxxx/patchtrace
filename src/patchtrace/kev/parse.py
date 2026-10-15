"""CISA KEV JSON catalog bytes to strict ``kev/1`` records (KEV-integration-plan sections 6 and 7). Pure and offline.

The input is untrusted. The JSON is read strictly (no duplicate keys, NaN or Infinity; size and entry caps) and then
mapped by hand: a field this parser does not know is listed by name and ignored, but anything that violates CISA's own
schema (a missing required field, a wrong type, a bad CVE ID or date, a count that does not match, a repeated CVE ID)
fails the whole file with ``KevError``, because an entry dropped quietly would later read as "Not listed". For that
reason ``skipped_entries`` stays 0 here. Text is cleaned to one plain line at this boundary and capped; the raw bytes
stay the source of truth (the store keeps them). Identities depend on the bytes and the parser version only, never on
the clock, so ``retrieved_at`` is a caller-supplied label.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime

from pydantic import ValidationError

from ..enrichment.identity import domain_id
from . import limits
from .contracts import (
    VERSION_PATTERN,
    ConsentRecord,
    KevCatalog,
    KevCatalogMeta,
    KevEntry,
    KevError,
    clean_text,
    entry_digest,
)

FORMAT, VALIDATE = 'PT-KEV-FORMAT', 'PT-KEV-VALIDATE'
TOP_REQUIRED = ('catalogVersion', 'dateReleased', 'count', 'vulnerabilities')
TOP_KNOWN = frozenset((*TOP_REQUIRED, 'title'))              # the real catalog also carries a title the schema omits
ENTRY_REQUIRED = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'shortDescription',
                  'requiredAction', 'dueDate')
ENTRY_OPTIONAL = ('knownRansomwareCampaignUse', 'forensicTriage', 'notes', 'cwes')
ENTRY_KNOWN = frozenset((*ENTRY_REQUIRED, *ENTRY_OPTIONAL))
UPSTREAM_NAMES = {'cve_id': 'cveID', 'vendor_project': 'vendorProject', 'product': 'product',
                  'name': 'vulnerabilityName', 'date_added': 'dateAdded', 'due_date': 'dueDate',
                  'short_description': 'shortDescription', 'required_action': 'requiredAction', 'notes': 'notes',
                  'cwes': 'cwes', 'ransomware_use': 'knownRansomwareCampaignUse', 'forensic_triage': 'forensicTriage'}
SOURCES = ('cisa-site', 'cisa-github', 'local-import')

_BOM = b'\xef\xbb\xbf'
_RANSOMWARE = {'Known': 'known', 'Unknown': 'unknown'}
_TRIAGE = {'Yes': 'yes', 'No': 'no'}
_CWE = re.compile(r'CWE-[0-9]{1,6}')
_VERSION = re.compile(VERSION_PATTERN)
_RELEASED = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?Z')


class _Tally:
    """What the mapping tolerated, reported once in the meta as counts (never as untrusted text)."""
    __slots__ = ('shortened', 'unrecognized', 'dropped_cwes', 'unknown')

    def __init__(self) -> None:
        self.shortened = self.unrecognized = self.dropped_cwes = 0
        self.unknown: set[str] = set()


# --- bytes to a JSON document -------------------------------------------------------------------------------

def _no_repeated_keys(pairs: list) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise KevError(FORMAT, 'the file repeats a key inside one JSON object')
    return result


def _no_constants(_name: str):
    raise KevError(FORMAT, 'the file contains NaN or Infinity, which JSON does not allow')


def _looks_like_csv(raw: bytes) -> bool:
    return raw[len(_BOM):].startswith(b'cveID,') if raw.startswith(_BOM) else raw.startswith(b'cveID,')


def _load(raw: bytes) -> dict:
    if len(raw) > limits.MAX_CATALOG_BYTES:
        raise KevError('PT-KEV-LIMIT', f'the file is larger than {limits.MAX_CATALOG_BYTES // limits.MIB} MiB')
    if not raw or raw.isspace():
        raise KevError(FORMAT, 'the file is empty')
    if _looks_like_csv(raw):
        raise KevError('PT-KEV-UNSUPPORTED', 'a CSV file has no catalog version or release date; import the JSON file')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise KevError(FORMAT, 'the file is not UTF-8 text') from None
    try:
        document = json.loads(text, object_pairs_hook=_no_repeated_keys, parse_constant=_no_constants)
    except KevError:
        raise
    except RecursionError:
        raise KevError(FORMAT, 'the JSON is nested too deeply') from None
    except ValueError:                                          # includes JSONDecodeError and absurd integers
        raise KevError(FORMAT, 'the file is not valid JSON') from None
    if not isinstance(document, dict):
        raise KevError(FORMAT, 'the file is not a KEV JSON catalog')
    return document


# --- header -------------------------------------------------------------------------------------------------

def _released(value: object) -> str:
    match = _RELEASED.fullmatch(value) if type(value) is str else None
    if match is not None:
        try:
            datetime(*map(int, match.groups()))
        except ValueError:
            match = None
    if match is None:
        raise KevError(FORMAT, 'dateReleased is not a real UTC timestamp like 2026-10-13T19:10:43Z')
    return value[:19] + 'Z'                                     # seconds; the real file carries four fraction digits


def _header(document: dict) -> tuple[str, str, int, list]:
    missing = [name for name in TOP_REQUIRED if name not in document]
    if missing:
        raise KevError(FORMAT, f'the file is not a KEV catalog: it lacks {", ".join(missing)}')
    version = document['catalogVersion']
    version = version.strip() if type(version) is str else ''
    if not _VERSION.fullmatch(version):
        raise KevError(FORMAT, 'catalogVersion is not a short printable text')
    count, rows = document['count'], document['vulnerabilities']
    if type(count) is not int or count < 0:
        raise KevError(FORMAT, 'count is not a whole number')
    if not isinstance(rows, list):
        raise KevError(FORMAT, 'vulnerabilities is not a list')
    return version, _released(document['dateReleased']), count, rows


# --- entries ------------------------------------------------------------------------------------------------

def _field_name(scope: str, name: str) -> str:
    return f'{scope}.' + (clean_text(name, limits.MAX_UNKNOWN_NAME_CHARS - len(scope) - 1) or '?')


def _text(number: int, raw: dict, name: str, limit: int, tally: _Tally) -> str:
    value = raw[name]
    if type(value) is not str:
        raise KevError(VALIDATE, f'entry {number} has a {name} that is not text')
    text = clean_text(value, None)
    if len(text) > limit:
        tally.shortened += 1
        text = text[:limit - 3] + '...'
    return text


def _choice(number: int, raw: dict, name: str, mapping: dict, tally: _Tally) -> str:
    if name not in raw:
        return 'absent'
    value = raw[name]
    if type(value) is not str:
        raise KevError(VALIDATE, f'entry {number} has a {name} that is not text')
    found = mapping.get(value.strip())
    if found is None:
        tally.unrecognized += 1
        return 'unrecognized'
    return found


def _weaknesses(number: int, raw: dict, tally: _Tally) -> tuple[str, ...]:
    if 'cwes' not in raw:
        return ()
    items = raw['cwes']
    if not isinstance(items, list) or not all(type(item) is str for item in items):
        raise KevError(VALIDATE, f'entry {number} has a cwes that is not a list of text')
    kept = [token for token in (item.strip() for item in items) if _CWE.fullmatch(token)][:limits.MAX_CWES]
    tally.dropped_cwes += len(items) - len(kept)
    return tuple(kept)


def _entry(number: int, raw: object, tally: _Tally) -> KevEntry:
    if type(raw) is not dict:
        raise KevError(VALIDATE, f'entry {number} is not a JSON object')
    for name in ENTRY_REQUIRED:
        if name not in raw:
            raise KevError(VALIDATE, f'entry {number} lacks the required field {name}')
    tally.unknown.update(_field_name('entry', name) for name in raw if name not in ENTRY_KNOWN)
    for name in ('cveID', 'dateAdded', 'dueDate'):          # hashed below before the model checks their form
        if type(raw[name]) is not str:
            raise KevError(VALIDATE, f'entry {number} has a {name} that is not text')
        if not raw[name].isascii():
            raise KevError(VALIDATE, f'entry {number} has a {name} that is not plain ASCII')
    fields = {
        'cve_id': raw['cveID'],
        'vendor_project': _text(number, raw, 'vendorProject', limits.MAX_VENDOR_CHARS, tally),
        'product': _text(number, raw, 'product', limits.MAX_PRODUCT_CHARS, tally),
        'name': _text(number, raw, 'vulnerabilityName', limits.MAX_NAME_CHARS, tally),
        'date_added': raw['dateAdded'], 'due_date': raw['dueDate'],
        'short_description': _text(number, raw, 'shortDescription', limits.MAX_DESCRIPTION_CHARS, tally),
        'required_action': _text(number, raw, 'requiredAction', limits.MAX_ACTION_CHARS, tally),
        'notes': _text(number, raw, 'notes', limits.MAX_NOTES_CHARS, tally) if 'notes' in raw else '',
        'cwes': _weaknesses(number, raw, tally),
        'ransomware_use': _choice(number, raw, 'knownRansomwareCampaignUse', _RANSOMWARE, tally),
        'forensic_triage': _choice(number, raw, 'forensicTriage', _TRIAGE, tally),
    }
    try:
        return KevEntry(**fields, entry_digest=entry_digest(fields))
    except ValidationError as error:
        names = sorted({UPSTREAM_NAMES.get(str(item['loc'][0]), str(item['loc'][0])) for item in error.errors()
                        if item['loc']})
        raise KevError(VALIDATE, f'entry {number} failed checks ({", ".join(names) or "consistency"})') from None


def _entries(rows: list, tally: _Tally) -> list[KevEntry]:
    entries, seen = [], set()
    for number, raw in enumerate(rows, start=1):
        item = _entry(number, raw, tally)
        if item.cve_id in seen:
            raise KevError(VALIDATE, f'{item.cve_id} is listed more than once')
        seen.add(item.cve_id)
        entries.append(item)
    return sorted(entries, key=lambda item: item.cve_id)


# --- the catalog --------------------------------------------------------------------------------------------

def _warnings(tally: _Tally) -> tuple[str, ...]:
    found = len(tally.unknown)
    messages = [
        (tally.shortened, f'text values shortened to their length limit: {tally.shortened}'),
        (tally.unrecognized, f'ransomware or forensic triage values not recognized: {tally.unrecognized}'),
        (tally.dropped_cwes, 'weakness identifiers left out (not CWE-n, or beyond '
                             f'{limits.MAX_CWES} per entry): {tally.dropped_cwes}'),
        (found, f'unknown field names found: {found} (listed in unknown_fields)'),
        (found > limits.MAX_UNKNOWN_FIELDS, f'unknown field names not listed: {found - limits.MAX_UNKNOWN_FIELDS}')]
    return tuple(text for show, text in messages if show)


def parse_catalog(raw: bytes, *, source: str, retrieved_at: str, source_url: str | None = None,
                  final_url: str | None = None, consent: ConsentRecord | None = None,
                  file_name: str | None = None) -> KevCatalog:
    """Parse and check one catalog. ``source`` and the provenance arguments describe where ``raw`` came from; a
    description that contradicts itself is ``PT-KEV-INPUT``. Raises only ``KevError``."""
    if source not in SOURCES:
        raise KevError('PT-KEV-INPUT', 'source must be cisa-site, cisa-github or local-import')
    raw = bytes(raw)
    document = _load(raw)
    version, released, declared, rows = _header(document)
    if len(rows) > limits.MAX_ENTRIES:
        raise KevError('PT-KEV-LIMIT', f'the catalog lists more than {limits.MAX_ENTRIES} entries')
    if declared != len(rows):
        raise KevError(VALIDATE, f'count says {declared} entries but the file lists {len(rows)}')
    if not rows:
        raise KevError(VALIDATE, 'the catalog lists no entries')
    tally = _Tally()
    tally.unknown.update(_field_name('catalog', name) for name in document if name not in TOP_KNOWN)
    entries = _entries(rows, tally)
    sha = hashlib.sha256(raw).hexdigest()
    try:
        meta = KevCatalogMeta(
            snapshot_id=domain_id('kev-snapshot', 1, {'raw_sha256': sha, 'parser_version': limits.PARSER_VERSION}),
            raw_sha256=sha, raw_size=len(raw),
            content_digest=domain_id('kev-content', 1, [item.entry_digest for item in entries]),
            catalog_version=version, date_released=released, count=declared, entry_count=len(entries),
            source=source, source_url=source_url, final_url=final_url, retrieved_at=retrieved_at,
            authenticity='unverified-local-file' if source == 'local-import' else 'tls-allowlisted-host',
            unknown_fields=tuple(sorted(tally.unknown))[:limits.MAX_UNKNOWN_FIELDS], warnings=_warnings(tally),
            consent=consent, file_name=file_name)
    except ValidationError as error:
        names = sorted({str(item['loc'][0]) for item in error.errors() if item['loc']})
        raise KevError('PT-KEV-INPUT', f'the source description is inconsistent ({", ".join(names) or "source"})',
                       recoverable=False) from None
    return KevCatalog(meta, tuple(entries))
