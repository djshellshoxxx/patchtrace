"""Tolerant, bounded reader for CISA's KEV catalog JSON (KEV-integration-plan sections 6 and 7). Pure.

The input is untrusted: strict JSON (no duplicate keys, NaN or Infinity, bounded size and depth), parsed by content
and never by Content-Type. Unknown upstream fields are reported by name, not fatal; a missing required field is fatal
(upstream drift); an entry whose values fail validation is skipped and counted, never repaired. Only ``KevError`` is
raised. Messages are fixed templates. The CSV export has no release metadata, so it is refused.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re

from pydantic import ValidationError

from ..enrichment.identity import domain_id
from ..search.normalize import sanitize_text
from . import limits
from .contracts import ConsentRecord, KevCatalog, KevCatalogMeta, KevEntry, KevError, Source

TOP_REQUIRED = ('catalogVersion', 'dateReleased', 'count', 'vulnerabilities')
TOP_KNOWN = frozenset(TOP_REQUIRED) | {'title'}
ENTRY_REQUIRED = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'shortDescription',
                  'requiredAction', 'dueDate')
ENTRY_OPTIONAL = ('knownRansomwareCampaignUse', 'forensicTriage', 'notes', 'cwes')
ENTRY_KNOWN = frozenset(ENTRY_REQUIRED) | frozenset(ENTRY_OPTIONAL)
_RELEASED = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})')
_BOM = b'\xef\xbb\xbf'


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def _reject_constant(_name: str) -> None:
    raise ValueError('non-finite number')


def _depth(value: object) -> int:
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, (dict, list)):
            deepest = max(deepest, level)
            stack.extend((child, level + 1) for child in (item.values() if isinstance(item, dict) else item))
    return deepest


def _load(raw: bytes) -> tuple[object, list[str]]:
    warnings: list[str] = []
    if len(raw) > limits.MAX_BYTES:
        raise KevError('PT-KEV-LIMIT', 'the file is larger than 16 MiB')
    if raw.startswith(_BOM):
        raw = raw[len(_BOM):]
        warnings.append('A UTF-8 byte order mark was ignored.')
    if raw.lstrip()[:5] == b'cveID':
        raise KevError('PT-KEV-UNSUPPORTED', 'CSV has no catalog release date; import the JSON file')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise KevError('PT-KEV-FORMAT', 'the file is not a KEV JSON catalog') from exc
    if _depth(data) > limits.MAX_JSON_DEPTH:
        raise KevError('PT-KEV-FORMAT', 'the file is nested too deeply')
    return data, warnings


def _release_time(value: object) -> str:
    match = _RELEASED.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise KevError('PT-KEV-FORMAT', 'the catalog release time is missing or malformed')
    day, clock, zone = match.groups()
    try:
        stamp = datetime.datetime.fromisoformat(f'{day}T{clock}{"+00:00" if zone == "Z" else zone}')
    except ValueError as exc:
        raise KevError('PT-KEV-FORMAT', 'the catalog release time is not a real time') from exc
    return stamp.astimezone(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def _enum(value: object, mapping: dict[str, str]) -> str:
    if value is None:
        return 'absent'
    return mapping.get(value, 'unrecognized') if isinstance(value, str) else 'unrecognized'


def _text(item: dict, key: str, required: bool = True) -> str:
    value = item.get(key, None if required else '')
    if not isinstance(value, str):
        raise ValueError(f'{key} is not text')
    return value


def entry_digest(fields: dict) -> str:
    return domain_id('kev-entry', 1, fields)


def _entry(item: dict) -> KevEntry:
    """Map one upstream object to a stored entry; ValueError or ValidationError means skip it."""
    cwes = item.get('cwes', [])
    if not isinstance(cwes, list) or not all(isinstance(c, str) for c in cwes):
        raise ValueError('cwes is not a list of text')
    fields = {
        'cve_id': _text(item, 'cveID'), 'vendor_project': _text(item, 'vendorProject').strip(),
        'product': _text(item, 'product').strip(), 'name': _text(item, 'vulnerabilityName'),
        'date_added': _text(item, 'dateAdded'), 'due_date': _text(item, 'dueDate'),
        'cwes': tuple(cwes),
        'ransomware_use': _enum(item.get('knownRansomwareCampaignUse'), {'Known': 'known', 'Unknown': 'unknown'}),
        'forensic_triage': _enum(item.get('forensicTriage'), {'Yes': 'yes', 'No': 'no'}),
        'short_description': _text(item, 'shortDescription'),
        'required_action': _text(item, 'requiredAction'), 'notes': _text(item, 'notes', False),
    }
    return KevEntry(**fields, entry_digest=entry_digest(fields))


def content_digest(entries: list[KevEntry] | tuple[KevEntry, ...]) -> str:
    """Identity of the facts alone: independent of JSON layout, key order, entry order and edge whitespace."""
    return domain_id('kev-content', 1, sorted([entry.cve_id, entry.entry_digest] for entry in entries))


def snapshot_id(raw_sha256: str) -> str:
    return domain_id('kev-snapshot', 1, {'raw_sha256': raw_sha256, 'parser_version': limits.PARSER_VERSION})


def _basename(name: str | None) -> str | None:
    return re.split(r'[\\/]', name)[-1][:255] or None if name else None


def parse_catalog(raw: bytes, *, source: Source, retrieved_at: str, source_url: str | None = None,
                  final_url: str | None = None, consent: ConsentRecord | None = None,
                  file_name: str | None = None) -> KevCatalog:
    """Parse and validate catalog bytes. ``retrieved_at`` is supplied by the caller: the clock is never read here."""
    data, warnings = _load(raw)
    if not isinstance(data, dict) or any(key not in data for key in TOP_REQUIRED):
        raise KevError('PT-KEV-FORMAT', 'the file is not a KEV JSON catalog')
    items, count, version = data['vulnerabilities'], data['count'], data['catalogVersion']
    if not isinstance(items, list) or type(count) is not int or not isinstance(version, str) or not version \
            or len(version) > 32:
        raise KevError('PT-KEV-FORMAT', 'the catalog header has the wrong types')
    released = _release_time(data['dateReleased'])
    if count != len(items):
        raise KevError('PT-KEV-VALIDATE', 'the declared count differs from the number of entries')
    if not items:
        raise KevError('PT-KEV-VALIDATE', 'the catalog has no entries')
    if len(items) > limits.MAX_ENTRIES:
        raise KevError('PT-KEV-LIMIT', 'the catalog has too many entries')
    unknown = {key for key in data if key not in TOP_KNOWN}
    entries: dict[str, KevEntry] = {}
    skipped = 0
    for position, item in enumerate(items):
        if not isinstance(item, dict) or any(key not in item for key in ENTRY_REQUIRED):
            raise KevError('PT-KEV-FORMAT', 'an entry lacks a required field')
        unknown.update(key for key in item if key not in ENTRY_KNOWN)
        try:
            entry = _entry(item)
        except (ValueError, ValidationError):  # ValidationError is a ValueError subclass
            skipped += 1
            if len(warnings) < limits.MAX_WARNINGS:
                warnings.append(f'Entry {position + 1} failed validation and was skipped.')
            continue
        if entry.cve_id in entries:
            raise KevError('PT-KEV-VALIDATE', 'a CVE ID appears twice')
        entries[entry.cve_id] = entry
    ordered = tuple(entries[key] for key in sorted(entries))
    if not ordered:
        raise KevError('PT-KEV-VALIDATE', 'no entry passed validation')
    sha = hashlib.sha256(raw).hexdigest()
    try:
        meta = KevCatalogMeta(
            snapshot_id=snapshot_id(sha), raw_sha256=sha, raw_size=len(raw), content_digest=content_digest(ordered),
            catalog_version=version, date_released=released, count=count, entry_count=len(ordered),
            skipped_entries=skipped, source=source, source_url=source_url, final_url=final_url,
            retrieved_at=retrieved_at, authenticity='unverified-local-file' if source == 'local-import'
            else 'tls-allowlisted-host', unknown_fields=tuple(sorted(sanitize_text(key, 64) for key in unknown))[:limits.MAX_UNKNOWN_FIELDS], warnings=tuple(warnings), consent=consent, file_name=_basename(file_name))
        return KevCatalog(meta=meta, entries=ordered)
    except ValidationError as exc:
        raise KevError('PT-KEV-VALIDATE', 'the catalog header failed checks') from exc
