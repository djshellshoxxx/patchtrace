"""Pure Winbindex parsing (SPEC-08 §4.1-4.3). Stdlib only; never touches the network.

Winbindex is a metadata source (GPL-3 data fetched at runtime, never bundled). Field
semantics are from Winbindex @ aacec0c (docs/research/phase3/acquisition.md §1).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
import zlib
from dataclasses import dataclass
from datetime import date as _calendar_date

from .contracts import (
    UINT32_MAX,
    AcquisitionError,
    BuildCandidate,
    KbRef,
    symbol_server_url,
    validate_file_name,
)

METADATA_BASE = 'https://winbindex.m417z.com/data/by_filename_compressed'
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_DECOMPRESSED = 256 * 1024 * 1024
MAX_PROBES = 256
PAGE = 0x1000
_SHA = re.compile(r'[0-9a-f]{64}')
_DATE_SHAPE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')  # ASCII only: \d also matches other scripts' digits
REQUIRED = ('sha256', 'size', 'machineType', 'timestamp')


def metadata_url(file_name: str) -> str:
    # Lowercase is enforced by validate_file_name; the Winbindex URL is case-sensitive.
    return f'{METADATA_BASE}/{validate_file_name(file_name)}.json.gz'


@dataclass(frozen=True)
class ParseResult:
    candidates: tuple[BuildCandidate, ...]
    skipped: int
    warnings: tuple[str, ...]


def decompress(data: bytes) -> bytes:
    if len(data) > MAX_COMPRESSED:
        raise AcquisitionError('PT-ACQ-LIMIT', 'Winbindex record exceeds 64 MiB compressed')
    inflater = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        # max_length bounds memory while inflating, so a gzip bomb stops at the cap.
        out = inflater.decompress(data, MAX_DECOMPRESSED + 1)
        if len(out) > MAX_DECOMPRESSED or inflater.unconsumed_tail:
            raise AcquisitionError('PT-ACQ-LIMIT', 'Winbindex record exceeds 256 MiB decompressed')
        out += inflater.flush()
        if len(out) > MAX_DECOMPRESSED:
            raise AcquisitionError('PT-ACQ-LIMIT', 'Winbindex record exceeds 256 MiB decompressed')
    except zlib.error:
        raise AcquisitionError('PT-ACQ-PROVIDER', 'Winbindex record is not valid gzip') from None
    if not inflater.eof or inflater.unused_data:
        raise AcquisitionError('PT-ACQ-PROVIDER', 'Winbindex record is truncated or has trailing data')
    return out


_SURROGATE_ESCAPE = re.compile(rb'\\u[dD][89a-fA-F]')


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate key {key!r}')
        result[key] = value
    return result


def _reject_constant(name):
    raise ValueError(f'non-finite number {name}')


def _finite_float(literal: str) -> float:
    number = float(literal)  # an overflowing literal such as 1e999 never reaches parse_constant
    if not math.isfinite(number):
        _reject_constant(literal[:40])
    return number


def strict_json(text: bytes):
    try:
        value = json.loads(text.decode('utf-8'), object_pairs_hook=_no_duplicates,
                           parse_constant=_reject_constant, parse_float=_finite_float)
        if _SURROGATE_ESCAPE.search(text):
            _canonical(value)  # an unpaired surrogate is legal JSON but not text; this raises on it
        return value
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise AcquisitionError('PT-ACQ-PROVIDER', 'Winbindex record is not strict JSON') from None


def _uint(value) -> bool:
    return type(value) is int and 0 <= value <= UINT32_MAX


def _opt_uint(info: dict, key: str) -> int | None:
    value = info.get(key)
    return value if _uint(value) else None


class _DateShape:
    """``fullmatch`` for a real calendar day written ``YYYY-MM-DD`` in ASCII digits."""

    @staticmethod
    def fullmatch(value: str) -> bool:
        if not _DATE_SHAPE.fullmatch(value):
            return False
        try:
            _calendar_date.fromisoformat(value)
        except ValueError:
            return False
        return True


_DATE = _DateShape()


def _canonical(value) -> bytes:
    """Hashed form of one entry. Raises ``UnicodeEncodeError`` for a lone surrogate, which callers count as a
    malformed entry (the JSON parser accepts ``\\ud800``; UTF-8 cannot encode it)."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _kbs(windows: dict) -> tuple[tuple[str, ...], tuple[KbRef, ...]]:
    versions: set[str] = set()
    kbs: dict[tuple, KbRef] = {}
    for version, updates in windows.items():
        if not isinstance(updates, dict):
            continue
        versions.add(version)
        for kb, body in updates.items():
            info = body.get('updateInfo') if isinstance(body, dict) else None
            info = info if isinstance(info, dict) else {}
            date = info.get('releaseDate')
            release = info.get('releaseVersion')
            # Keys and versions are provider text that reaches a terminal: control, format and separator
            # characters are replaced (``_clean``) before anything is kept.
            ref = KbRef(kb=_clean(kb, 64).strip() or '?',
                        release_date=date if isinstance(date, str) and _DATE.fullmatch(date) else None,
                        release_version=_clean(release, 64) if isinstance(release, str) else None)
            kbs[(ref.kb, ref.release_date or '', ref.release_version or '')] = ref
    return tuple(sorted(versions)), tuple(kbs[k] for k in sorted(kbs))


def parse(data: bytes, file_name: str, data_date: str, *, compressed: bool = True) -> ParseResult:
    """Parse a ``<name>.json.gz`` body into candidates; malformed entries are skipped and counted."""
    file_name = validate_file_name(file_name)
    if not _DATE.fullmatch(data_date):
        raise AcquisitionError('PT-ACQ-INPUT', 'data date must be YYYY-MM-DD')
    document = strict_json(decompress(data) if compressed else data)
    if not isinstance(document, dict):
        raise AcquisitionError('PT-ACQ-PROVIDER', 'Winbindex record must be a JSON object')
    candidates = []
    skipped = 0
    for key, entry in document.items():
        info = entry.get('fileInfo') if isinstance(entry, dict) else None
        if (not isinstance(info, dict) or any(f not in info for f in REQUIRED)
                or not isinstance(info['sha256'], str) or not _SHA.fullmatch(info['sha256'])
                or info['sha256'] != key or not _uint(info['size']) or info['size'] < 1
                or not _uint(info['timestamp']) or type(info['machineType']) is not int
                or not 0 <= info['machineType'] <= 0xFFFF):
            skipped += 1
            continue
        virtual_size = _opt_uint(info, 'virtualSize') or None
        va, raw = _opt_uint(info, 'lastSectionVirtualAddress'), _opt_uint(info, 'lastSectionPointerToRawData')
        if virtual_size is not None:
            download = 'direct'
        elif va is not None and raw is not None:
            download = 'candidates'
        else:
            download = 'unavailable'
        windows = entry.get('windowsVersions')
        versions, kbs = _kbs(windows) if isinstance(windows, dict) else ((), ())
        version = info.get('version')
        try:
            record_sha256 = hashlib.sha256(_canonical(entry)).hexdigest()
        except UnicodeEncodeError:
            skipped += 1
            continue
        candidates.append(BuildCandidate(
            file_name=file_name, sha256=key, size=info['size'], machine_type=info['machineType'],
            timestamp=info['timestamp'], virtual_size=virtual_size,
            last_section_va=va if download == 'candidates' else None,
            last_section_raw=raw if download == 'candidates' else None,
            version=_clean(version, 200) if isinstance(version, str) else None, windows_versions=versions,
            kbs=kbs, download=download, source=f'winbindex@{data_date}', record_sha256=record_sha256))
    candidates.sort(key=lambda c: (min((k.release_date for k in c.kbs if k.release_date), default=''),
                                   c.sha256))
    warnings = (f'{skipped} Winbindex entries skipped: missing or invalid required fields',) if skipped else ()
    return ParseResult(tuple(candidates), skipped, warnings)


def direct_url(candidate: BuildCandidate) -> str:
    if candidate.download != 'direct' or candidate.virtual_size is None:
        raise AcquisitionError('PT-ACQ-INPUT', 'candidate has no direct symbol-server URL')
    return symbol_server_url(candidate.file_name, candidate.timestamp, candidate.virtual_size)


def candidate_sizes(candidate: BuildCandidate) -> tuple[int, ...]:
    """SizeOfImage guesses, largest first, per Winbindex's delta-only enumeration."""
    va, raw = candidate.last_section_va, candidate.last_section_raw
    if candidate.download != 'candidates' or va is None or raw is None:
        raise AcquisitionError('PT-ACQ-INPUT', 'candidate has no last-section data to enumerate')
    if candidate.size < raw:
        return ()
    end = va + (candidate.size - raw)
    top = -(-end // PAGE) * PAGE
    bottom = va + PAGE
    if top < bottom:
        return ()
    count = (top - bottom) // PAGE + 1
    if count > MAX_PROBES:
        raise AcquisitionError('PT-ACQ-LIMIT', f'candidate enumeration needs {count} probes (cap {MAX_PROBES})')
    return tuple(range(top, bottom - 1, -PAGE))


def candidate_urls(candidate: BuildCandidate) -> tuple[str, ...]:
    return tuple(symbol_server_url(candidate.file_name, candidate.timestamp, s)
                 for s in candidate_sizes(candidate) if s <= UINT32_MAX)


# ----------------------------------------------------------------------------------------------- per-row view
# Additive (KB2 s2.D, RK2 s1.5): identity is the dict key, one row per (version key, KB) body, md5-only delta
# records kept. ``parse`` above is unchanged and still feeds the acquisition flow.

HEADING_MAX = 300
_KB = re.compile(r'KB[0-9]{4,10}')
_VERSION_KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,39}')
_UBR = re.compile(r'[0-9]{1,6}\.[0-9]{1,6}')
_FULL_MARKERS = ('version', 'sha1', 'description')


@dataclass(frozen=True)
class WinbindexRow:
    """One Winbindex ``(file build, Windows version, KB)`` fact; ``kb`` is None for the dated BASE image."""
    file_name: str
    sha256: str
    version_key: str
    kb: str | None
    release_date: str | None
    release_version: str | None
    heading: str
    heading_class: str
    other_versions: tuple[str, ...]
    variant: str
    download: str
    size: int | None
    machine_type: int | None
    timestamp: int | None
    virtual_size: int | None
    last_section_va: int | None
    last_section_raw: int | None
    file_version: str | None
    record_sha256: str
    source: str

    def as_mapping(self) -> dict:
        """JSON-compatible form handed to ``kbcorrelation`` through its index port."""
        data = {name: getattr(self, name) for name in self.__dataclass_fields__}
        data['other_versions'] = list(self.other_versions)
        if self.download == 'direct' and self.timestamp is not None and self.virtual_size is not None:
            data['download_url'] = symbol_server_url(self.file_name, self.timestamp, self.virtual_size)
        return data


@dataclass(frozen=True)
class RowsResult:
    rows: tuple[WinbindexRow, ...]
    skipped: int
    skipped_bodies: int
    warnings: tuple[str, ...]


def heading_class(heading: str | None) -> str:
    text = (heading or '').lower()
    if not text:
        return 'none'
    if 'expired' in text:
        return 'expired'
    if 'out-of-band' in text or 'out of band' in text:
        return 'out-of-band'
    return 'preview' if 'preview' in text else 'standard'


def _clean(text: str, limit: int) -> str:
    # Advisory-adjacent text is untrusted: drop control and format (bidi) characters and the Unicode line and
    # paragraph separators (Zl, Zp), then bound it.
    return ''.join(' ' if unicodedata.category(c)[0] == 'C' or unicodedata.category(c) in ('Zl', 'Zp') else c
                   for c in text)[:limit]


def _variant(info: dict) -> str:
    if 'timestamp' not in info or 'machineType' not in info:
        return 'raw'
    if any(marker in info for marker in _FULL_MARKERS):
        return 'full'
    return 'delta+' if 'virtualSize' in info else 'delta'


def _download_class(size, timestamp, virtual_size, va, raw) -> str:
    if timestamp is not None and virtual_size is not None:
        return 'direct'
    if timestamp is not None and size is not None and va is not None and raw is not None:
        return 'candidates'
    return 'unavailable'


def _date(value) -> str | None:
    return value if isinstance(value, str) and _DATE.fullmatch(value) else None


def _body_facts(kb: str, body) -> tuple[str | None, str | None, str, tuple[str, ...]] | None:
    """(release_date, release_version, heading, other version keys) or None for an unreadable body."""
    if not isinstance(body, dict):
        return None
    if kb == 'BASE':
        base = body.get('windowsVersionInfo')
        return (_date(base.get('releaseDate')) if isinstance(base, dict) else None), None, '', ()
    info = body.get('updateInfo')
    if not _KB.fullmatch(kb) or not isinstance(info, dict):
        return None
    release = info.get('releaseVersion')
    heading = info.get('heading')
    others = info.get('otherWindowsVersions')
    shared = sorted({o for o in others if isinstance(o, str) and _VERSION_KEY.fullmatch(o)}) \
        if isinstance(others, list) else []
    return (_date(info.get('releaseDate')),
            release if isinstance(release, str) and _UBR.fullmatch(release) else None,
            _clean(heading, HEADING_MAX) if isinstance(heading, str) else '', tuple(shared))


def _entry_rows(file_name: str, key: str, entry: dict, info: dict, source: str):
    """Rows for one entry plus the number of unreadable ``(version, KB)`` bodies."""
    size, timestamp = _opt_uint(info, 'size') or None, _opt_uint(info, 'timestamp')
    virtual_size = _opt_uint(info, 'virtualSize') or None
    va, raw = _opt_uint(info, 'lastSectionVirtualAddress'), _opt_uint(info, 'lastSectionPointerToRawData')
    machine = info.get('machineType')
    version = info.get('version')
    common = dict(
        file_name=file_name, sha256=key, variant=_variant(info),
        download=_download_class(size, timestamp, virtual_size, va, raw), size=size,
        machine_type=machine if type(machine) is int and 0 <= machine <= 0xFFFF else None, timestamp=timestamp,
        virtual_size=virtual_size, last_section_va=va, last_section_raw=raw,
        file_version=_clean(version, 200) if isinstance(version, str) else None,
        record_sha256=hashlib.sha256(_canonical(entry)).hexdigest(), source=source)
    rows, bad = [], 0
    windows = entry.get('windowsVersions')
    for version_key, updates in (windows.items() if isinstance(windows, dict) else ()):
        if not isinstance(updates, dict) or not _VERSION_KEY.fullmatch(version_key):
            bad += 1
            continue
        for kb, body in updates.items():
            facts = _body_facts(kb, body)
            if facts is None:
                bad += 1
                continue
            date, release, heading, others = facts
            rows.append(WinbindexRow(version_key=version_key, kb=None if kb == 'BASE' else kb, release_date=date,
                                     release_version=release, heading=heading,
                                     heading_class=heading_class(heading or None),
                                     other_versions=tuple(o for o in others if o != version_key), **common))
    return rows, bad


def parse_rows(data: bytes, file_name: str, data_date: str, *, compressed: bool = True) -> RowsResult:
    """Parse a ``<name>.json.gz`` body into one row per ``(SHA-256, version key, KB)``.

    Identity is the dict key; a ``fileInfo.sha256`` that disagrees with it is a conflict and the entry is skipped,
    while an absent one (md5-only delta records, the newest builds) is kept. Counts of what was skipped are returned.
    """
    file_name = validate_file_name(file_name)
    if not _DATE.fullmatch(data_date):
        raise AcquisitionError('PT-ACQ-INPUT', 'data date must be YYYY-MM-DD')
    document = strict_json(decompress(data) if compressed else data)
    if not isinstance(document, dict):
        raise AcquisitionError('PT-ACQ-PROVIDER', 'Winbindex record must be a JSON object')
    rows: list[WinbindexRow] = []
    skipped = skipped_bodies = 0
    for key, entry in document.items():
        info = entry.get('fileInfo') if isinstance(entry, dict) else None
        if (not isinstance(info, dict) or not _SHA.fullmatch(key)
                or info.get('sha256', key) != key):
            skipped += 1
            continue
        try:
            found, bad = _entry_rows(file_name, key, entry, info, f'winbindex@{data_date}')
        except UnicodeEncodeError:                  # a lone surrogate somewhere in the entry
            skipped += 1
            continue
        rows.extend(found)
        skipped_bodies += bad
    rows.sort(key=lambda r: (r.version_key, r.release_date or '', r.release_version or '', r.kb or '', r.sha256))
    warnings = []
    if skipped:
        warnings.append(f'{skipped} index rows skipped (newest builds may be missing)')
    if skipped_bodies:
        warnings.append(f'{skipped_bodies} version/KB bodies unreadable and ignored')
    return RowsResult(tuple(rows), skipped, skipped_bodies, tuple(warnings))
