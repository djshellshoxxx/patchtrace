"""Pure Winbindex parsing (SPEC-08 §4.1-4.3). Stdlib only; never touches the network.

Winbindex is a metadata source (GPL-3 data fetched at runtime, never bundled). Field
semantics are from Winbindex @ aacec0c (docs/research/phase3/acquisition.md §1).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import zlib
from dataclasses import dataclass

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
_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
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
        return json.loads(text.decode('utf-8'), object_pairs_hook=_no_duplicates,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise AcquisitionError('PT-ACQ-PROVIDER', 'Winbindex record is not strict JSON') from None


def _uint(value) -> bool:
    return type(value) is int and 0 <= value <= UINT32_MAX


def _opt_uint(info: dict, key: str) -> int | None:
    value = info.get(key)
    return value if _uint(value) else None


def _canonical(value) -> bytes:
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
            ref = KbRef(kb=kb[:64] or '?',
                        release_date=date if isinstance(date, str) and _DATE.fullmatch(date) else None,
                        release_version=release if isinstance(release, str) else None)
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
        candidates.append(BuildCandidate(
            file_name=file_name, sha256=key, size=info['size'], machine_type=info['machineType'],
            timestamp=info['timestamp'], virtual_size=virtual_size,
            last_section_va=va if download == 'candidates' else None,
            last_section_raw=raw if download == 'candidates' else None,
            version=version if isinstance(version, str) else None, windows_versions=versions, kbs=kbs,
            download=download, source=f'winbindex@{data_date}',
            record_sha256=hashlib.sha256(_canonical(entry)).hexdigest()))
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
