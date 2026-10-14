"""Winbindex catalogue for Tier W (SPEC-33 s3.1-3.3).

Reuses `acquisition.winbindex` for decompression caps, strict JSON and the validated per-build fields; adds a
strict, bounded extraction of the per-line KB annotations (line -> KB -> date/release/kind). Winbindex data is
GPL-3.0 metadata fetched at runtime; the catalogue is written only under PATCHTRACE_CALIB_ROOT.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

from patchtrace.acquisition import winbindex
from patchtrace.acquisition.contracts import (
    UINT32_MAX,
    X64_MACHINE,
    AcquisitionError,
    BuildCandidate,
    symbol_server_url,
    validate_file_name,
)

from .contracts import Catalogue, CatalogueBuild, KbLine
from .paths import TIER, TierWError

FAMILIES: dict[str, str] = {
    'ntoskrnl.exe': 'kernel',
    'afd.sys': 'driver', 'clfs.sys': 'driver', 'http.sys': 'driver', 'tcpip.sys': 'driver', 'ntfs.sys': 'driver',
    'win32kfull.sys': 'driver',
    'ntdll.dll': 'usermode-dll', 'kernelbase.dll': 'usermode-dll', 'kernel32.dll': 'usermode-dll',
    'rpcrt4.dll': 'usermode-dll', 'ucrtbase.dll': 'usermode-dll', 'msvcrt.dll': 'usermode-dll',
    'ole32.dll': 'usermode-dll',
}
CLASSES = ('kernel', 'driver', 'usermode-dll')
_LINE = re.compile(r'[A-Za-z0-9._-]{1,32}')
_KB = re.compile(r'[A-Za-z0-9._-]{1,64}')
_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
_RELEASE = re.compile(r'\d{1,6}\.\d{1,6}')
_VERSION_NUM = re.compile(r'\d+')
MAX_HEADING = 512


def family_of(file_name: str, overrides: Mapping[str, str] | None = None) -> str:
    family = (overrides or {}).get(file_name) or FAMILIES.get(file_name)
    if family not in CLASSES:
        raise TierWError('PT-TIERW-INPUT', f'{file_name}: unknown family; pass --family {file_name}=<'
                                           + '|'.join(CLASSES) + '>')
    return family


def kb_kind(kb: str, heading: object) -> str:
    if kb.upper().startswith('BASE'):
        return 'base'
    text = heading.lower() if isinstance(heading, str) else ''
    if 'out-of-band' in text:
        return 'oob'
    if 'preview' in text:
        return 'preview'
    return 'monthly'


def version_tuple(version: str | None) -> tuple[int, ...]:
    """'10.0.22621.4317 (WinBuild...)' -> (10, 0, 22621, 4317); unparsable -> ()."""
    if not isinstance(version, str):
        return ()
    head = version.split(' ', 1)[0]
    parts = head.split('.')
    if not all(_VERSION_NUM.fullmatch(p) for p in parts) or len(parts) > 6:
        return ()
    return tuple(int(p) for p in parts)


def _date_of(body: Mapping, key: str) -> str | None:
    info = body.get(key)
    date = info.get('releaseDate') if isinstance(info, dict) else None
    return date if isinstance(date, str) and _DATE.fullmatch(date) else None


def extract_lines(windows: object) -> tuple[dict[str, tuple[KbLine, ...]], int]:
    """Strict, bounded per-line KB annotations. Returns (lines, dropped_count)."""
    lines: dict[str, tuple[KbLine, ...]] = {}
    dropped = 0
    if not isinstance(windows, dict):
        return lines, 0
    for line, updates in sorted(windows.items())[:64]:
        if not isinstance(line, str) or not _LINE.fullmatch(line) or not isinstance(updates, dict):
            dropped += 1
            continue
        refs: dict[tuple, KbLine] = {}
        for kb, body in list(updates.items())[:256]:
            if not isinstance(kb, str) or not _KB.fullmatch(kb) or not isinstance(body, dict):
                dropped += 1
                continue
            info = body.get('updateInfo') if isinstance(body.get('updateInfo'), dict) else {}
            date = _date_of(body, 'updateInfo') or (_date_of(body, 'windowsVersionInfo')
                                                    if kb.upper().startswith('BASE') else None)
            release = info.get('releaseVersion')
            release = release if isinstance(release, str) and _RELEASE.fullmatch(release) else None
            heading = info.get('heading')
            heading = heading[:MAX_HEADING] if isinstance(heading, str) else None
            ref = KbLine(kb=kb, date=date, release=release, kind=kb_kind(kb, heading))
            refs[(ref.date or '', ref.kb, ref.release or '')] = ref
        if refs:
            lines[line] = tuple(refs[k] for k in sorted(refs))
    return lines, dropped


def build_catalogue(data: bytes, file_name: str, data_date: str, *, compressed: bool = True,
                    family: str | None = None, retrieved_at: str = '') -> Catalogue:
    """Parse one Winbindex `<name>.json.gz` body (or its decompressed JSON) into a `tier-w-catalogue/1`."""
    try:
        name = validate_file_name(file_name)
        raw = winbindex.decompress(data) if compressed else data
        parsed = winbindex.parse(raw, name, data_date, compressed=False)
        document = winbindex.strict_json(raw)
    except AcquisitionError as exc:
        raise TierWError('PT-TIERW-INPUT', f'Winbindex record for {file_name}: {exc.message}') from None
    builds, non_x64, dropped = [], 0, 0
    for cand in parsed.candidates:
        if cand.machine_type != X64_MACHINE:
            non_x64 += 1
            continue
        entry = document.get(cand.sha256) if isinstance(document, dict) else None
        lines, lost = extract_lines(entry.get('windowsVersions') if isinstance(entry, dict) else None)
        dropped += lost
        builds.append(CatalogueBuild(
            sha256=cand.sha256, size=cand.size, machine=cand.machine_type, timestamp=cand.timestamp,
            virtual_size=cand.virtual_size, last_section_va=cand.last_section_va,
            last_section_raw=cand.last_section_raw, version=cand.version[:128] if cand.version else None,
            download=cand.download, record_sha256=cand.record_sha256, lines=lines))
    builds.sort(key=lambda b: b.sha256)
    return Catalogue(contract='tier-w-catalogue/1', tier=TIER, file_name=name,
                     family=family or family_of(name), source=f'winbindex@{data_date}',
                     retrieved_at=retrieved_at[:40],
                     metadata_sha256=hashlib.sha256(data).hexdigest() if compressed else None,
                     builds=tuple(builds), skipped=parsed.skipped, non_x64=non_x64, dropped_kbs=dropped,
                     warnings=parsed.warnings)


def as_candidate(cat: Catalogue, build: CatalogueBuild) -> BuildCandidate:
    """Rebuild the acquisition record for URL derivation (`winbindex.direct_url` / `candidate_urls`)."""
    return BuildCandidate(file_name=cat.file_name, sha256=build.sha256, size=build.size,
                          machine_type=build.machine, timestamp=build.timestamp,
                          virtual_size=build.virtual_size, last_section_va=build.last_section_va,
                          last_section_raw=build.last_section_raw, version=build.version,
                          windows_versions=tuple(sorted(build.lines)), download=build.download,
                          source=cat.source, record_sha256=build.record_sha256)


def resolve_candidates(cat: Catalogue, probe, *, max_probes: int, only: set[str] | None = None,
                       log=None) -> tuple[Catalogue, dict]:
    """Resolve SizeOfImage for `candidates` builds with HEAD probes (`probe(urls) -> url`, normally
    `Transport.resolve` with consent for exactly these URLs). Spends at most `max_probes` probes."""
    budget = max_probes
    stats = {'resolved': 0, 'not-found': 0, 'over-budget': 0, 'errors': 0}
    out = []
    for build in cat.builds:
        if build.download != 'candidates' or build.resolved_virtual_size or (only and build.sha256 not in only):
            out.append(build)
            continue
        try:
            sizes = winbindex.candidate_sizes(as_candidate(cat, build))
        except AcquisitionError:
            stats['errors'] += 1
            out.append(build)
            continue
        urls = winbindex.candidate_urls(as_candidate(cat, build))
        if not urls or len(urls) > budget:
            stats['over-budget' if urls else 'not-found'] += 1
            out.append(build)
            continue
        budget -= len(urls)
        if log:
            for url in urls:
                log(f'request: HEAD {url}')
        try:
            url = probe(urls)
        except AcquisitionError as exc:
            stats['not-found' if exc.code == 'PT-ACQ-NOTFOUND' else 'errors'] += 1
            if exc.code == 'PT-ACQ-CANCEL':
                raise TierWError('PT-TIERW-CANCEL', 'resolve cancelled') from None
            out.append(build)
            continue
        by_url = {symbol_server_url(cat.file_name, build.timestamp, s): s for s in sizes if s <= UINT32_MAX}
        if url not in by_url:
            stats['errors'] += 1
            out.append(build)
            continue
        out.append(build.model_copy(update={'resolved_virtual_size': by_url[url]}))
        stats['resolved'] += 1
    return cat.model_copy(update={'builds': tuple(out)}), stats
