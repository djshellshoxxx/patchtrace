"""File-index lineage (KB-integration-plan 3.1, 6 and 7.2; RK2 s2.3; slice K5). Pure: no sibling imports.

Winbindex rows reach this module as plain mappings (``acquisition.winbindex.WinbindexRow.as_mapping``) through
``IndexPort``. Rules that keep the index from over-claiming:

* chronology is ``(release date, release version UBR)`` inside one version key, never file version or PE timestamp;
* a sibling key listed in ``otherWindowsVersions`` gets its own row, tagged ``shared_from``, because the build prefix
  of a shared KB may belong to the sibling (only the UBR is common);
* ``changed_in_kb`` is ``yes`` only for the first row of a SHA run that has a predecessor; an unchanged file reports
  where it last changed; a missing row, a first row or two SHAs for one KB is ``unknown``, never ``no``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .contracts import Arch, Availability, BuildRow
from .ids import is_canonical_kb, kb_sort_key

MACHINES: dict[int, Arch] = {0x8664: 'amd64', 0xAA64: 'arm64', 0x14C: 'x86'}
Change = Literal['yes', 'no', 'unknown']

_SHA = re.compile(r'[0-9a-f]{64}')
_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
_UBR = re.compile(r'(\d{1,6})\.(\d{1,6})')
_BUILD_IN_TEXT = re.compile(r'(?<![\d.])\d{1,6}\.\d{1,6}(?![\d.])')
_FILE_VERSION = re.compile(r'\d{1,5}(?:\.\d{1,5}){3}')
_DELTA_VARIANTS = ('delta', 'delta+')


@dataclass(frozen=True)
class IndexRow:
    """A BuildRow plus the binary facts a pair needs. ``shared_from`` names the key this row was copied from."""
    build: BuildRow
    size: int
    machine: Arch
    file_version: str | None
    availability: Availability
    heading_builds: tuple[str, ...]
    shared_from: str | None = None

    @property
    def sha256(self) -> str:
        return self.build.sha256

    @property
    def kb(self) -> str | None:
        return self.build.kb


@dataclass(frozen=True)
class ChangeInfo:
    """``reason`` is one of no-row, variants, first-row, new-build, unchanged."""
    state: Change
    reason: str
    last_changed_in: str | None = None
    target_rows: tuple[IndexRow, ...] = ()


def ubr_key(text: str | None) -> tuple[int, int]:
    match = _UBR.fullmatch(text or '')
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def order_key(row: IndexRow) -> tuple:
    """Chronology within one version key: date, then UBR; the dated BASE image first on a tie."""
    build = row.build
    return (build.release_date or '', ubr_key(build.release_version), build.kb is not None,
            kb_sort_key(build.kb) if build.kb else (0, ''), build.sha256)


def _availability(download: object, variant: str) -> Availability:
    if download in ('direct', 'candidates'):
        return download  # type: ignore[return-value]
    return 'delta-only' if variant in _DELTA_VARIANTS else 'unavailable'


def _timestamp(date: object) -> str | None:
    return f'{date}T00:00:00Z' if isinstance(date, str) and _DATE.fullmatch(date) else None


def _text(value: object, default: str = '') -> str:
    return value if isinstance(value, str) else default


def _row_fields(item: Mapping, version_key: str, shared_from: str | None) -> dict | None:
    sha, kb = item.get('sha256'), item.get('kb')
    if not isinstance(sha, str) or not _SHA.fullmatch(sha) or not (kb is None or is_canonical_kb(kb)):
        return None
    heading = _text(item.get('heading'))
    release = item.get('release_version')
    machine = item.get('machine_type')
    size = item.get('size')
    version = _text(item.get('file_version'))
    return {'sha256': sha, 'kb': kb, 'version_key': version_key, 'shared_from': shared_from,
            'release_date': _timestamp(item.get('release_date')),
            'release_version': release if isinstance(release, str) and _UBR.fullmatch(release) else None,
            'heading_class': _text(item.get('heading_class'), 'none'), 'variant': _text(item.get('variant'), 'raw'),
            'download': item.get('download_url') if isinstance(item.get('download_url'), str) else None,
            'record_sha256': item.get('record_sha256'), 'size': size if type(size) is int and size > 0 else 0,
            'machine': MACHINES.get(machine, 'unknown') if type(machine) is int else 'unknown',
            'file_version': match.group(0) if (match := _FILE_VERSION.match(version)) else None,
            'availability': _availability(item.get('download'), _text(item.get('variant'))),
            'heading_builds': tuple(sorted(set(_BUILD_IN_TEXT.findall(heading))))}


def _expanded(item: Mapping) -> Iterable[dict]:
    key = item.get('version_key')
    if not isinstance(key, str) or not key:
        return
    for version_key, shared_from in [(key, None)] + [
            (other, key) for other in (item.get('other_versions') or ()) if isinstance(other, str) and other]:
        fields = _row_fields(item, version_key, shared_from)
        if fields is not None:
            yield fields


def index_rows(mappings: Iterable[Mapping], *, file_name: str) -> tuple[tuple[IndexRow, ...], int]:
    """Validate index mappings into rows, expanding ``other_versions``. Returns ``(rows, rejected_count)``.

    An own body wins over a copy for the same ``(version key, KB, SHA)``; a mapping that cannot become a row is
    counted, not guessed.
    """
    chosen: dict[tuple, dict] = {}
    seen = rejected = 0
    for item in mappings:
        seen += 1
        fields = list(_expanded(item)) if isinstance(item, Mapping) else []
        if not fields:
            rejected += 1
        for f in fields:
            key = (f['version_key'], f['kb'], f['sha256'])
            if key not in chosen or (chosen[key]['shared_from'] and not f['shared_from']):
                chosen[key] = f
    runs: dict[tuple, set[str]] = {}
    for f in chosen.values():
        if f['kb']:
            runs.setdefault((f['version_key'], f['sha256']), set()).add(f['kb'])
    rows = []
    for f in chosen.values():
        try:
            build = BuildRow(
                file_name=file_name, sha256=f['sha256'], version_key=f['version_key'], kb=f['kb'],
                release_date=f['release_date'], release_version=f['release_version'],
                heading_class=f['heading_class'],
                shared_with=tuple(sorted(runs.get((f['version_key'], f['sha256']), set()) - {f['kb']})),
                variant=f['variant'], download=f['download'], record_sha256=f['record_sha256'],
                data_date=None)
        except ValueError:
            rejected += 1
            continue
        rows.append(IndexRow(build, f['size'], f['machine'], f['file_version'], f['availability'],
                             f['heading_builds'], f['shared_from']))
    return tuple(sorted(rows, key=lambda r: (r.build.version_key, order_key(r)))), rejected


def timeline(rows: Iterable[IndexRow], version_key: str) -> tuple[IndexRow, ...]:
    return tuple(sorted((r for r in rows if r.build.version_key == version_key), key=order_key))


def version_keys(rows: Iterable[IndexRow]) -> tuple[str, ...]:
    return tuple(sorted({r.build.version_key for r in rows}))


def change_in_kb(line: Sequence[IndexRow], kb: str) -> ChangeInfo:
    """Did the file change in ``kb`` (an index claim for one version key; ``line`` is a :func:`timeline`)."""
    targets = tuple(r for r in line if r.kb == kb)
    if not targets:
        return ChangeInfo('unknown', 'no-row')
    if len({r.sha256 for r in targets}) > 1:
        return ChangeInfo('unknown', 'variants', None, targets)  # several SHAs for one KB: never auto-pick
    index = line.index(targets[0])
    start = index
    while start > 0 and line[start - 1].sha256 == targets[0].sha256:
        start -= 1
    if start < index:
        return ChangeInfo('no', 'unchanged', line[start].kb, targets)
    if index == 0:
        return ChangeInfo('unknown', 'first-row', None, targets)
    return ChangeInfo('yes', 'new-build', None, targets)


def predecessor(line: Sequence[IndexRow], target: IndexRow, *,
                same_class_only: bool = True) -> tuple[IndexRow | None, tuple[IndexRow, ...]]:
    """The build before ``target``'s bytes first appeared (RK2 s2.3), and the rows between it and ``target``.

    The search starts at the first row of ``target``'s SHA run, so an unchanged file reports the real change and the
    rows where it stayed unchanged become the window. With ``same_class_only`` a Preview, Out-of-band or EXPIRED
    row is not taken as the older side of a standard update (and the reverse); it stays in the window as a
    confounder. The older row is the last row of its own SHA run, so rows with the older bytes never count.
    """
    index = start = line.index(target)
    while start > 0 and line[start - 1].sha256 == target.sha256:
        start -= 1
    anchor_class = line[start].build.heading_class
    for j in range(start - 1, -1, -1):
        row = line[j]
        if same_class_only and row.kb is not None and row.build.heading_class != anchor_class:
            continue
        last = j
        while last + 1 < start and line[last + 1].sha256 == row.sha256:
            last += 1
        return line[last], tuple(line[last + 1:index])
    return None, ()
