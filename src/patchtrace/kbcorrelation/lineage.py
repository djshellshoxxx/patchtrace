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
from datetime import UTC, datetime
from typing import Literal

from .contracts import Arch, Availability, BuildRow
from .ids import is_canonical_kb, kb_sort_key

MACHINES: dict[int, Arch] = {0x8664: 'amd64', 0xAA64: 'arm64', 0x14C: 'x86'}
Change = Literal['yes', 'no', 'unknown']

_SHA = re.compile(r'[0-9a-f]{64}')
# ASCII digits only: Python's \d also matches other scripts' digits (issue #105 BUG-KBC-7).
_DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
_UBR = re.compile(r'([0-9]{1,6})\.([0-9]{1,6})')
_BUILD_IN_TEXT = re.compile(r'(?<![0-9.])[0-9]{1,6}\.[0-9]{1,6}(?![0-9.])')
_FILE_VERSION = re.compile(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}')
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
    """``reason`` is no-row, variants, first-row, order-unverified, new-build or unchanged."""
    state: Change
    reason: str
    last_changed_in: str | None = None
    target_rows: tuple[IndexRow, ...] = ()


def ubr_key(text: str | None) -> tuple[int, int]:
    match = _UBR.fullmatch(text or '')
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _release_instant(text: str | None) -> str | None:
    """Sortable UTC timestamp with all nine allowed fractional digits; invalid evidence has no ordering value."""
    if text is None:
        return None
    try:
        # fromisoformat normalizes an offset such as +00:99; that is not a valid source timestamp.
        if text[-6:-5] in ('+', '-') and int(text[-2:]) > 59:
            return None
        value = datetime.fromisoformat(text)
        if value.tzinfo is None:
            return None
        utc = value.astimezone(UTC).isoformat(timespec='microseconds')
        fraction = re.search(r'\.([0-9]{1,9})', text)
        residue = (fraction[1][6:] if fraction else '').ljust(3, '0')
        return utc[:-6] + residue + '+00:00'  # datetime alone truncates the final three digits
    except (ValueError, OverflowError):
        return None


def order_key(row: IndexRow) -> tuple:
    """Stable display order: valid UTC date, then UBR; absent dates never prove chronology."""
    build = row.build
    instant = _release_instant(build.release_date)
    return (instant or '',
            ubr_key(build.release_version), build.kb is not None,
            kb_sort_key(build.kb) if build.kb else (0, ''), build.sha256)


def chronologically_before(older: IndexRow, newer: IndexRow) -> bool:
    """Whether stated source dates/builds establish order, without display-key defaults."""
    return _before(_source_order(older), _source_order(newer))


def _source_order(row: IndexRow) -> tuple[str, str | None, tuple[int, int] | None]:
    build = row.build
    return (build.version_key, _release_instant(build.release_date),
            ubr_key(build.release_version) if _UBR.fullmatch(build.release_version or '') else None)


def _before(old: tuple, new: tuple) -> bool:
    old_key, old_date, old_build = old
    new_key, new_date, new_build = new
    if old_key != new_key or old_date is None or new_date is None:
        return False
    if old_date != new_date:
        return old_date < new_date
    return (old_build is not None and new_build is not None and old_build[0] == new_build[0]
            and old_build < new_build)


class LineageOrder:
    """Per-calculation chronology facts and display positions; no global cache of untrusted source rows."""

    def __init__(self, line: Sequence[IndexRow]):
        self._facts = {id(row): _source_order(row) for row in line}
        self._positions = {id(row): position for position, row in enumerate(line)}

    def before(self, older: IndexRow, newer: IndexRow) -> bool:
        return _before(self._facts[id(older)], self._facts[id(newer)])

    def position(self, row: IndexRow) -> int:
        return self._positions[id(row)]


def _unordered_rows(line: Sequence[IndexRow], target: IndexRow, order: LineageOrder) -> tuple[IndexRow, ...]:
    """Observations which display tie-breakers cannot place before or after the target."""
    return tuple(row for row in line if row is not target and row.build.version_key == target.build.version_key
                 and not order.before(row, target) and not order.before(target, row)
                 and (row.sha256 != target.sha256 or row.kb != target.kb or row != target))


def _availability(download: object, variant: str) -> Availability:
    if download in ('direct', 'candidates'):
        return download  # type: ignore[return-value]
    return 'delta-only' if variant in _DELTA_VARIANTS else 'unavailable'


def _timestamp(date: object) -> str | None:
    if not isinstance(date, str) or not _DATE.fullmatch(date):
        return None
    stamp = f'{date}T00:00:00Z'
    return stamp if _release_instant(stamp) is not None else None


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
    others = item.get('other_versions', ())
    if not isinstance(others, (list, tuple)) or any(not isinstance(other, str) or not other for other in others):
        return
    for version_key, shared_from in [(key, None)] + [(other, key) for other in others]:
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


def change_in_kb(line: Sequence[IndexRow], kb: str, *, order: LineageOrder | None = None) -> ChangeInfo:
    """Did the file change in ``kb`` (an index claim for one version key; ``line`` is a :func:`timeline`)."""
    targets = tuple(r for r in line if r.kb == kb)
    if not targets:
        return ChangeInfo('unknown', 'no-row')
    if len({r.sha256 for r in targets}) > 1:
        return ChangeInfo('unknown', 'variants', None, targets)  # several SHAs for one KB: never auto-pick
    order = order or LineageOrder(line)
    index = line.index(targets[0])
    target = targets[0]
    if _release_instant(target.build.release_date) is None or _unordered_rows(line, target, order):
        return ChangeInfo('unknown', 'order-unverified', None, targets)
    if index > 0 and not order.before(line[index - 1], target):
        return ChangeInfo('unknown', 'order-unverified', None, targets)
    start = index
    while start > 0 and line[start - 1].sha256 == targets[0].sha256:
        start -= 1
    # Check both sides of the run frontier: a peer sorted before or after it may disagree on whether these bytes
    # already existed. Display order must not turn the same observations into either a new or unchanged claim.
    for row in line[max(0, start - 1):start + 1]:
        same_content = {peer.sha256 == target.sha256 for peer in (row, *_unordered_rows(line, row, order))}
        if len(same_content) > 1:
            return ChangeInfo('unknown', 'order-unverified', None, targets)
    if start < index:
        if any(not order.before(line[i], line[i + 1]) for i in range(start, index)):
            return ChangeInfo('unknown', 'order-unverified', None, targets)
        return ChangeInfo('no', 'unchanged', line[start].kb, targets)
    if index == 0:
        return ChangeInfo('unknown', 'first-row', None, targets)
    return ChangeInfo('yes', 'new-build', None, targets)


def predecessor(line: Sequence[IndexRow], target: IndexRow, *,
                same_class_only: bool = True, order: LineageOrder | None = None
                ) -> tuple[IndexRow | None, tuple[IndexRow, ...]]:
    """The build before ``target``'s bytes first appeared (RK2 s2.3), and the rows between it and ``target``.

    The search starts at the first row of ``target``'s SHA run, so an unchanged file reports the real change and the
    rows where it stayed unchanged become the window. With ``same_class_only`` a Preview, Out-of-band or EXPIRED
    row is not taken as the older side of a standard update (and the reverse); it stays in the window as a
    confounder. The older row is the last row of its own SHA run, so rows with the older bytes never count.

    The older row never carries ``target``'s own bytes (spec 31-C C4, audit KBA-06): when a build reverted across a
    row of another class, the earlier rows with those bytes are passed over and stay in the window, and the nearest
    earlier build with other bytes is returned. No such build is ``(None, ())``, never a byte-identical pair.

    Unordered peers cannot become predecessors merely by KB/hash order. They stay in the confounding window.
    If no established predecessor exists, preserve the display-derived proposal for its grade-X diagnostic.
    """
    # Keep the public value-based target contract while the local cache uses row identities.
    target = line[line.index(target)]
    order = order or LineageOrder(line)
    eligible = tuple(row for row in line if row == target or order.before(row, target))
    older, between = _display_predecessor(eligible, target, same_class_only=same_class_only)
    if older is None:
        older, between = _display_predecessor(line, target, same_class_only=same_class_only)
    if older is None:
        return None, ()
    included = {id(row) for row in (older, target, *between)}
    unplaced = {id(row): row for endpoint in (older, target) for row in _unordered_rows(line, endpoint, order)
                if id(row) not in included}
    return older, tuple(sorted((*between, *unplaced.values()), key=order.position))


def _display_predecessor(line: Sequence[IndexRow], target: IndexRow, *,
                         same_class_only: bool) -> tuple[IndexRow | None, tuple[IndexRow, ...]]:
    index = start = line.index(target)
    while start > 0 and line[start - 1].sha256 == target.sha256:
        start -= 1
    anchor_class = line[start].build.heading_class
    for j in range(start - 1, -1, -1):
        row = line[j]
        if row.sha256 == target.sha256:
            continue
        if same_class_only and row.kb is not None and row.build.heading_class != anchor_class:
            continue
        last = j
        while last + 1 < start and line[last + 1].sha256 == row.sha256:
            last += 1
        return line[last], tuple(line[last + 1:index])
    return None, ()
