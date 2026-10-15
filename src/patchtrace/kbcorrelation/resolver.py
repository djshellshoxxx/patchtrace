"""Pair candidates from file-index rows (KB-integration-plan 3.1, 7.2 pair rules; RK2 s2.3; slice K5). Pure.

Index rows are claims, so a proposal carries ``bytes_state=pending``: grade A is the best it can reach (no hard
block, older row is the preceding distinct-SHA row of the same version key). Anything that would let an unverified
pair look better is a hard block and grade X: another product, another architecture, a reversed order, identical
content, a delta-only side. A wider window (rows between the two builds) stays grade A but is named
``WINDOW_CONFOUNDED`` and sorts after the adjacent pairs. The contract allows grade B only for verified bytes.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .contracts import HARD_BLOCKS, BinaryRef, FixBoundary, PairProposal, ProductScope, domain_id
from .ids import is_canonical_kb
from .limits import DEFAULT_LIMITS
from .lineage import ChangeInfo, IndexRow, change_in_kb, order_key, predecessor, timeline, ubr_key
from .pairs import SUPPORTED_ARCH, reason_text

_UBR = re.compile(r'[0-9]{1,6}\.[0-9]{1,6}')
_CHANGED_ORDER = {'yes': 0, 'unknown': 1, 'no': 2}
_AVAILABILITY_ORDER = {'local': 0, 'direct': 1, 'candidates': 2, 'delta-only': 3, 'unavailable': 4}
NOT_IN_INDEX = 'Not in the file index (Windows 10/11 client x64 only).'
NO_KEY = 'No file-index key is known for this product.'


@dataclass(frozen=True)
class Resolution:
    """Candidate pairs for one file and one KB. No pair and a blocker means the index cannot answer, not "no change"."""
    kb: str
    file_name: str
    scope_id: str
    version_key: str | None
    changed_in_kb: str
    last_changed_in: str | None
    pairs: tuple[PairProposal, ...]
    blockers: tuple[str, ...]
    note: str
    skipped_rows: int
    truncated: bool = False


def binary_ref(row: IndexRow) -> BinaryRef:
    build = row.build
    return BinaryRef(sha256=build.sha256, size=row.size, basename=build.file_name, machine=row.machine,
                     file_version=row.file_version, build_ubr=build.release_version, origin='index-row',
                     availability=row.availability, authenticity='signature-unknown')


def fix_boundary(older: IndexRow, newer: IndexRow, fixed_build: str | None,
                 intervening: Sequence[IndexRow]) -> FixBoundary:
    """Compare only with a build stated by the row itself (UBR or heading), never file version or timestamp."""
    if fixed_build is None or not _UBR.fullmatch(fixed_build):
        return 'unverified'
    if fixed_build in _builds(newer) and not intervening:
        return 'source-supported'
    major = fixed_build.split('.')[0]
    older_same = [b for b in _builds(older) if b.split('.')[0] == major]  # a sibling's prefix proves nothing
    if older_same and all(ubr_key(b) >= ubr_key(fixed_build) for b in older_same):
        return 'contradicted'
    return 'unverified'


def _builds(row: IndexRow) -> set[str]:
    own = {row.build.release_version} if row.build.release_version else set()
    return own | set(row.heading_builds)


def _reasons(older: IndexRow, newer: IndexRow, intervening: Sequence[IndexRow], skipped_rows: int) -> set[str]:
    reasons: set[str] = set()
    if older.sha256 == newer.sha256:
        reasons.add('IDENTICAL_CONTENT')
    if SUPPORTED_ARCH != older.machine or SUPPORTED_ARCH != newer.machine:
        reasons.add('ARCH')
    if older.build.version_key != newer.build.version_key:
        reasons.add('CROSS_PRODUCT')
    if order_key(older) >= order_key(newer):
        reasons.add('ORDER_UNVERIFIED')
    if {older.availability, newer.availability} & {'delta-only', 'unavailable'}:
        reasons.add('DELTA_ONLY')
    if intervening:
        reasons.add('WINDOW_CONFOUNDED')
    if skipped_rows or any(r.build.release_date is None for r in (older, newer, *intervening)):
        reasons.add('INDEX_GAP')
    return reasons


def propose_index_pair(older: IndexRow, newer: IndexRow, *, scope_id: str, intervening: Sequence[IndexRow] = (),
                       fixed_build: str | None = None, skipped_rows: int = 0, tier: str = 'C') -> PairProposal:
    """Grade two index rows. Never raises for a bad pair: the block is the grade and its reason codes."""
    reasons = _reasons(older, newer, intervening, skipped_rows)
    incompatible = bool({'CROSS_PRODUCT', 'ORDER_UNVERIFIED'} & reasons)
    blocked = incompatible or bool(HARD_BLOCKS & reasons)
    window = tuple(sorted({r.kb for r in intervening if r.kb}))
    window_id = f'index:{newer.build.version_key}:{newer.kb or "BASE"}'
    key = {'older': older.sha256, 'newer': newer.sha256, 'scope_id': scope_id, 'window_id': window_id}
    return PairProposal(
        pair_id=domain_id('kbc.pair', 1, key), older=binary_ref(older), newer=binary_ref(newer), scope_id=scope_id,
        window_id=window_id, bytes_state='incompatible' if 'ARCH' in reasons else 'pending',
        lineage_state='incompatible' if incompatible else 'index-adjacent',
        fix_boundary='unverified' if blocked else fix_boundary(older, newer, fixed_build, intervening),
        window=window, window_complete=None, reason_codes=tuple(sorted(reasons)), grade='X' if blocked else 'A',
        tier=tier)  # type: ignore[arg-type]


def rank_key(pair: PairProposal, changed_in_kb: str = 'unknown') -> tuple:
    """Lexicographic, never arithmetic (plan 3.1): blocked last, changed yes<unknown<no, grade, tier, intervening
    updates, availability, then names and SHAs so equal candidates have one stable order."""
    worst = max(_AVAILABILITY_ORDER[pair.older.availability], _AVAILABILITY_ORDER[pair.newer.availability])
    return (pair.grade == 'X', _CHANGED_ORDER[changed_in_kb], pair.grade, pair.tier, len(pair.window), worst,
            pair.newer.basename, pair.older.sha256, pair.newer.sha256)


def _empty(kb: str, file_name: str, scope: ProductScope, key: str | None, blockers: tuple[str, ...], note: str,
           skipped_rows: int) -> Resolution:
    return Resolution(kb, file_name, scope.scope_id, key, 'unknown', None, (), blockers, note, skipped_rows)


def resolve(rows: Sequence[IndexRow], *, kb: str, scope: ProductScope, file_name: str, fixed_build: str | None = None,
            skipped_rows: int = 0, same_class_only: bool = True, tier: str = 'C',
            limit: int = DEFAULT_LIMITS.pairs_per_file) -> Resolution:
    """Candidate pairs for ``kb`` in ``scope``. An index that cannot answer says why instead of returning nothing."""
    if not is_canonical_kb(kb):
        raise ValueError('kb must be a canonical KB id')
    if scope.family == 'windows-server':
        return _empty(kb, file_name, scope, scope.winbindex_key, ('SERVER_NOT_COVERED',),
                      reason_text('SERVER_NOT_COVERED'), skipped_rows)
    if scope.winbindex_key is None:
        return _empty(kb, file_name, scope, None, ('NO_NEWER',), NO_KEY, skipped_rows)
    line = timeline((r for r in rows if r.build.file_name == file_name), scope.winbindex_key)
    change: ChangeInfo = change_in_kb(line, kb)
    if not change.target_rows:
        return _empty(kb, file_name, scope, scope.winbindex_key, ('NO_NEWER',), NOT_IN_INDEX, skipped_rows)
    pairs: dict[str, PairProposal] = {}
    for target in {r.sha256: r for r in reversed(change.target_rows)}.values():
        older, between = predecessor(line, target, same_class_only=same_class_only)
        if older is not None:
            pair = propose_index_pair(older, target, scope_id=scope.scope_id, intervening=between,
                                      fixed_build=fixed_build, skipped_rows=skipped_rows, tier=tier)
            pairs.setdefault(pair.pair_id, pair)
    ordered = sorted(pairs.values(), key=lambda p: rank_key(p, change.state))
    blockers = () if ordered else ('NO_OLDER',)
    return Resolution(kb, file_name, scope.scope_id, scope.winbindex_key, change.state, change.last_changed_in,
                      tuple(ordered[:limit]), blockers, '' if ordered else reason_text('NO_OLDER'), skipped_rows,
                      len(ordered) > limit)
