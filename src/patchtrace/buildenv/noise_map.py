"""`noise-map/1`: which change classes a toolchain difference can explain (DIE plan s7). View data only.

The map never touches a verdict, `result_key` or a stored result, and it never hides a row. A row qualifies only
when its verdict is `review`, every delta class is in the map, no delta was omitted, no limit was hit and the
toolchain differs for the same pair. Ordering is a stable partition inside each materiality group.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .contracts import Effect, NoiseReason, ToolchainVerdict
from .copy import NOISE_WHY

ORDER_CLASSES = ('eh', 'frame', 'register-only', 'address-only', 'layout-only', 'size-only', 'refcount-only',
                 'name-only')
TAG_CLASSES = ('cfg', 'block-added', 'block-removed')
NEVER_CLASSES = ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
                 'struct-offset', 'string', 'unknown')
NOISE_MAP: dict[str, Effect] = {**dict.fromkeys(ORDER_CLASSES, 'order'), **dict.fromkeys(TAG_CLASSES, 'tag')}


@dataclass(frozen=True, slots=True)
class RowFacts:
    """The slice of a unified row the map reads."""
    row_id: str
    group: str  # materiality group; rows never cross it
    verdict: str
    classes: tuple[str, ...]
    deltas_omitted: int = 0
    limits_hit: tuple[str, ...] = ()


def row_effect(row: RowFacts, toolchain: ToolchainVerdict) -> Effect | None:
    """None when the row does not qualify; a mixed row takes the weakest effect (`tag`)."""
    if (toolchain != 'differs' or row.verdict != 'review' or not row.classes or row.deltas_omitted
            or row.limits_hit):
        return None
    effects = {NOISE_MAP.get(cls) for cls in row.classes}
    if None in effects:
        return None
    return 'tag' if 'tag' in effects else 'order'


def tag_rows(rows: Sequence[RowFacts], toolchain: ToolchainVerdict) -> dict[str, Effect]:
    return {row.row_id: effect for row in rows if (effect := row_effect(row, toolchain)) is not None}


def order_rows(rows: Sequence[RowFacts], tags: dict[str, Effect], *, group_tagged_last: bool = False) -> list[str]:
    """Row ids in display order: engine order, except that moved rows go after the others of their group."""
    moved = {'order', 'tag'} if group_tagged_last else {'order'}
    groups: dict[str, tuple[list[str], list[str]]] = {}
    for row in rows:
        keep, late = groups.setdefault(row.group, ([], []))
        (late if tags.get(row.row_id) in moved else keep).append(row.row_id)
    return [row_id for keep, late in groups.values() for row_id in (*keep, *late)]


def summary_counts(rows: Sequence[RowFacts], tags: dict[str, Effect]) -> tuple[int, int]:
    """(tagged review rows, review rows)."""
    review = [row for row in rows if row.verdict == 'review']
    return sum(1 for row in review if row.row_id in tags), len(review)


def noise_reasons(toolchain: ToolchainVerdict) -> tuple[NoiseReason, ...]:
    if toolchain != 'differs':
        return ()
    return tuple(NoiseReason(code='toolchain-differs', classes=classes, effect=effect, why=NOISE_WHY[effect])
                 for effect, classes in (('order', ORDER_CLASSES), ('tag', TAG_CLASSES)))
