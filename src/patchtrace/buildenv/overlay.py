"""View-layer overlay for unified rows (DIE plan s7, slice D6 pure part). Pure: no Qt, no I/O.

Composes `noise_map` for one pair: tags, display order and the summary line. It never touches a verdict,
`result_key` or a stored result and never hides a row. A delta for another pair, another orientation or one
that is not comparable yields no tags, so stale evidence cannot mark rows.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from .contracts import BuildEnvDelta, Effect
from .copy import ROW_CHIP, ROW_CHIP_DETAIL, SUMMARY_TEXT
from .noise_map import RowFacts, order_rows, summary_counts, tag_rows


@dataclass(frozen=True, slots=True)
class RowOverlay:
    tags: Mapping[str, Effect]  # row_id -> effect; absent means untagged
    order: tuple[str, ...]  # every input row id exactly once
    tagged: int  # tagged review rows
    review: int  # review rows

    @property
    def active(self) -> bool:
        return bool(self.tags)

    @property
    def summary(self) -> str:
        return SUMMARY_TEXT.format(n=self.tagged, total=self.review) if self.tags else ''

    def chip(self, row_id: str) -> str:
        """The precomputed `build_tag` text for a row; empty when untagged."""
        return ROW_CHIP if row_id in self.tags else ''


def _matches(delta: BuildEnvDelta | None, older_sha256: str, newer_sha256: str) -> bool:
    return (delta is not None and delta.comparable and delta.orientation == 'older->newer'
            and (delta.older_sha256, delta.newer_sha256) == (older_sha256, newer_sha256))


def build_overlay(rows: Sequence[RowFacts], delta: BuildEnvDelta | None, *, older_sha256: str, newer_sha256: str,
                  group_tagged_last: bool = False) -> RowOverlay:
    """Tags, order and counts for `rows` (in engine order); a pure function of its inputs."""
    tags = tag_rows(rows, delta.toolchain) if delta is not None and _matches(delta, older_sha256, newer_sha256) \
        else {}
    order = (order_rows(rows, tags, group_tagged_last=group_tagged_last) if tags
             else [row.row_id for row in rows])
    tagged, review = summary_counts(rows, tags)
    return RowOverlay(MappingProxyType(tags), tuple(order), tagged, review)


def chip_detail(row: RowFacts) -> str:
    """Tooltip text for a tagged row, built on demand from its change classes."""
    return ROW_CHIP_DETAIL.format(classes=', '.join(sorted(set(row.classes))))
