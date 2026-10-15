"""Function descriptors for the `shift` report block (LBL-11; plan s7.1).

Descriptive only: flags are counted and shown, never used to abstain (abstention belongs to a model's OOD rule). Flags:
`size-outside` (a present side's size lies outside the reference range, by default the Tier R 0.1..99.9 percentiles),
`thunk` (taxonomy N2) and `n9` (compiler-generated, taxonomy N9). Quantiles use linear interpolation between order
statistics (the "type 7" definition).
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Protocol

from ..tier_r import contracts as C
from .protocols import TruthLabelLike

SIZE_PERCENTILES = (0.1, 99.9)
QUANTILE_POINTS = (5, 25, 50, 75, 95)
TAXONOMY_FLAGS = {'N2': 'thunk', 'N9': 'n9'}


class LabelDocLike(Protocol):
    lineage: str
    functions: Sequence[TruthLabelLike]


def percentile(values: Sequence[float], p: float) -> float | None:
    """p in [0, 100]; None for no values."""
    if not values:
        return None
    ordered = sorted(values)
    h = (len(ordered) - 1) * p / 100
    lo = math.floor(h)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (h - lo) * (ordered[hi] - ordered[lo])


def quantiles(values: Sequence[float]) -> C.Quantiles:
    q = [percentile(values, p) for p in QUANTILE_POINTS]
    return C.Quantiles(n=len(values), q05=q[0], q25=q[1], q50=q[2], q75=q[3], q95=q[4])


def _sizes(record: TruthLabelLike) -> list[int]:
    return [s for s in (record.old_size, record.new_size) if s is not None]


def reference_size_range(docs: Iterable[LabelDocLike]) -> tuple[float, float] | None:
    sizes = [s for doc in docs for r in doc.functions for s in _sizes(r)]
    if not sizes:
        return None
    return percentile(sizes, SIZE_PERCENTILES[0]), percentile(sizes, SIZE_PERCENTILES[1])


def descriptor_flags(record: TruthLabelLike, size_range: tuple[float, float] | None) -> tuple[str, ...]:
    flags = []
    if size_range is not None and any(not size_range[0] <= s <= size_range[1] for s in _sizes(record)):
        flags.append('size-outside')
    flags += [TAXONOMY_FLAGS[t] for t in ('N2', 'N9') if t in record.taxonomy]
    return tuple(flags)


def shift_block(docs: Sequence[LabelDocLike], size_range: tuple[float, float] | None) -> C.ShiftBlock:
    """Descriptor quantiles and flag shares over every function record of `docs` (one population, e.g. the shift
    lineages); `size_range` comes from the reference population."""
    records = [r for doc in docs for r in doc.functions]
    sizes = [s for r in records for s in _sizes(r)]
    ratios = [r.new_size / r.old_size for r in records
              if r.identity == 'same' and r.old_size and r.new_size is not None]
    flagged = [descriptor_flags(r, size_range) for r in records]
    shares = {name: (sum(name in f for f in flagged) / len(records) if records else 0.0)
              for name in ('size-outside', *TAXONOMY_FLAGS.values())}
    return C.ShiftBlock(descriptors={'function-size': quantiles(sizes), 'size-ratio': quantiles(ratios)},
                        shares=shares, n_lineages=len({doc.lineage for doc in docs}))
