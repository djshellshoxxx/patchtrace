"""Shared pack result and lineage-interval helpers (LBL-13). Pair-level values are macro-averaged inside ONE pack."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..evalcore import boot

STATUSES = ('ok', 'blocked', 'not-run')
EMPTY = {'point': None, 'lo': None, 'hi': None, 'n': 0, 'anti_conservative': True, 'undefined': 0}


@dataclass(frozen=True)
class PackReport:
    pack: str
    status: str
    reason: str | None = None
    pairs: int = 0
    lineages: int = 0
    metrics: dict = field(default_factory=dict)  # name -> interval dict (see `interval`)
    counts: dict = field(default_factory=dict)  # name -> int (exact tallies, no interval)
    gate: dict = field(default_factory=dict)  # name -> True / False / None (None = undefined, not a failure)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f'unknown pack status {self.status!r}')


def ratio(num: float, den: float) -> float | None:
    return num / den if den else None


def observations[T](rows: Iterable[T], value: Callable[[T], float | None]) -> boot.Obs:
    """pair id -> (lineage, value); rows whose value is None (unknown / undefined) are left out, not zeroed."""
    out = {}
    for r in rows:
        v = value(r)
        if v is not None:
            out[r.pair_id] = (r.lineage, float(v))
    return out


def interval(obs: boot.Obs, pack: str, name: str, b_count: int = boot.B_COUNT) -> dict:
    if not obs:
        return dict(EMPTY)
    iv = boot.lineage_bootstrap(obs, b_count, seed=f'channels:{pack}:{name}')
    return {'point': iv.point, 'lo': iv.lo, 'hi': iv.hi, 'n': len(obs), 'anti_conservative': iv.anti_conservative,
            'undefined': iv.undefined}


def lineage_count(rows: Iterable) -> int:
    return len({r.lineage for r in rows})
