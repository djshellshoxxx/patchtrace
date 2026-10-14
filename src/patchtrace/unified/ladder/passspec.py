"""The data record of one ladder pass (SPEC-31 04 s4), kept apart from the pass table so that `state` (which indexes
passes by id and builds their key tables) and `passes` (whose guards and hooks work on the `State`) do not import
each other: `passspec` is a leaf below both. `PassSpec` is re-exported by `ladder.passes`.

A pass is data: `keys(side, limits)` returns one hashable key (or None) per function; the engine owns uniqueness.
`guard(state, older_fid, newer_fid, key)` may veto a unique pair (None) or cap its tier (`Verdict`); `run(state,
round)` replaces the key mechanics for passes that are not "bucket by key" (P15, and the residual passes of slice
S5). Both hooks receive the ladder `State`; they are typed loosely on purpose (a typed `State` here would be the
import cycle this module exists to remove).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

from ..limits import UnifiedLimits
from .side import SideData


class Verdict(NamedTuple):
    """A guard's answer for a pair whose key was unique on both sides: the tier cap and hints for the pair."""
    tier: str
    hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class PassSpec:
    id: str
    name: str
    stage: int                     # T0 = 0 (P00-P03), T1 = 1 (P04-P05), T2 = 2 (P06-P11), T3 = 3 (P12-P14), P15 = 4
    tier: str
    family: str                    # family when the bytes family does not apply (04 s4, 05 s1.1)
    cls: str                       # evidence class (05 s1.1)
    keys: Callable[[SideData, UnifiedLimits], list] | None = None
    guard: Callable[..., Verdict | None] | None = None      # (State, older fid, newer fid, key) -> Verdict | None
    hubs: bool = False             # may match hubs (fan-in > L-17): only P01-P05 may
    neighbour: bool = False        # evaluated inside neighbour sets by propagation (P04-P14)
    bytes_family: bool = False     # F-PT-BYTES when both functions are .pdata-confirmed
    run: Callable[..., None] | None = None                   # (State, round) -> None

    @property
    def step(self) -> str:
        return f'{self.id}-{self.name}'
