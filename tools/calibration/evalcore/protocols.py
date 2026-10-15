"""Engine-neutral inputs of the scorer (LBL-11; plan s7.1).

Truth is anything shaped like `TruthLabelLike` (a `known-answer-labels/1` `FunctionLabel` is one). An engine's answer for
one pair is reduced to `EnginePairs`: one `EnginePair` per thing the engine said, never a score that is averaged
with another engine's. SPEC-33's Tier W protocol names (`older_rva`, `answer`) are adapted by a wrapper when the Tier W
evaluator is built; this core reads `old_rva`/`new_rva`.

Row meaning:
* `paired`: the engine matched `old_rva` to `new_rva`; `flag` is its changed/material verdict (`None` = abstained on the
  verdict: unknown is not a negative vote). A flagged row carries `order_key`, the sort key of the lead list
  (smaller = more suspicious; equal keys are midrank ties).
* `unpaired`: the engine said this one function has no counterpart (exactly one RVA).
* `abstained`: the engine proposed or left open (candidate / contested / ambiguous) and did not commit.
`implicit_unchanged` is for engines that list only modified functions (Ghidriff): a same-identity truth record the engine
never mentions counts as paired and unflagged, which makes its identity numbers an upper bound.
"""
from __future__ import annotations

import typing
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from ..tier_r import contracts as C

PairIdentity = Literal['paired', 'abstained', 'unpaired']
OrderKey = tuple[int | float | str, ...]
IDENTITIES = typing.get_args(PairIdentity)
ENGINES = typing.get_args(C.Engine)
SYMBOLS = ('hidden', 'visible')


class TruthLabelLike(Protocol):
    name: str
    old_rva: int | None
    new_rva: int | None
    old_size: int | None
    new_size: int | None
    identity: str
    label: str
    taxonomy: tuple[str, ...]


class EngineMatchLike(Protocol):
    old_rva: int | None
    new_rva: int | None


@dataclass(frozen=True)
class EnginePair:
    old_rva: int | None
    new_rva: int | None
    flag: bool | None
    native: float | None = None
    order_key: OrderKey | None = None
    identity: PairIdentity = 'paired'

    def __post_init__(self):
        sides = (self.old_rva is not None) + (self.new_rva is not None)
        if self.identity not in IDENTITIES:
            raise ValueError(f'unknown pair identity {self.identity!r}')
        if (self.identity == 'paired' and sides != 2) or (self.identity == 'unpaired' and sides != 1) \
                or (self.identity == 'abstained' and sides == 0):
            raise ValueError(f'a {self.identity} row has the wrong number of RVAs')
        if self.identity != 'paired' and self.flag is not None:
            raise ValueError('only a paired row carries a verdict')
        if self.flag and self.order_key is None:
            raise ValueError('a flagged row needs its order key')
        if self.order_key is not None and not all(
                isinstance(k, int | float | str) and not isinstance(k, bool) for k in self.order_key):
            raise ValueError('order key parts are numbers or strings')


@dataclass(frozen=True)
class EnginePairs:
    engine: str
    version: str | None
    symbols: str
    pairs: tuple[EnginePair, ...]
    implicit_unchanged: bool = False

    def __post_init__(self):
        if self.engine not in ENGINES:
            raise ValueError(f'unknown engine {self.engine!r}')
        if self.symbols not in SYMBOLS:
            raise ValueError(f'symbols must be one of {SYMBOLS}')


def pairs_from_doc(doc: Mapping) -> EnginePairs:
    """Build `EnginePairs` from its JSON form (fixtures and replays)."""
    rows: Sequence[Mapping] = doc['pairs']
    return EnginePairs(
        doc['engine'], doc.get('version'), doc['symbols'],
        tuple(EnginePair(r['old_rva'], r['new_rva'], r['flag'], r.get('native'),
                         None if r.get('order_key') is None else tuple(r['order_key']), r['identity'])
              for r in rows),
        bool(doc.get('implicit_unchanged', False)))
