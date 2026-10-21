"""Engine-neutral run results and the reduction of production adapter output to RVAs (LBL-11; plan s7.1).

An `EngineOutput` is what one engine said about one pair, in RVAs. A missing tool, import or image is `blocked` with its
reason, an engine error is `failed`: never a silent skip and never a zero score. `to_engine_pairs` is the scorer's view.
"""
from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from patchtrace.secondary.contracts import SecondaryMatchSet

from ...tier_r import contracts as C
from .. import protocols as EP


@dataclass(frozen=True)
class Prediction:
    old_rva: int
    new_rva: int
    changed: bool
    similarity_milli: int | None = None
    old_name: str | None = None
    new_name: str | None = None
    order_key: tuple | None = None               # lead-list sort key; default (similarity, name), smaller first


@dataclass(frozen=True)
class EngineOutput:
    engine: str
    status: str                                  # ok | blocked | failed
    version: str | None = None
    reason: str | None = None
    predictions: tuple[Prediction, ...] = ()
    old_only: frozenset[int] = frozenset()       # old functions the engine reports without a counterpart
    new_only: frozenset[int] = frozenset()
    implicit_unchanged: bool = False
    ignored_unaddressed: int = 0


def _choice_key(p: Prediction) -> tuple:
    """Total order over the duplicates of one (old, new): higher native similarity first (unknown last), then the
    unflagged one (an engine that does not consistently claim a change does not get a flag), then names, order key."""
    return (-1 if p.similarity_milli is None else 0, -(p.similarity_milli or 0), p.changed, p.old_name or '',
            p.new_name or '', repr(p.order_key))


def dedupe_predictions(predictions) -> tuple[list[Prediction], int]:
    """(one prediction per (old, new) in a provider-order-independent choice, number of dropped duplicates) (D-09)."""
    groups: dict[tuple[int, int], list[Prediction]] = {}
    for p in predictions:
        groups.setdefault((p.old_rva, p.new_rva), []).append(p)
    kept = [min(groups[k], key=_choice_key) for k in sorted(groups)]
    return kept, sum(len(v) - 1 for v in groups.values())


def blocked(engine: str, reason: str) -> EngineOutput:
    return EngineOutput(engine, 'blocked', reason=clean(reason))


def failed(engine: str, reason: str) -> EngineOutput:
    return EngineOutput(engine, 'failed', reason=clean(reason))


def clean(text: str, limit: int = 400) -> str:
    return re.sub(r'[\x00-\x1f\x7f]+', ' ', str(text)).strip()[:limit]


class Provider(Protocol):
    engine: str

    def __call__(self, labels: C.KnownAnswerLabels, symbols: str) -> EngineOutput: ...


class StaticProvider:
    """Pre-computed output per pair id (tests and replays); a pair without an entry is blocked."""

    def __init__(self, engine: str, outputs: Mapping[str, EngineOutput]):
        self.engine, self.outputs = engine, dict(outputs)

    def __call__(self, labels, symbols):
        return self.outputs.get(labels.pair_id) or blocked(self.engine, f'no recorded output for {labels.pair_id}')


def to_rva(address: int, image_base: int) -> int:
    """Engines report virtual addresses (BinExport, rizin, Ghidra) or already-relative ones: subtract the base once."""
    return address - image_base if address >= image_base else address


def from_match_set(engine: str, match_set: SecondaryMatchSet, image_base: int) -> EngineOutput:
    base = 0 if match_set.image_base_subtracted == 'yes' else image_base
    predictions, old_only, new_only = [], set(), set()
    for m in match_set.matches:
        if m.older_address is None or m.newer_address is None:
            (old_only if m.newer_address is None else new_only).add(
                to_rva(m.older_address if m.newer_address is None else m.newer_address, base))
            continue
        changed = m.similarity_milli < 1000
        if engine == 'rz-diff':
            changed = changed or m.match_type != 'COMPLETE'
        predictions.append(Prediction(to_rva(m.older_address, base), to_rva(m.newer_address, base), changed,
                                      m.similarity_milli, m.older_name, m.newer_name))
    return EngineOutput(engine, 'ok', version=match_set.engine_version, predictions=tuple(predictions),
                        old_only=frozenset(old_only), new_only=frozenset(new_only))


def to_engine_pairs(out: EngineOutput, symbols: str) -> EP.EnginePairs:
    """The scorer-neutral view of one engine run. Flagged rows are ordered by ascending native similarity, then
    name (an unknown similarity sorts last), unless the output carries its own `order_key` (attention, unified)."""
    rows = []
    for p in dedupe_predictions(out.predictions)[0]:
        key = None
        if p.changed:
            sim = math.inf if p.similarity_milli is None else p.similarity_milli
            key = p.order_key or (sim, p.old_name or p.new_name or '')
        rows.append(EP.EnginePair(p.old_rva, p.new_rva, p.changed,
                                  None if p.similarity_milli is None else p.similarity_milli / 1000, key))
    rows += [EP.EnginePair(rva, None, None, identity='unpaired') for rva in sorted(out.old_only)]
    rows += [EP.EnginePair(None, rva, None, identity='unpaired') for rva in sorted(out.new_only)]
    return EP.EnginePairs(out.engine, out.version, symbols, tuple(rows), out.implicit_unchanged)
