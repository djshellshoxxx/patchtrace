"""One pair project's contribution to the N-way evolution: stored callee sets and the 1:1 callee map (A7)."""
from __future__ import annotations

from typing import Literal, NamedTuple

from .contracts import Side
from .pairing import PairMap
from .project_input import ProjectInput

Direction = Literal['forward', 'backward']
Status = Literal['mapped', 'gone', 'unknown']


class Step(NamedTuple):
    label: str | None
    status: Status


class PairCalls:
    """Read-only view over the current run of one adjacent pair (k, k+1). Holds no project handle."""

    def __init__(self, data: ProjectInput) -> None:
        self._map = PairMap(data)
        self._records: dict[tuple[Side, str], list[tuple[str, ...]]] = {}
        for entry in data.entries:
            if not entry.external:
                self._records.setdefault((entry.side, entry.label), []).append(entry.callees)
        self.has_raw_matches = data.raw.matches is not None

    def callees(self, side: Side, label: str) -> frozenset[str] | None:
        """Stored callee labels of the function's record; None when there is no record or the label is
        ambiguous (an absent record is unknown, never an empty set)."""
        records = self._records.get((side, label), [])
        return frozenset(records[0]) if len(records) == 1 else None

    def step(self, direction: Direction, label: str) -> Step:
        """Where a callee label of one build goes in the adjacent build. Only a 1:1 pair that both ends
        agree on is followed; a removed or added callee is `gone`; everything else is `unknown`."""
        side, other = ('older', 'newer') if direction == 'forward' else ('newer', 'older')
        pairing = self._map.partner(side, label)
        if pairing.kind in {'removed', 'added'}:
            return Step(None, 'gone')
        if pairing.kind != 'one' or pairing.inferred:
            return Step(None, 'unknown')
        partner = pairing.partners[0]
        back = self._map.partner(other, partner)
        if back.kind != 'one' or back.partners != (label,):
            return Step(None, 'unknown')
        return Step(partner, 'mapped')
