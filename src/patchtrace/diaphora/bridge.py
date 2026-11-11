"""Read-only reconciliation of a Diaphora match set against Ghidriff matches (SPEC-DA-01 `MatchBridge`). Pure.

Comparison is by exact function endpoints, never by name. A Diaphora row whose EA could not be mapped with
certainty (`address_status != verified-rva`) is `not-comparable`: it is never counted as agreeing. Disagreement
takes priority over agreement for a Ghidriff row, and absence is not a negative vote. Ghidriff records, manual
corrections and attention scores are not touched.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from ..models import FunctionMatch
from ..secondary.reconcile import _endpoints
from .contracts import DiaphoraMatch, DiaphoraMatchSet

Status = Literal['agreement', 'disagreement', 'absent', 'not-comparable']


@dataclass(frozen=True)
class BridgeRow:
    match_id: str
    status: Status
    older_address: int | None
    newer_address: int | None
    diaphora: tuple[DiaphoraMatch, ...]
    note: str


@dataclass(frozen=True)
class BridgeReport:
    rows: tuple[BridgeRow, ...]
    diaphora_only: tuple[DiaphoraMatch, ...]
    limitations: tuple[str, ...]

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(('agreement', 'disagreement', 'absent', 'not-comparable'), 0)
        for row in self.rows:
            out[row.status] += 1
        return out


def reconcile(matches: Iterable[FunctionMatch], diaphora: DiaphoraMatchSet) -> BridgeReport:
    by_older: dict[int, list[DiaphoraMatch]] = defaultdict(list)
    by_newer: dict[int, list[DiaphoraMatch]] = defaultdict(list)
    for record in diaphora.matches:
        by_older[record.older_ea].append(record)
        by_newer[record.newer_ea].append(record)
    used: set[int] = set()
    rows = []
    for match in matches:
        ends = _endpoints(match)
        if ends is None or ends[0] is None or ends[1] is None:
            rows.append(BridgeRow(match.id, 'not-comparable', None, None, (),
                                  'Ghidriff match is one-sided, many-to-many or has an unparsable address'))
            continue
        older, newer = ends
        related = {id(r): r for r in by_older.get(older, []) + by_newer.get(newer, [])}
        candidates = tuple(related.values())
        used.update(related)
        if not candidates:
            rows.append(BridgeRow(match.id, 'absent', older, newer, (), 'Diaphora has no record for these addresses'))
        elif any(r.address_status != 'verified-rva' for r in candidates):
            rows.append(BridgeRow(match.id, 'not-comparable', older, newer, candidates,
                                  'a Diaphora address could not be mapped to a verified RVA'))
        elif all((r.older_ea, r.newer_ea) == (older, newer) for r in candidates):
            rows.append(BridgeRow(match.id, 'agreement', older, newer, candidates,
                                  'Diaphora pairs the same endpoints (agreement, not proof)'))
        else:
            rows.append(BridgeRow(match.id, 'disagreement', older, newer, candidates,
                                  'Diaphora pairs at least one endpoint differently'))
    only = tuple(r for r in diaphora.matches if id(r) not in used)
    return BridgeReport(tuple(rows), only, (*diaphora.limitations,
                                            'Addresses are compared as virtual addresses; a rebased Ghidra or IDA '
                                            'database appears as absent or not-comparable, not as agreement.'))
