"""Pure reconciliation of a secondary match set against Ghidriff matches by address (SPEC-10 §5).

Read-only by construction: it takes Ghidriff matches and returns new records, so it
cannot change Ghidriff records, manual corrections or attention scores. `agreement`
means both engines paired the same endpoints; it is not independent proof.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from ..enrichment.identity import parse_address
from ..models import FunctionMatch
from .contracts import SecondaryMatch, SecondaryMatchSet

Status = Literal['agreement', 'disagreement', 'absent', 'not-comparable']


@dataclass(frozen=True)
class Reconciliation:
    match_id: str
    status: Status
    older_address: int | None
    newer_address: int | None
    secondary: tuple[SecondaryMatch, ...]
    note: str


@dataclass(frozen=True)
class ReconciliationReport:
    engine: str
    engine_version: str
    rows: tuple[Reconciliation, ...]
    secondary_only: tuple[SecondaryMatch, ...]
    limitations: tuple[str, ...]

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in ('agreement', 'disagreement', 'absent', 'not-comparable')}
        for row in self.rows:
            out[row.status] += 1
        return out


def _endpoints(match: FunctionMatch) -> tuple[int | None, int | None] | None:
    if len(match.older) > 1 or len(match.newer) > 1:
        return None
    older = parse_address(match.older[0].address) if match.older else None
    newer = parse_address(match.newer[0].address) if match.newer else None
    if (match.older and older is None) or (match.newer and newer is None):
        return None
    return older, newer


def reconcile(matches: Iterable[FunctionMatch], secondary: SecondaryMatchSet) -> ReconciliationReport:
    by_older: dict[int, list[SecondaryMatch]] = defaultdict(list)
    by_newer: dict[int, list[SecondaryMatch]] = defaultdict(list)
    for record in secondary.matches:
        if record.older_address is not None:
            by_older[record.older_address].append(record)
        if record.newer_address is not None:
            by_newer[record.newer_address].append(record)
    used: set[int] = set()
    rows = []
    for match in matches:
        ends = _endpoints(match)
        if ends is None:
            rows.append(Reconciliation(match.id, 'not-comparable', None, None, (),
                                       'Ghidriff match is many-to-many or has an unparsable address'))
            continue
        older, newer = ends
        related = {id(r): r for r in by_older.get(older, []) + by_newer.get(newer, [])}
        candidates = tuple(related.values())
        used.update(related)
        if not candidates:
            rows.append(Reconciliation(match.id, 'absent', older, newer, (),
                                       f'{secondary.engine} has no record for these addresses'))
        elif all((r.older_address, r.newer_address) == (older, newer) for r in candidates):
            rows.append(Reconciliation(match.id, 'agreement', older, newer, candidates,
                                       f'{secondary.engine} pairs the same endpoints (agreement, not proof)'))
        else:
            rows.append(Reconciliation(match.id, 'disagreement', older, newer, candidates,
                                       f'{secondary.engine} pairs at least one endpoint differently'))
    only = tuple(r for r in secondary.matches if id(r) not in used)
    limitations = secondary.limitations
    if secondary.image_base_subtracted != 'no':
        limitations += (f'Image-base subtraction is {secondary.image_base_subtracted}; '
                        'absent rows may reflect an address-space difference.',)
    return ReconciliationReport(secondary.engine, secondary.engine_version, tuple(rows), only, limitations)
