"""`leads` (FAB): every lead lists its independent channels and never a combined number."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import ValidationError

from .. import text
from ..contracts import Lead
from . import Built, bounded, refuse


@dataclass(frozen=True)
class LeadRecord:
    lead_id: str
    kind: str
    channels: tuple[str, ...]
    statement: str
    evidence_ids: tuple[str, ...] = ()


class LeadsPort(Protocol):
    def leads(self) -> Sequence[LeadRecord]: ...


def build_leads(port: LeadsPort | None) -> Built | None:
    records = [] if port is None else list(port.leads())
    if not records:
        return None
    try:
        leads = tuple(Lead(
            lead_id=bounded(r.lead_id, text.CAP_NAME)[0], kind=bounded(r.kind, text.CAP_NAME)[0],
            channels=[bounded(c, text.CAP_NAME)[0] for c in r.channels],
            statement=bounded(r.statement, text.CAP_EVIDENCE)[0],
            evidence_ids=[bounded(e, text.CAP_NAME)[0] for e in r.evidence_ids]) for r in records)
    except ValidationError as exc:
        raise refuse('leads', exc) from None
    return Built(leads)
