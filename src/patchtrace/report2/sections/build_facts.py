"""`build_facts` (SPEC-26 D2): observed-in-file facts from a closed list; timestamps are claims."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import ValidationError

from .. import text
from ..contracts import BuildFact
from . import Built, bounded, cap_rows, refuse


@dataclass(frozen=True)
class FactRecord:
    side: str
    fact: str
    value: str
    source: str


class BuildFactsPort(Protocol):
    def facts(self) -> Sequence[FactRecord]: ...


def build_build_facts(port: BuildFactsPort | None) -> Built | None:
    records = [] if port is None else list(port.facts())
    if not records:
        return None
    records, truncated = cap_rows(records, text.MAX_BUILD_FACTS, 'build_facts')
    facts = []
    try:
        for record in records:
            value, cut = bounded(record.value, text.CAP_NAME)
            facts.append(BuildFact(side=record.side, fact=record.fact, value=value, truncated=cut,
                                   source=bounded(record.source, text.CAP_NAME)[0]))
    except ValidationError as exc:
        raise refuse('build_facts', exc) from None
    return Built(tuple(facts), truncated)
