"""Caller-side inputs of a v2 export: the redaction profile and the prebuilt optional sections (SPEC-50 7.6, 8)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .contracts import (
    Advisory,
    BuildFact,
    EngineEvidence,
    Lead,
    Series,
    Symbols,
    Truncated,
    UnifiedResult,
)

UrlMode = Literal['text', 'defanged', 'removed']


@dataclass(frozen=True)
class RedactionProfile:
    """`share` forces code off, notes off and web addresses defanged; `local` keeps the caller's choices."""
    name: Literal['local', 'share', 'custom'] = 'local'
    urls: UrlMode = 'text'
    include_ordinal_index: bool = False

    @classmethod
    def share(cls, include_ordinal_index: bool = False) -> RedactionProfile:
        return cls('share', 'defanged', include_ordinal_index)

    def effective(self, include_code: bool, include_notes: bool) -> tuple[bool, bool]:
        return (False, False) if self.name == 'share' else (include_code, include_notes)


@dataclass(frozen=True)
class SectionInputs:
    """Sections built by `report2.sections.*` (each `None` when its producer is absent) plus their notes."""
    engine_evidence: EngineEvidence | None = None
    series: Series | None = None
    unified_result: UnifiedResult | None = None
    build_facts: tuple[BuildFact, ...] | None = None
    symbols: Symbols | None = None
    advisories: tuple[Advisory, ...] | None = None
    leads: tuple[Lead, ...] | None = None
    truncated: tuple[Truncated, ...] = ()
    unknowns: tuple[str, ...] = ()
