"""`engine_evidence` from `secondary.evidence` verdicts (SPEC-28/C6). Engines stay separate; missing is unknown."""
from __future__ import annotations

from typing import Protocol

from pydantic import ValidationError

from ...secondary.evidence import EvidenceAssessment, MatchEvidence
from .. import text
from ..contracts import AlternativeRank, Channel, Engine, EngineEvidence, EvidenceRow
from . import Built, bounded, cap_rows, refuse


class EvidencePort(Protocol):
    def assessment(self) -> EvidenceAssessment | None: ...
    def is_stale(self) -> bool: ...


def _note(limitations: tuple[str, ...], engine: str) -> str:
    for line in limitations:
        if line.startswith(f'{engine}: '):
            return bounded(line, text.CAP_EVIDENCE)[0]
    return ''


def _n(value: str) -> str:
    return bounded(value, text.CAP_NAME)[0]


def _channels(row: MatchEvidence) -> list[Channel]:
    """Ghidriff is the base pairing; `missing` merges absent and not-comparable, so only an all-not-comparable
    row (verdict `insufficient`) is labelled not_comparable."""
    missing = 'not_comparable' if row.verdict == 'insufficient' else 'absent'
    channels = [Channel(engine='ghidriff', state='present', note='base pairing')]
    channels += [Channel(engine=_n(e), state='present', note='agrees with the Ghidriff endpoints')
                 for e in row.supporting_engines]
    channels += [Channel(engine=_n(e), state='present', note='proposes conflicting endpoints')
                 for e in row.contradicting_engines]
    channels += [Channel(engine=_n(e), state=missing, note=_note(row.limitations, e)) for e in row.missing_engines]
    return channels


def _row(row: MatchEvidence) -> EvidenceRow:
    return EvidenceRow(
        match_id=_n(row.match_id), verdict=row.verdict, tier=row.tier, channels=_channels(row),
        supporting_engines=[_n(e) for e in row.supporting_engines],
        contradicting_engines=[_n(e) for e in row.contradicting_engines],
        missing_engines=[_n(e) for e in row.missing_engines],
        alternative_ranks=[AlternativeRank(engine=_n(e), rank=r) for e, r in row.alternative_ranks],
        limitations=[bounded(line, text.CAP_EVIDENCE)[0] for line in row.limitations],
        ordinal_index=row.evidence_index, explanation=bounded(row.explanation, text.CAP_EVIDENCE)[0])


def _engine(label: str) -> Engine:
    name, _, version = label.partition(' ')
    return Engine(name=_n(name), version=_n(version or 'unknown'))


def build_engine_evidence(port: EvidencePort | None) -> Built | None:
    assessment = None if port is None else port.assessment()
    if assessment is None or not assessment.rows:
        return None
    rows, truncated = cap_rows(list(assessment.rows), text.MAX_EVIDENCE_ROWS, 'engine_evidence')
    try:
        section = EngineEvidence(
            engines=[_engine(label) for label in assessment.engine_versions], rows=[_row(r) for r in rows],
            limitations=[bounded(w, text.CAP_EVIDENCE)[0] for w in assessment.warnings], stale=port.is_stale())
    except ValidationError as exc:
        raise refuse('engine_evidence', exc) from None
    return Built(section, truncated)
