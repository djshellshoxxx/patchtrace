"""Conservative cross-engine evidence adjudication.

Scores are *ordinal evidence-strength indices*, NOT calibrated probabilities that
a vulnerability exists or that a function correspondence is correct. Absence,
non-comparability and correlated tools must not be scored as affirmative votes.
This pure module consumes reconciled, artifact-verified secondary match reports.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .reconcile import ReconciliationReport

Verdict = Literal['corroborated', 'contested', 'single-engine', 'insufficient']
Tier = Literal['high', 'moderate', 'low', 'unassessed']


@dataclass(frozen=True)
class MatchEvidence:
    match_id: str
    verdict: Verdict
    tier: Tier
    evidence_index: int | None
    supporting_engines: tuple[str, ...]
    contradicting_engines: tuple[str, ...]
    missing_engines: tuple[str, ...]
    limitations: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class EvidenceAssessment:
    rows: tuple[MatchEvidence, ...]
    engine_versions: tuple[str, ...]
    warnings: tuple[str, ...]


def assess_reports(reports: tuple[ReconciliationReport, ...]) -> EvidenceAssessment:
    """Adjudicate per-match agreement while separating disagreement from missing data.

    Indices deliberately never use upstream similarity/confidence values (different
    scales). No probability calibration exists yet. 55 is the single-engine baseline,
    +20 for BinDiff structural corroboration, +8 for rz-diff's byte-level
    corroboration. The maximum is 83 to avoid false certainty from dependent tools.
    A contradiction takes priority, regardless of corroborating majority.
    """
    if not reports:
        return EvidenceAssessment((), (), ('No secondary engines ran; cross-engine evidence unavailable.',))
    engine_names = [r.engine for r in reports]
    if len(set(engine_names)) != len(engine_names):
        raise ValueError('one report per distinct secondary engine required')
    row_ids = {row.match_id for row in reports[0].rows}
    for report in reports[1:]:
        if {row.match_id for row in report.rows} != row_ids:
            raise ValueError('secondary reports must describe the same Ghidriff match set')
    rows = []
    for match_id in sorted(row_ids):
        selected = [(report.engine, next(row for row in report.rows if row.match_id == match_id))
                    for report in reports]
        support = tuple(engine for engine, row in selected if row.status == 'agreement')
        conflict = tuple(engine for engine, row in selected if row.status == 'disagreement')
        missing = tuple(engine for engine, row in selected if row.status in ('absent', 'not-comparable'))
        limitations = tuple(f'{engine}: {row.note}' for engine, row in selected
                            if row.status != 'agreement')
        if conflict:
            verdict, tier, index = 'contested', 'low', 0
            reason = 'At least one engine proposes conflicting endpoints. Review identities manually before interpreting a patch.'
        elif support:
            index = min(83, 55 + (20 if 'bindiff' in support else 0) +
                        (8 if 'rz-diff' in support else 0))
            verdict, tier = 'corroborated', ('high' if index >= 75 else 'moderate')
            reason = ('Match endpoints agree, but engines can share disassembly artifacts and '
                      'failure modes. Evidence index is an uncalibrated triage aid.')
        elif all(row.status == 'not-comparable' for _, row in selected):
            verdict, tier, index = 'insufficient', 'unassessed', None
            reason = 'The secondary engine output cannot be compared to this match.'
        else:
            verdict, tier, index = 'single-engine', 'low', 55
            reason = 'Only Ghidriff has an address-comparable match; absence is not contradiction.'
        rows.append(MatchEvidence(match_id, verdict, tier, index, support, conflict, missing,
                                  limitations, reason))
    return EvidenceAssessment(
        tuple(rows),
        tuple(f'{r.engine} {r.engine_version}' for r in reports),
        ('Scores are ordinal, uncalibrated indices of function MATCH corroboration only; '
         'never vulnerability probability, patch validity, exploitability, or independent proof.',
         'Function matching and semantic security findings require separate validation.',
         'Engine agreement may reflect shared disassembly or compiler artifacts; do not average upstream scores.')
    )
