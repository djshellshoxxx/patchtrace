"""Groups `ann` (analyst notes) and `fnd` (findings) from the project aggregate (WB1 section 7).

Model-generated findings and analyst conclusions are separate documents whose `extra` names the origin, so a
model hypothesis never reads as analyst evidence. `validation` annotations hold JSON, not prose, and are skipped.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable

from patchtrace.models import AnalystAnnotation, ComparisonProject, Finding
from patchtrace.search.segment import SegmentDoc
from patchtrace.search.sources.base import SourceSpec

TABLE_SETS = ('text',)
NOTE_KINDS = frozenset({'note', 'bookmark', 'match-override'})


def _digest(rows: Iterable[tuple]) -> str:
    """sha256 of the sorted rows (section 7 'Digest': `(id, kind, text, stale)`)."""
    digest = hashlib.sha256()
    for row in sorted(rows):
        digest.update(repr(row).encode('utf-8') + b'\n')
    return digest.hexdigest()


def _notes(annotations: tuple[AnalystAnnotation, ...]) -> Iterable[SegmentDoc]:
    for ref, note in enumerate(annotations):
        yield SegmentDoc('note', None, note.target_id[:64], note.text, ref, extra='stale' if note.stale else '',
                         text_title=note.kind, text_body=note.text)


def annotation_spec(project: ComparisonProject) -> SourceSpec:
    notes = tuple(sorted((a.model_copy() for a in project.annotations if a.kind in NOTE_KINDS), key=lambda a: a.id))
    rows = [(a.id, a.kind, a.text, a.stale) for a in notes]
    return SourceSpec('ann', ('note',), TABLE_SETS, None, {'notes': _digest(rows)}, lambda: _notes(notes))


def _model_text(finding: Finding) -> str:
    parts = [finding.fix_purpose, finding.hypothesis.explanation, finding.cwe or '', finding.cwe_rationale or '']
    return '\n'.join(part for part in parts if part)


def _findings(rows: tuple[tuple[str, Finding], ...]) -> Iterable[SegmentDoc]:
    ref = 0
    for subject, finding in rows:
        stale = ' stale' if finding.stale else ''
        yield SegmentDoc('finding', None, subject[:64], finding.summary, ref, extra=f'model{stale}',
                         text_title=finding.summary, text_body=_model_text(finding))
        ref += 1
        if finding.analyst_conclusion:
            yield SegmentDoc('finding', None, subject[:64], finding.analyst_conclusion, ref, extra=f'analyst{stale}',
                             text_title=finding.summary, text_body=finding.analyst_conclusion)
            ref += 1


def finding_spec(project: ComparisonProject) -> SourceSpec:
    rows = tuple(sorted(((f.id, f.model_copy(deep=True)) for run in project.interpretations
                         if run.status == 'completed' for f in run.findings), key=lambda row: row[0]))
    inputs = [(fid, f.summary, _model_text(f), f.analyst_conclusion, f.stale) for fid, f in rows]
    return SourceSpec('fnd', ('finding',), TABLE_SETS, None, {'findings': _digest(inputs)}, lambda: _findings(rows))
