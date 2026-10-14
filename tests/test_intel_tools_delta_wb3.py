"""WB3-S1b string delta amendments: truncation per type and encodings compared (F21). Pure model tests."""
from __future__ import annotations

import hashlib

from patchtrace.intelligence.tools import delta
from patchtrace.intelligence.tools.common import (
    EvidenceLink,
    StringEvidence,
    ToolEvidenceSet,
    ToolManifest,
    ToolRun,
)

SHA = {'older': 'a' * 64, 'newer': 'b' * 64}


def make(side: str, items: list[tuple[str, str, str]], truncated_types=(), truncated=False) -> ToolEvidenceSet:
    run_id = f'run-{side}'
    strings = tuple(StringEvidence(
        value_hash=hashlib.sha256(value.encode()).hexdigest(), length=len(value), display_value=value,
        encoding=encoding, type=kind, source_location=EvidenceLink(tool_run_id=run_id, artifact_sha256=SHA[side]),
        confidence_class='tool-reported', extraction_method=f'floss-{kind}', source_run_id=run_id)
        for value, kind, encoding in items)
    return ToolEvidenceSet(run_id=run_id, engine='floss', side=side, artifact_sha256=SHA[side], cache_key='c' * 64,
                           config_digest='d' * 64, strings=strings, truncated=truncated or bool(truncated_types),
                           truncated_types=tuple(truncated_types), counts={'strings': len(strings)})


def compare(older: ToolEvidenceSet, newer: ToolEvidenceSet):
    manifest = ToolManifest(engine='floss', version='3.1.1', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    runs = [ToolRun(run_id=s.run_id, engine='floss', side=s.side, input_artifact_hash=s.artifact_sha256,
                    config_digest='d' * 64, cache_key='c' * 64, started_at='t', elapsed=0, status='ok',
                    evidence_count=len(s.strings), profile='context', manifest=manifest) for s in (older, newer)]
    return {c.display_value: c for c in delta.compute(runs[0], older, runs[1], newer).strings}


def test_only_the_truncated_types_make_absence_indeterminate():
    older = make('older', [('shared', 'static', 'ASCII')], truncated_types=('static',))
    newer = make('newer', [('shared', 'static', 'ASCII'), ('late static', 'static', 'ASCII'),
                           ('late decoded', 'decoded', 'ASCII')])
    changes = compare(older, newer)
    assert changes['late static'].change == 'indeterminate'    # the older static list was cut
    assert changes['late decoded'].change == 'added'           # decoded was complete on the older side


def test_removed_against_a_truncated_newer_side_is_indeterminate():
    older = make('older', [('gone', 'static', 'ASCII'), ('gone decoded', 'decoded', 'ASCII')])
    newer = make('newer', [], truncated_types=('static',))
    changes = compare(older, newer)
    assert changes['gone'].change == 'indeterminate' and changes['gone decoded'].change == 'removed'


def test_legacy_truncated_flag_without_types_covers_every_type():
    older = make('older', [], truncated=True)
    newer = make('newer', [('new', 'decoded', 'ASCII')])
    assert compare(older, newer)['new'].change == 'indeterminate'


def test_encoding_only_change_is_representation_changed():
    older = make('older', [('same text', 'static', 'ASCII')])
    newer = make('newer', [('same text', 'static', 'UTF-16LE')])
    change = compare(older, newer)['same text']
    assert change.change == 'representation-changed'
    assert change.older_encodings == ('ASCII',) and change.newer_encodings == ('UTF-16LE',)
