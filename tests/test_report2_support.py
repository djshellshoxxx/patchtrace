"""Shared deterministic fixtures for the report/2 tests (no tests live here)."""
from __future__ import annotations

import os
from pathlib import Path

from patchtrace.models import ComparisonProject
from patchtrace.report2 import text
from patchtrace.report2.contracts import (
    Advisory,
    BuildFact,
    Channel,
    Engine,
    EngineEvidence,
    EvidenceRow,
    Lead,
    Symbols,
    UnifiedResult,
)
from patchtrace.report2.inputs import SectionInputs

GOLDEN = Path(__file__).parent / 'golden' / 'report2'
FIXED_TIME = '2026-10-14T00:00:00+00:00'
HOSTILE_NAME = '\u202egnidnuf<script>alert(1)</script>\n# Injected'
ADVISORY_TEXT = ('[click](https://evil.example/x) and https://evil.example/y\n```\n# not a heading\n`````\n'
                 '<img src=x onerror=alert(1)>')
SHA_A, SHA_B = 'a' * 64, 'b' * 64


def frozen_project() -> ComparisonProject:
    return ComparisonProject.model_validate_json((GOLDEN / 'project_v1_input.json').read_text(encoding='utf-8'))


def hostile_project() -> tuple[ComparisonProject, str, str]:
    """The frozen project with the section 5 hostile name on match A; returns (project, match A id, match B id)."""
    project = frozen_project()
    ids = {}
    for match in project.matches:
        for function in match.older + match.newer:
            if function.name == 'read_item':
                function.name = HOSTILE_NAME
                ids['a'] = match.id
            elif function.name == 'get_version':
                ids['b'] = match.id
    return project, ids['a'], ids['b']


def _n(value: str, cap: int = 512) -> str:
    return text.normalize_text(value, max_chars=cap)


def synergy_sections(match_a: str, match_b: str) -> SectionInputs:
    """Match A: Ghidriff + BinDiff agree, rz-diff absent. Match B: BinDiff disagrees."""
    rows = [
        EvidenceRow(match_id=match_a, verdict='corroborated', tier='moderate', ordinal_index=75,
                    channels=[Channel(engine='ghidriff', state='present'), Channel(engine='bindiff', state='present'),
                              Channel(engine='rz-diff', state='absent')],
                    supporting_engines=['ghidriff', 'bindiff'], contradicting_engines=[],
                    missing_engines=['rz-diff'], explanation='Ghidriff and BinDiff agree; rz-diff did not run.'),
        EvidenceRow(match_id=match_b, verdict='contested', tier='low',
                    channels=[Channel(engine='ghidriff', state='present'), Channel(engine='bindiff', state='present'),
                              Channel(engine='rz-diff', state='not_run')],
                    supporting_engines=['ghidriff'], contradicting_engines=['bindiff'],
                    missing_engines=['rz-diff'], explanation='BinDiff disagrees with the Ghidriff pairing.')]
    return SectionInputs(
        engine_evidence=EngineEvidence(engines=[Engine(name='bindiff', version='8'), Engine(name='ghidriff', version='0.9')],
                                       rows=rows),
        build_facts=(BuildFact(side='older', fact='company_name', value=_n('Vendor <b>Corp</b>'), source='pe-version'),
                     BuildFact(side='newer', fact='file_version', value='10.0.1.2', source='pe-version')),
        symbols=Symbols(mode='off'),
        advisories=(Advisory(kind='cve', id='CVE-2024-12345', vendor=_n('Vendor'), url_text='https://evil.example/adv.html',
                             text=text.normalize_text(ADVISORY_TEXT, verbatim=True, max_chars=text.CAP_ADVISORY)),),
        leads=(Lead(lead_id='lead-1', kind='cluster', channels=['ghidriff', 'bindiff'], statement=_n('Two channels agree.', 4096)),),
        unified_result=UnifiedResult(result_id=SHA_A, manifest_sha256=SHA_B, engines=['ghidriff'], status='complete',
                                     stale=False))


def check_or_update(name: str, actual: str) -> None:
    """Golden compare, LF-normalised so a CRLF checkout cannot fail; PATCHTRACE_UPDATE_GOLDENS=1 rewrites."""
    path = GOLDEN / name
    if os.environ.get('PATCHTRACE_UPDATE_GOLDENS') == '1':
        path.write_bytes(actual.encode('utf-8'))
    assert path.read_bytes().decode('utf-8').replace('\r\n', '\n') == actual, name
