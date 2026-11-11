"""Shared deterministic fixtures for the report/2 tests (no tests live here)."""
from __future__ import annotations

import os
from pathlib import Path

from patchtrace.models import ComparisonProject
from patchtrace.report2.inputs import SectionInputs
from patchtrace.report2.sections import collect
from patchtrace.report2.sections.advisories import AdvisoryRecord
from patchtrace.report2.sections.build_facts import FactRecord
from patchtrace.report2.sections.leads import LeadRecord
from patchtrace.secondary.evidence import assess_reports
from patchtrace.secondary.reconcile import Reconciliation, ReconciliationReport

GOLDEN = Path(__file__).parent / 'golden' / 'report2'
FIXED_TIME = '2026-10-14T00:00:00+00:00'
HOSTILE_NAME = '\u202egnidnuf<script>alert(1)</script>\n# Injected'
ADVISORY_TEXT = ('[click](https://evil.example/x) and https://evil.example/y\n```\n# not a heading\n`````\n'
                 '<img src=x onerror=alert(1)>')


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


def _report(engine: str, version: str, entries: list[tuple[str, str]]) -> ReconciliationReport:
    return ReconciliationReport(engine, version, tuple(
        Reconciliation(key, status, 0x1000, 0x2000, (), status) for key, status in entries), (), ())


class FakeEvidence:
    def __init__(self, assessment, stale=False):
        self._assessment, self._stale = assessment, stale

    def assessment(self):
        return self._assessment

    def is_stale(self):
        return self._stale


class FakeFacts:
    def facts(self):
        return [FactRecord('older', 'company_name', 'Vendor <b>Corp</b>', 'pe-version'),
                FactRecord('newer', 'file_version', '10.0.1.2', 'pe-version')]


class FakeAdvisories:
    def advisories(self):
        return [AdvisoryRecord('cve', 'CVE-2024-12345', ADVISORY_TEXT, vendor='Vendor',
                               url='https://evil.example/adv.html', kev_listed=None)]


class FakeLeads:
    def leads(self):
        return [LeadRecord('lead-1', 'cluster', ('ghidriff', 'bindiff'), 'Two channels agree.')]


class FakeSettings:
    def latest_settings(self):
        return {'symbol_mode': 'off'}


def synergy_sections(match_a: str, match_b: str) -> SectionInputs:
    """Match A: Ghidriff + BinDiff agree, rz-diff absent. Match B: BinDiff disagrees (real `assess_reports`)."""
    assessment = assess_reports((_report('bindiff', '8', [(match_a, 'agreement'), (match_b, 'disagreement')]),
                                 _report('rz-diff', '0.9', [(match_a, 'absent'), (match_b, 'absent')])))
    return collect(evidence=FakeEvidence(assessment), run_settings=FakeSettings(), build_facts=FakeFacts(),
                   advisories=FakeAdvisories(), leads=FakeLeads())


def check_or_update(name: str, actual: str) -> None:
    """Golden compare, LF-normalised so a CRLF checkout cannot fail; PATCHTRACE_UPDATE_GOLDENS=1 rewrites."""
    path = GOLDEN / name
    if os.environ.get('PATCHTRACE_UPDATE_GOLDENS') == '1':
        path.write_bytes(actual.encode('utf-8'))
    assert path.read_bytes().decode('utf-8').replace('\r\n', '\n') == actual, name
