"""Pure view-model of the Export dialog (SPEC-50 section 8): contract and profile choices, the section checklist with
counts and reasons, copy text, and a capped preview. No Qt import, so the dialog's logic is testable offscreen-free and
the preview can be built on a worker thread. The `ui.py` dialog only binds widgets to this class.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from ..models import ComparisonProject
from .export import _LatestRun
from .export import render as render_v2
from .inputs import SectionInputs
from .options import ExportOptions, resolve
from .sections.symbols import build_symbols

CONTRACTS = ('Report v1 (current)', 'Report v2')
PROFILES = ('Local analysis', 'Share with others')
PREVIEW_LIMIT = 200 * 1024
PREVIEW_NOTE = 'Preview truncated; the file will contain the full report.'
SHARE_HINT = 'Share profile removes code, notes and file paths and writes web addresses as inert text.'
SHARE_NEEDS_V2 = 'The share profile is part of Report v2; the contract was switched to Report v2.'
V1_NO_SHARE = 'Report v1 has no share profile; the local profile was selected.'
LOCAL_WARNING = ('This report may contain code and file names from the binaries you analysed. '
                 'Do not publish Microsoft-derived content.')
CALIBRATION_LINE = 'Scores are ordinal triage indices, not probabilities of a vulnerability.'
EMPTY_PROJECT = 'Nothing to export: no matches yet.'
V1_REASON = 'Not available: report v1 has no optional sections.'
ACCESSIBLE_NAMES = {'contract': 'export.contract', 'profile': 'export.profile', 'sections': 'export.sections',
                    'preview': 'export.preview'}
TAB_ORDER = ('export.contract', 'export.profile', 'export.sections', 'export.preview', 'export.button')
SECTION_LABELS = {'engine_evidence': 'Engine evidence', 'series': 'Series', 'unified_result': 'Unified result',
                  'build_facts': 'Build facts', 'symbols': 'Symbols', 'advisories': 'Advisories', 'leads': 'Leads'}
UNAVAILABLE = {
    'engine_evidence': 'Not available: no secondary engine ran.',
    'series': 'Not available: no series is loaded.',
    'unified_result': 'Not available: no stored unified result.',
    'build_facts': 'Not available: no build facts were parsed.',
    'symbols': 'Not available: no completed run recorded a symbol mode.',
    'advisories': 'Not available: no advisories were fetched or imported.',
    'leads': 'Not available: no leads were generated.'}


@dataclass(frozen=True)
class SectionRow:
    key: str
    label: str
    count: int
    enabled: bool
    checked: bool
    reason: str  # empty when the section is available


def _count(value) -> int:
    if value is None:
        return 0
    rows = getattr(value, 'rows', None) or getattr(value, 'builds', None)
    return len(rows) if rows is not None else (len(value) if isinstance(value, tuple) else 1)


class ExportViewModel:
    def __init__(self, project: ComparisonProject, sections: SectionInputs | None = None):
        self.project = project
        self.contract_index = 0
        self.profile_index = 0
        self._warned = False
        self._unchecked: set[str] = set()
        sections = sections or SectionInputs()
        if sections.symbols is None:
            built = build_symbols(_LatestRun(project))
            sections = replace(sections, symbols=None if built is None else built.value)
        self._sections = sections

    @property
    def report_version(self) -> int:
        return 2 if self.contract_index else 1

    @property
    def nothing_to_export(self) -> str | None:
        return None if self.project.matches else EMPTY_PROJECT

    def set_contract(self, index: int) -> str | None:
        """Report v1 has no share profile: choosing it while sharing falls back to the local profile and says so."""
        self.contract_index = self._index(index, CONTRACTS)
        if not self.contract_index and self.profile_index:
            self.profile_index = 0
            return V1_NO_SHARE
        return None

    def set_profile(self, index: int) -> str | None:
        """The share profile exists only in report v2: choosing it switches the contract and says so."""
        self.profile_index = self._index(index, PROFILES)
        if self.profile_index and not self.contract_index:
            self.contract_index = 1
            return SHARE_NEEDS_V2
        return None

    @staticmethod
    def _index(index: int, choices: tuple[str, ...]) -> int:
        if index not in range(len(choices)):
            raise ValueError('unknown choice')
        return index

    def section_rows(self) -> list[SectionRow]:
        rows = []
        for key, label in SECTION_LABELS.items():
            count = _count(getattr(self._sections, key))
            reason = V1_REASON if self.report_version == 1 else (UNAVAILABLE[key] if not count else '')
            enabled = not reason
            rows.append(SectionRow(key, label, count, enabled, enabled and key not in self._unchecked, reason))
        return rows

    def set_section_checked(self, key: str, checked: bool) -> None:
        if key not in SECTION_LABELS:
            raise ValueError('unknown section')
        if checked:
            self._unchecked.discard(key)
        else:
            self._unchecked.add(key)

    def profile_hint(self) -> str:
        return SHARE_HINT if self.profile_index else ''

    def take_local_warning(self) -> str | None:
        """The local-profile warning, once per dialog and only while the local profile is selected."""
        if self.profile_index or self._warned:
            return None
        self._warned = True
        return LOCAL_WARNING

    def options(self, *, include_code: bool = False, include_notes: bool | None = None,
                include_ordinal_index: bool = False) -> ExportOptions:
        return resolve(report_version=self.report_version, profile='share' if self.profile_index else 'local',
                       include_code=include_code and not self.profile_index,
                       include_notes=None if self.profile_index else include_notes,
                       include_ordinal_index=include_ordinal_index)

    def sections_for_export(self) -> SectionInputs:
        keep = {row.key for row in self.section_rows() if row.checked}
        return replace(self._sections, **{key: None for key in SECTION_LABELS if key not in keep})

    def export_kwargs(self, **choices) -> dict:
        """Keyword arguments for `ProjectService.export_report` (the dialog adds format and destination)."""
        chosen = self.options(**choices)
        kwargs = {'include_code': chosen.include_code, 'include_notes': chosen.include_notes}
        if chosen.report_version == 2:
            kwargs |= {'report_version': 2, 'redaction': chosen.profile, 'sections': self.sections_for_export()}
        return kwargs

    def preview(self, format: str = 'md', *, generated_at: str | None = None, **choices) -> str:
        """Plain text of the file as it would be written, capped at 200 KiB with a note (never rich text)."""
        from ..reports import _render, _snapshot
        chosen = self.options(**choices)
        snapshot = _snapshot(self.project, chosen.include_code, chosen.include_notes, None, None)
        if chosen.report_version == 1:
            full = _render(snapshot, format)
        else:
            full = render_v2(self.project, format, snapshot, include_code=chosen.include_code,
                             include_notes=chosen.include_notes, sections=self.sections_for_export(),
                             profile=chosen.profile, generated_at=generated_at)[0]
        raw = full.encode('utf-8', 'replace')
        if len(raw) <= PREVIEW_LIMIT:
            return full
        return raw[:PREVIEW_LIMIT].decode('utf-8', 'ignore') + f'\n\n{PREVIEW_NOTE}\n'

    @staticmethod
    def error_text(code: str) -> str:
        return f'Export failed: {code}. The previous file, if any, is unchanged.'

