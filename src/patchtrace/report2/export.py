"""The v2 branch of `reports.export_project` (SPEC-50 7.6): snapshot -> validated report -> rendered text."""
from __future__ import annotations

from dataclasses import replace

from pydantic import ValidationError

from ..models import ComparisonProject
from .assemble import build_report
from .inputs import RedactionProfile, SectionInputs
from .render_html import render_html
from .render_json import finalize, render_json
from .render_md import render_md
from .sections import refuse
from .sections.symbols import build_symbols

RENDERERS = {'json': render_json, 'md': render_md, 'html': render_html}


class _LatestRun:
    """Run settings come from the persisted snapshot itself, so no producer track is needed (GHR)."""

    def __init__(self, project: ComparisonProject):
        done = [r for r in project.runs if r.status == 'completed']
        self._settings = max(done, key=lambda r: r.created).settings if done else None

    def latest_settings(self) -> dict | None:
        return self._settings


def render(project: ComparisonProject, format: str, snapshot: dict, *, include_code: bool, include_notes: bool,
           sections: SectionInputs | None, profile: RedactionProfile, calibration_profile: str | None = None,
           generated_at: str | None = None) -> tuple[str, dict]:
    """(rendered text, finalized report dict). `snapshot` was built with the profile's effective flags."""
    sections = sections or SectionInputs()
    if sections.symbols is None:
        built = build_symbols(_LatestRun(project))
        sections = replace(sections, symbols=None if built is None else built.value)
    from .calibration_block import build_calibration_block
    try:
        report = build_report(snapshot, include_code=include_code, include_notes=include_notes, sections=sections,
                              profile=profile, generated_at=generated_at,
                              calibration=build_calibration_block(profile=calibration_profile))
    except ValidationError as exc:
        raise refuse('report', exc) from None
    data = finalize(report)
    return RENDERERS[format](data), data
