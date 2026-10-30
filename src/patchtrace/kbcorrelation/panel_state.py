"""Pure state mapping of the KB and CVE panel: which StateView kind and fields a loaded report or a failure produce,
and the coverage notice. No Qt."""
from __future__ import annotations

from ..gui.state import NoticeModel
from .view_model import LeadsViewModel

HINT = 'Import advisory documents and rank a comparison, then press Refresh.'


def report_conditions(model: LeadsViewModel) -> tuple[dict[str, dict[str, object]], bool]:
    """(StateView conditions, has_content) for a loaded report. Stale shows its rows for reference, an advisory-only
    or comparison-only result is partial, and an empty list is explained (idle), never silent."""
    report = model.report
    if not model.lead_count:
        return {'idle': {'hint': model.status_text or HINT}}, False
    if report.state == 'stale':
        return {'stale': {'reason': report.text}}, True
    reasons = [report.text] if report.state in ('no-advisory', 'no-comparison') else []
    if report.truncated:
        reasons.append(f'{report.truncated} more rows are not shown')
    return ({'partial': {'reasons': '; '.join(reasons)}} if reasons else {'ready': {}}), True


def failure_conditions(code: str, message: str) -> dict[str, dict[str, object]]:
    return {'error': {'code': code, 'message': message}}


def coverage_notice(model: LeadsViewModel | None) -> NoticeModel | None:
    """The one-line coverage note above the workspace; cleared when nothing is loaded."""
    if model is None or not model.lead_count:
        return None
    return NoticeModel('kb.coverage', 'notice', model.coverage_line, '\n'.join(model.footer_lines))
