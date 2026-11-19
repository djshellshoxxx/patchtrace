"""Accessible names for registry-backed controls that their builder leaves unnamed (SPEC-45 R-N1, R-N7; GUI plan
8.7 R1). Pure: no Qt.

`gui.tips.apply_tip` names a control from `NAMES` only while the control has no name of its own, so an explicit
`setAccessibleName` always wins, and never names a label (R-N4). The controls listed are built by the frozen
`ui.py`, which is why their names live here and not beside the widgets. A name is a noun phrase of at most
`NAME_LIMIT` characters, without a role word (UI Automation already reports the role) and without a final period.
"""
from __future__ import annotations

from .registry import NAME_LIMIT

NAMES: dict[str, str] = {
    'job.log': 'Analysis log',
    'findings.search': 'Finding search text',
    'findings.review_filter': 'Finding review status filter',
    'findings.stale_filter': 'Current or stale findings filter',
    'findings.list': 'AI-assisted findings',
    'findings.detail': 'Selected finding detail',
    'findings.evidence': 'Evidence cited by the selected finding',
    'findings.review_status': 'Selected finding review status',
    'findings.conclusion': 'Analyst conclusion on the selected finding',
    'findings.note_target': 'Analyst note target',
    'findings.notes': 'Analyst note text',
    'viewer.mode': 'Code representation',
    'viewer.raw_scope': 'Raw byte scope',
    'viewer.raw_page': 'Raw byte page',
    'viewer.raw_goto': 'File offset to go to',
}

_POPUP_SUFFIX = ' options'


def popup_name(name: str) -> str:
    """The name of a combo box's drop-down list, which UI Automation shows as its own list."""
    return name[:NAME_LIMIT - len(_POPUP_SUFFIX)].rstrip() + _POPUP_SUFFIX
