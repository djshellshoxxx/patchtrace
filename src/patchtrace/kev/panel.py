"""The KEV dock's declaration for the panel host (KEV-integration-plan s8, slice K3; GUI plan 8.10). Pure: Qt loads
only when the factory runs, which the host does at first show. The dock reads a stored catalog and, after an explicit
consent, fetches one; it never opens another window and never leaves a ranking, a score or a function behind."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..gui.text import ClaimsProfile
from .tooltip_entries import KEV_TEMPLATES, KEV_TOOLTIPS

# The wording KEV must not turn into claims: a listing is context about a CVE, not an assessment.
CLAIMS = ClaimsProfile(
    banned_stems=('probab', 'likelihood'),
    banned_words=('safe', 'secure', 'verified', 'proven', 'certain', 'confidence'))


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_kev import KevController
    return KevController(ctx)


PANEL = PanelSpec(
    id='kev', title='Exploitation context', factory=_factory, area='right', tabify_with='kb', shortcut='Ctrl+Shift+X',
    claims=CLAIMS, tips=KEV_TOOLTIPS, tip_templates=KEV_TEMPLATES, minimum_em=(48, 18))
