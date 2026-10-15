"""The KB and CVE panel's declaration for the panel host (KB-integration-plan 8.2, slice K4b; GUI plan 8.10). Pure:
Qt loads only when the factory runs, which the host does at first show. The panel reads stored results only; nothing
here opens the network, runs a tool or executes a target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..gui.text import ClaimsProfile
from .tooltip_entries import TEMPLATES, TIPS

# The leads view states KEV and exploitation facts, so unlike the Leads panel those words are allowed here; wording
# that presents a number as likelihood is not.
CLAIMS = ClaimsProfile(
    banned_stems=('probab', 'likelihood', 'confidence', 'percent', 'proven', 'certain', 'verified', 'safe', 'secure'))


def _factory(ctx: PanelContext) -> PanelController:
    from .panel_qt import KbController
    return KbController(ctx)


PANEL = PanelSpec(
    id='kb', title='KB and CVE', factory=_factory, area='right', shortcut='Ctrl+Shift+K', claims=CLAIMS, tips=TIPS,
    tip_templates=TEMPLATES, minimum_em=(48, 16), anchors_in=frozenset({'cve'}), anchors_out=frozenset({'match'}))
