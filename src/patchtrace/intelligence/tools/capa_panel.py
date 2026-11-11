"""The Capabilities panel's declaration for the panel host (CAP-6a/6b; GUI plan 8.10). Pure: Qt loads only when the
factory runs. The panel reads stored capa evidence; running capa is an explicit, previewed local operation."""
from __future__ import annotations

from ...gui.registry import PanelContext, PanelController, PanelSpec
from ...gui.text import CLAIMS_NEUTRAL
from .tooltip_entries import TEMPLATES, TIPS


def _factory(ctx: PanelContext) -> PanelController:
    from .capa_qt import CapabilitiesController
    return CapabilitiesController(ctx)


PANEL = PanelSpec(
    id='capabilities', title='Capabilities', factory=_factory, area='bottom', tabify_with='graph',
    shortcut='Ctrl+Shift+A', focus_order=150, requires=('project',), claims=CLAIMS_NEUTRAL, tips=TIPS,
    tip_templates=TEMPLATES, minimum_em=(48, 16), anchors_in=frozenset({'capability'}),
    anchors_out=frozenset({'function', 'match', 'rule', 'import', 'string'}))
