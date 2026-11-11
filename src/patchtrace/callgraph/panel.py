"""The Calls panel's declaration for the panel host (WB2 G5/G6; GUI plan 8.10). Pure: Qt loads only when the factory
runs. The panel reads stored call lists only; nothing here runs a tool, opens the network or executes a target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..gui.text import CLAIMS_PAIRING
from .tooltip_entries import TEMPLATES, TIPS


def _factory(ctx: PanelContext) -> PanelController:
    from .panel_qt import CallsController
    return CallsController(ctx)


PANEL = PanelSpec(
    id='graph', title='Calls', factory=_factory, area='bottom', shortcut='Ctrl+Shift+G', focus_order=130,
    requires=('project',), claims=CLAIMS_PAIRING, tips=TIPS, tip_templates=TEMPLATES,
    anchors_out=frozenset({'function'}), minimum_em=(56, 16))
