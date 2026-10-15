"""The Detection rules panel's declaration for the panel host (YRX-integration-plan s8, panel spec R6b). Pure: Qt loads only
when the factory runs, which the host does at first show. The panel reads stored rule rows; it runs no engine, opens no
network and executes no target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from .tooltip_entries import TEMPLATES, TIPS
from .view_model import CLAIMS


def _factory(ctx: PanelContext) -> PanelController:
    from .qt_panel import RulesController
    return RulesController(ctx)


PANEL = PanelSpec(
    id='rules', title='Detection rules', factory=_factory, area='right', shortcut='Ctrl+Shift+R', focus_order=170,
    requires=('project',), claims=CLAIMS, tips=TIPS, tip_templates=TEMPLATES, minimum_em=(48, 18),
    anchors_in=frozenset({'rule'}), anchors_out=frozenset({'match'}))
