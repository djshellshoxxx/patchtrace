"""The Search panel's declaration for the panel host (WB1 S7; GUI framework section 1). Pure: Qt loads only when the
factory runs, which the host does at first show. The panel reads the project's saved data and a local derived index
only; nothing here runs a tool, opens the network or executes a target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from .tooltip_entries import TEMPLATES, TIPS


def _factory(ctx: PanelContext) -> PanelController:
    from .qt_panel import SearchController
    return SearchController(ctx)


PANEL = PanelSpec(
    id='search', title='Search', factory=_factory, area='bottom', shortcut='Ctrl+Shift+F', focus_order=120,
    requires=('project',), tips=TIPS, tip_templates=TEMPLATES, minimum_em=(56, 16),
    anchors_out=frozenset({'function', 'string', 'import'}))
