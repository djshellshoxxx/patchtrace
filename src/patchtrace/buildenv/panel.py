"""The Build environment panel's declaration for the panel host (DIE D5, GUI plan 8.10). Pure: Qt loads only when
the factory runs, which the host does at first show. The panel reads PE header facts and stored results; it runs no
tool, opens no network and executes no target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from .tooltip_entries import TEMPLATES, TIPS


def _factory(ctx: PanelContext) -> PanelController:
    from .qt_panel import BuildEnvController
    return BuildEnvController(ctx)


PANEL = PanelSpec(
    id='build_env', title='Build environment', factory=_factory, area='right', tabify_with='evidence',
    shortcut='Ctrl+Shift+B', focus_order=160, requires=('project',), tips=TIPS, tip_templates=TEMPLATES,
    minimum_em=(48, 16), anchors_in=frozenset({'build_fact'}))
