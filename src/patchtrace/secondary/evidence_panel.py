"""The engine evidence panel's declaration for the panel host (GUI plan 8.10, step M1). Pure: Qt loads only when the
factory runs, which the host does once, at window start, because the panel owns the engines probe and the BinDiff
setup and must exist before its dock is first shown."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..gui.text import CLAIMS_PAIRING
from ..tooltips import REGISTRY


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_evidence import EvidenceController
    return EvidenceController(ctx)


PANEL = PanelSpec(
    id='evidence', title='Engine evidence', factory=_factory, area='right', shortcut='Ctrl+Shift+E',
    claims=CLAIMS_PAIRING, eager=True,
    tips={tip_id: REGISTRY[tip_id] for tip_id in ('evidence.dock', 'evidence.action')})
