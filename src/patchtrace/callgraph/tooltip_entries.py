"""Tooltip entries of the Calls panel, owned by the panel (the shared registry is not edited). The What/Why/Effect
text lives in `view_model.GRAPH_TIPS`; this module adds the Source line every entry cites."""
from __future__ import annotations

from ..tooltips import TooltipEntry
from .view_model import GRAPH_TIP_TEMPLATES, GRAPH_TIPS

SOURCE = 'The stored Ghidriff call lists of this project, the current pairing and the recorded source completeness.'


def _entry(parts: tuple[str, str, str]) -> TooltipEntry:
    what, why, effect = parts
    return TooltipEntry(what, why, effect, SOURCE)


TIPS = {tip_id: _entry(parts) for tip_id, parts in GRAPH_TIPS.items()}
TEMPLATES = {tip_id: _entry(parts) for tip_id, parts in GRAPH_TIP_TEMPLATES.items()}
