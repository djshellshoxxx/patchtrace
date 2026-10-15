"""The Strings panel's declaration for the panel host (WB3 S7b; GUI framework 1.1). Pure: Qt loads only when the
factory runs, which the host does at first show. The panel never runs a target and never uploads a string."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..tooltips import TooltipEntry
from .tooltip_entries import ENTRIES

_SOURCE = 'The strings of the two builds from the built-in scan or FLOSS, with their recorded extraction basis.'


def _entry(values: tuple[str, ...]) -> TooltipEntry:
    what, why, effect, source, availability = values
    return TooltipEntry(what, why, effect, source or _SOURCE, availability)


# Only the controls this panel builds: the host audit requires every registered tip to be on a control. The
# entries of the planned FLOSS, probe, export and further filter controls stay in `tooltip_entries` until built.
BUILT = ('dock', 'action', 'table', 'detail', 'cancel', 'run.builtin', 'filter.change', 'filter.scope',
         'filter.text', 'filter.noise', 'copy.safe', 'open.function', 'open.hex')
TIPS = {f'strings.{name}': _entry(ENTRIES[f'strings.{name}']) for name in BUILT}


def _factory(ctx: PanelContext) -> PanelController:
    from .qt_panel import StringsController
    return StringsController(ctx)


PANEL = PanelSpec(
    id='strings', title='Strings', factory=_factory, area='bottom', tabify_with='graph', shortcut='Ctrl+Shift+T',
    focus_order=140, requires=('project',), tips=TIPS, minimum_em=(48, 14), anchors_in=frozenset({'string'}),
    anchors_out=frozenset({'function'}))
