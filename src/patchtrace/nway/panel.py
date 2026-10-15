"""The Series panel's declaration for the panel host (GUI plan 8.10, step M3). Pure: Qt loads only when the factory
runs. The dock holds one tab per opened series.json; the File menu entry chooses the file."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..tooltips import TooltipEntry

TIPS = {
    'series.dock': TooltipEntry(
        'Dock with one tab for each series.json you opened.',
        'Follow a function across several builds without leaving the main window.',
        'Read-only; closing a tab or the dock changes no project data.',
        'The series.json written by `patchtrace series create` and the pair projects next to it.',
        'Open a series.json from the File menu.'),
    'series.open_file': TooltipEntry(
        'Choose a series.json and open it in a new tab.', 'Same as the Series window entry of the File menu.',
        'Reads the file and the pair projects next to it. Nothing is computed, run or written.',
        availability='Always available.'),
    'series.action': TooltipEntry(
        'Show or hide the Series panel.', 'Keeps stored chain hypotheses next to the workspace.',
        'Toggles the dock.'),
}


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_series import SeriesController
    return SeriesController(ctx)


PANEL = PanelSpec(id='series', title='Series', factory=_factory, area='bottom', tips=TIPS)
