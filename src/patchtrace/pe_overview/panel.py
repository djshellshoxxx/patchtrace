"""The Files panel's declaration for the panel host (GUI plan 8.10, step M3). Pure: Qt loads only when the factory
runs. It replaces the former File overview dialog: recorded artifact fields plus the parsed PE comparison."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..tooltips import TooltipEntry

TIPS = {
    'files.dock': TooltipEntry(
        'Dock comparing the recorded and the parsed fields of the older and newer files.',
        'A fast structural check before, or without, the Ghidriff analysis backend.',
        'Read-only; nothing is executed and the project is not modified.',
        'Project metadata plus bounded read-only parsing of the verified artifact copies.',
        'Needs an open project.'),
    'files.action': TooltipEntry(
        'Show or hide the Files panel.', 'Keeps the file comparison next to the workspace.',
        'Toggles the dock.', availability='Needs an open project for content.'),
}


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_inspection import FilesController
    return FilesController(ctx)


PANEL = PanelSpec(id='files', title='Files', factory=_factory, area='bottom', requires=('project',), tips=TIPS)
