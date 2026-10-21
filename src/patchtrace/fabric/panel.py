"""The Related evidence panel's declaration for the panel host (FAB-integration-plan.md s8, slice FAB-6). Pure: Qt loads
only when the factory runs. The panel reads published anchors only; nothing here runs a tool, opens the network or
executes a target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec, TeachTopic
from ..tooltips import TooltipEntry
from .contracts import KINDS

SOURCE = 'The anchors that tools and databases published for this project, each with its witnesses and origins.'


def _tip(what: str, why: str, effect: str, source: str = SOURCE, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


TIPS = {
    'related.dock': _tip(
        'Dock listing what else is known about the selected function pair: imports, strings, capabilities and more.',
        'Gathers the evidence of several tools in one place, each line with where it comes from.',
        'Read-only; a line is evidence to read, not a finding about the code.',
        availability='Needs a project with a selected function pair.'),
    'related.action': _tip('Show or hide the Related evidence panel.', 'Keeps the cross-tool evidence next to the code.',
                           'Toggles the dock.'),
    'related.table': _tip(
        'Evidence published for the selected pair, one line each, in a set order with no score.',
        'Shows what is known and how many independent origins stand behind each line.',
        'Enter opens the owning panel; Space shows where the line comes from.'),
    'related.kind_filter': _tip('Show only evidence of one kind.', 'Narrows a long list to the part you are reading.',
                                'Changes the rows shown; stores nothing.'),
    'related.role': _tip(
        'Role of a line: + observed in the files, i stated by an advisory or catalog, ? a hint to look for.',
        'A statement or a hint is not something found in this code.', 'Read-only text.'),
    'related.witnesses': _tip(
        'How many independent origins stand behind a line, out of how many witnesses reported it.',
        'Witnesses that share an origin are one voice, so they are counted once.', 'Read-only text; no sum is made.'),
    'related.detail': _tip('Where the selected line comes from: its producers and independent origins.',
                           'Lets you check the evidence behind a line.', 'Read-only text.'),
    'related.refresh': _tip('Load the published evidence of this pair again.', 'Picks up evidence published since.',
                            'Reads the stored anchors again; nothing is changed.'),
}
TEACH = (
    TeachTopic('related.origin_once',
               'Two tools that read the same source are one voice, so their witnesses count once.',
               ('Read the Witnesses column as independent of total.', 'Open the detail to see the producers.')),
    TeachTopic('related.role_hint',
               'A hint is something to look for; a statement comes from an advisory; only observed was found here.',
               ('Read the Role column before the label.',)),
    TeachTopic('related.unknown',
               'A pair with no lines is unknown, not clear: no tool has published evidence for it yet.',
               ('Run capabilities, strings or build tools to add evidence.',)))


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_related import RelatedController
    return RelatedController(ctx)


PANEL = PanelSpec(
    id='related', title='Related evidence', factory=_factory, area='bottom', tabify_with='leads',
    shortcut='Ctrl+Shift+J', requires=('project',), tips=TIPS, teach=TEACH, minimum_em=(48, 12),
    anchors_in=frozenset(KINDS), anchors_out=frozenset(KINDS))
