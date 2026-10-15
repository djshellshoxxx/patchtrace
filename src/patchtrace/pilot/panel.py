"""The Leads panel's declaration for the panel host (PIL-integration-plan.md s8, slice C2; GUI plan 8.10). Pure: Qt loads
only when the factory runs, which the host does at first show. The panel reads stored results only; nothing here
runs a tool, opens the network or executes a target."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..tooltips import TooltipEntry
from .read_model import CLAIMS

SOURCE = 'The stored patch-intent result of this project; every line cites the evidence it rests on.'


def _tip(what: str, why: str, effect: str, source: str = SOURCE, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


TIPS = {
    'leads.dock': _tip(
        'Dock listing the functions that changed between the two builds, ordered by explainable rules.',
        'Gives a reading order for a patch diff, with the evidence for each position.',
        'Read-only; a lead does not show that a function contains or fixes any CVE.',
        availability='Needs a project with a completed comparison.'),
    'leads.action': _tip('Show or hide the Leads panel.', 'Keeps the ranked list next to the code panes.',
                         'Toggles the dock.'),
    'leads.table': _tip(
        'Ranked leads of the chosen context. Tied leads share a rank range and have equal evidence.',
        'Shows where to look first, and why.', 'Selecting a row fills the explanation below.'),
    'leads.context': _tip(
        'Choose the advisory CVE the leads are matched to, or code evidence only.',
        'The same functions rank differently for different advisories.', 'Changes the rows shown; stores nothing.'),
    'leads.filter_class': _tip('Show only leads of one class.', 'Narrows a long list to the part you are reading.',
                               'Changes the rows shown; stores nothing.'),
    'leads.search': _tip('Filter leads by function name or address.', 'Finds a function you already know.',
                         'Changes the rows shown; stores nothing.'),
    'leads.detail': _tip(
        'Why this function: the expected changes seen, the independent evidence, what is against it and what is '
        'unknown.', 'Lets you check the ranking against the code yourself.', 'Read-only text.'),
    'leads.refresh': _tip('Reload the stored leads of this project.', 'Picks up a result prepared elsewhere.',
                          'Reads the stored result again; the stored comparison is unchanged.'),
    'leads.prepare': _tip(
        'Prepare leads from the stored comparison, the advisories and the signals already computed.',
        'Leads are computed from stored results only.', 'Stores a new derived result; nothing is sent or executed.',
        availability='Needs a completed comparison.'),
    'leads.goto': _tip('Go to the selected lead in the code panes.', 'Lets you read the changed function.',
                       'Selects its comparison row and shows the code.',
                       availability='Needs a lead that is tied to a comparison row.'),
    'leads.copy': _tip('Copy the explanation of the selected lead as plain text.', 'Lets you cite the evidence.',
                       'Puts at most 16 KiB on the clipboard.'),
    'leads.pin': _tip('Pin the selected lead to the top of its list.', 'Keeps a function you care about in view.',
                      'Adds a review event; the lead keeps its class.'),
    'leads.dismiss': _tip('Dismiss the selected lead from the list.', 'Clears a function you have ruled out.',
                          'Adds a review event; nothing is deleted and Restore brings it back.'),
    'leads.note': _tip('Add an analyst statement to the selected lead.', 'Records what you concluded.',
                       'Adds a review event shown as your own statement.'),
    'leads.show_dismissed': _tip('Also list the leads you dismissed.', 'Lets you restore one.',
                                 'Changes the rows shown; stores nothing.'),
}
TEMPLATES = {
    'leads.chip': _tip('Evidence channel {state}.', 'Shows whether this kind of evidence was available for the result.',
                       'Read-only; a channel that did not run is unknown, not a negative result.')}


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_leads import LeadsController
    return LeadsController(ctx)


PANEL = PanelSpec(
    id='leads', title='Leads', factory=_factory, area='left', shortcut='Ctrl+Shift+L', claims=CLAIMS, tips=TIPS,
    tip_templates=TEMPLATES, minimum_em=(48, 16), anchors_in=frozenset({'cve', 'match'}),
    anchors_out=frozenset({'string', 'import', 'capability', 'rule', 'build_fact', 'advisory_phrase'}))
