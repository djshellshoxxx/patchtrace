"""Tooltip entries of the KB and CVE panel (What/Why/Effect/Source). Panel-owned: the shared tooltips module is not
edited; the panel registers these when its factory runs. Plain text only."""
from __future__ import annotations

from ..tooltips import TooltipEntry

SOURCE = 'The advisory context stored for this project and the stored comparison ranking; each line names its source.'


def _tip(what: str, why: str, effect: str, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, SOURCE, availability)


TIPS = {
    'kb.dock': _tip(
        'Dock that pairs the advisory documents you loaded with the changed functions of this comparison.',
        'Shows which changed functions deserve a look for each CVE, and what is still unknown.',
        'Read-only; it reads stored results and sends nothing.',
        'Needs a project with an attached advisory context or a ranked comparison.'),
    'kb.action': _tip('Show or hide the KB and CVE panel.', 'Keeps the advisory leads next to the code panes.',
                      'Toggles the dock.'),
    'kb.table': _tip(
        'Changed functions grouped by CVE, in the engine\'s own attention order, with the evidence of each channel.',
        'Shows where to look first and which kind of evidence supports each line.',
        'Selecting a row fills the details below; a row never states that a function contains or fixes a CVE.'),
    'kb.group': _tip('Choose one CVE group, or all groups.', 'Narrows a long list to the advisory you are reading.',
                     'Changes the rows shown; stores nothing.'),
    'kb.search': _tip('Filter the rows by function name or text.', 'Finds a function you already know.',
                      'Changes the rows shown; stores nothing.'),
    'kb.detail': _tip('Evidence of the selected row, one line per channel, and the basis of its order.',
                      'Lets you check each channel yourself; an unknown channel is not a negative result.',
                      'Read-only text.'),
    'kb.footer': _tip('What was checked, what does not apply and what is unknown for this context.',
                      'Coverage and limits stay visible so that a short list is not read as a clean result.',
                      'Read-only text.'),
    'kb.refresh': _tip('Reload the stored KB and CVE leads of this project.', 'Picks up a context or ranking prepared elsewhere.',
                       'Reads stored results again; nothing is downloaded or run.'),
    'kb.goto': _tip('Go to the selected function in the code panes.', 'Lets you read the changed function.',
                    'Selects its comparison row.',
                    'Needs a current result and a row that is tied to a comparison row.'),
    'kb.copy': _tip('Copy the evidence of the selected row as plain text.', 'Lets you cite the evidence.',
                    'Puts at most 16 KiB on the clipboard.', 'Needs a selected function row.'),
}
TEMPLATES: dict[str, TooltipEntry] = {}
