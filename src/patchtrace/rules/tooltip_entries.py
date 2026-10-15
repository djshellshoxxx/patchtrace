"""Tooltip entries of the Detection rules panel (What, Why, Effect, Source). Pure data; the panel registers them with the
shared registry when it is built. Every id starts with `rules.`."""
from __future__ import annotations

from ..tooltips import TooltipEntry

SOURCE = 'The rule rows stored in this project (contract yara-rules/1); nothing here is computed again.'
READ_ONLY = 'Read-only; no rule is proposed, accepted, tested or saved to a file from here.'


def _tip(what: str, why: str, effect: str, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, SOURCE, availability)


TIPS = {
    'rules.dock': _tip(
        'Dock listing the detection rules stored for this project, the builds they were tested on and the saved versions.',
        'Shows which byte, string or import patterns separate the older build from the newer one.',
        'Read-only; a rule says a file contains a pattern, not whether the file is affected.',
        'Needs a project with stored rules.'),
    'rules.action': _tip('Show or hide the Detection rules panel.', 'Keeps stored rules next to the code panes.',
                         'Toggles the dock.'),
    'rules.tabs': _tip(
        'Switch between proposed rules, the test grid and the saved rule versions.',
        'Each tab answers one question about the same stored rules.', 'Changes the view only.'),
    'rules.candidates': _tip(
        'Rules proposed for accepted function pairs, with their status and how many checks pass.',
        'Lets you see which proposal is ready to review and which one failed a check.',
        'Selecting a row fills the features, checks and rule text below.'),
    'rules.features': _tip(
        'The patterns of the selected rule. Included ones form the rule; shown-only ones did not qualify.',
        'Older and newer columns show where a pattern was counted; unknown is not zero.',
        'Read-only table.'),
    'rules.checks': _tip(
        'The checks the selected rule went through, each with its measured number and basis.',
        'A rule with an open check is not offered as separating the builds.',
        'Read-only table; checks are never combined into a score.'),
    'rules.rule_text': _tip(
        'The generated YARA-X text of the selected rule, shown as plain text.',
        'Lets you read exactly what would be saved.', 'Read-only; the text is never executed here.'),
    'rules.copy_text': _tip(
        'Copy the exact rule text of the selected rule.', 'Lets you move the rule into your own tools.',
        'Puts the text on the clipboard if it fits in 16 KiB; larger text is refused, not cut.',
        'Needs a selected rule.'),
    'rules.open_pair': _tip(
        'Go to the changed function this rule came from.', 'Lets you read the code the rule was built from.',
        'Selects the comparison row and shows the code.', 'Needs a rule whose pair is in the current comparison.'),
    'rules.grid': _tip(
        'The newest stored test: each build against each rule version, as raw results.',
        'Shows which builds contain a pattern. A file that could not be scanned stays unknown.',
        'Read-only; selecting a row shows its details.'),
    'rules.grid_role': _tip('Show only builds of one role in the test grid.', 'Narrows a long grid to the builds you compare.',
                            'Changes the rows shown; stores nothing.'),
    'rules.grid_state': _tip('Show only grid rows with one kind of result.', 'Finds the files that were not scanned or failed.',
                             'Changes the rows shown; stores nothing.'),
    'rules.unexpected_only': _tip(
        'Show only builds where a result differs from what you expected.', 'Puts surprises first.',
        'Changes the rows shown; stores nothing.'),
    'rules.detail': _tip(
        'Details of the selected item as plain text.', 'Gives the full words for a short table cell.', READ_ONLY),
    'rules.saved': _tip(
        'Rule versions you accepted. A version never changes; a revision is a new version.',
        'Shows what was saved, when, and whether it was tested.', 'Read-only; nothing is deleted or exported.'),
}
TEMPLATES: dict[str, TooltipEntry] = {}
