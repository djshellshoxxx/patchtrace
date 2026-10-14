"""Tooltip entries of the Strings panel as plain data (spec WB3 s8). Pure: no Qt, no `tooltips` import.

Each value is `(what, why, effect, source, availability)`, the field order of `tooltips.TooltipEntry`, so the
`tooltips.register_entries()` hook (A7) can merge them without this module knowing that class.
"""
from __future__ import annotations

_READ = 'Read-only.'
_SOURCE = 'Strings come from the built-in scan or FLOSS; PatchTrace never runs the files.'


def _t(what: str, why: str, effect: str = _READ, source: str = '', availability: str = '') -> tuple[str, ...]:
    return what, why, effect, source, availability


def _col(what: str, why: str) -> tuple[str, ...]:
    return _t(what, why)


ENTRIES: dict[str, tuple[str, ...]] = {
    'strings.dock': _t('Strings of the older and newer build, side by side.',
                       'Shows which text was added, removed or edited, in review order.',
                       'Nothing changes in the project.', _SOURCE, 'Needs an open project with two builds.'),
    'strings.action': _t('Shows or hides the Strings panel.', 'Keeps the string comparison within reach.',
                         'Only the panel visibility changes.'),
    'strings.table': _t('One row per string that differs, in review order.',
                        'Review order is a reading order, not a finding.', 'Selecting a row shows its detail.',
                        _SOURCE),
    'strings.col.change': _col('Whether the string is only in the newer build, only in the older, edited or moved.',
                               'Shown as a symbol and a word, never colour alone.'),
    'strings.col.string': _col('The string text with control characters escaped.',
                               'Hostile or invisible characters stay visible and harmless.'),
    'strings.col.type': _col('How the string was found: static, stack, tight loop or decoded.',
                             'Emulated types can miss strings, so absence there is unknown.'),
    'strings.col.older': _col('Where the string sits in the older build.', 'Lets you open the bytes in the hex view.'),
    'strings.col.newer': _col('Where the string sits in the newer build.', 'Lets you open the bytes in the hex view.'),
    'strings.col.function': _col('The function that uses the string, when a link is known.',
                                 'An empty cell means no link was found, not that none exists.'),
    'strings.col.cues': _col('Short content labels such as message, path or format specifier.',
                             'Cues help you scan the list; they are not a verdict.'),
    'strings.col.source': _col('The tool that extracted the string.', 'Different tools can disagree on edge cases.'),
    'strings.filter.change': _t('Limits rows to one kind of change.', 'Helps you read additions first.',
                                'Only the list changes.'),
    'strings.filter.type': _t('Limits rows to chosen string types.', 'Separates plain strings from emulated ones.',
                              'Only the list changes.'),
    'strings.filter.side': _t('Limits rows to strings seen in one build.', 'Keeps older and newer orientation clear.',
                              'Only the list changes.'),
    'strings.filter.cue': _t('Limits rows to strings with a chosen content cue.', 'Narrows a long list quickly.',
                             'Only the list changes.'),
    'strings.filter.minlen': _t('Hides strings shorter than this length.', 'Short strings are often incidental.',
                                'Only the list changes; both builds use the same limit.'),
    'strings.filter.text': _t('Shows rows whose text contains what you type.', 'Finds a known word quickly.',
                              'Only the list changes; the text is matched as plain text.'),
    'strings.filter.scope': _t('Chooses between changed strings and every string.',
                               'The default shows only differences.', 'Only the list changes.'),
    'strings.filter.noise': _t('Hides strings that look like data rather than text.',
                               'Keeps the inventory view readable.',
                               'Only the inventory list changes; the count of hidden rows stays visible.'),
    'strings.run.builtin': _t('Reads the strings of both builds with the built-in scan.',
                              'Needs no setup and never runs the files.', 'Stores the result with the project.',
                              'Built-in scan.', 'Needs an open project.'),
    'strings.run.floss': _t('Runs FLOSS on both builds for extra string types.',
                            'Finds stack, tight and decoded strings the plain scan cannot.',
                            'Starts a tool run after your confirmation.', 'FLOSS 3.1.1.',
                            'Needs a FLOSS path you chose.'),
    'strings.run.emulation': _t('Lets FLOSS emulate code to recover hidden strings.',
                                'Emulation is slow and can miss strings, so results are heuristic.',
                                'Asks for consent first; time and memory are capped.', 'FLOSS 3.1.1.',
                                'Needs a FLOSS path you chose.'),
    'strings.cancel': _t('Stops the running scan after the current file.', 'Frees the machine.',
                         'Nothing is saved from a cancelled run.', availability='Only while a scan runs.'),
    'strings.probe': _t('Checks the FLOSS file you chose.', 'Confirms its hash and version before use.',
                        'Runs the tool with its version option only.', availability='Needs a FLOSS path.'),
    'strings.browse': _t('Chooses the FLOSS executable.', 'PatchTrace never searches PATH or downloads tools.',
                         'Stores the path only.'),
    'strings.basis': _t('Says whether the two scans can be compared and what was harmonized.',
                        'Different settings would make differences misleading.', _READ),
    'strings.detail': _t('Full text and provenance of the selected string.',
                         'Shows both values for an edited string and the code points of a look-alike.', _READ),
    'strings.rescan': _t('Scans the older build again with the newer build\'s settings.',
                         'Makes the two scans comparable.', 'Replaces the older scan after it finishes.',
                         availability='Shown when the scans are not comparable.'),
    'strings.copy.safe': _t('Copies the escaped single-line form of the selected rows.',
                            'Control characters stay visible, and secret-like text stays hidden.',
                            'Copies up to 200 rows or 16 KiB.'),
    'strings.copy.exact': _t('Copies the exact text of the selected string.',
                             'Control characters may behave oddly where you paste them.',
                             'Asks first when the text holds control characters.'),
    'strings.open.function': _t('Opens the function that uses the selected string.',
                                'Shows the string in its code context.', 'Moves the main view to that function.',
                                availability='Needs a linked function pair.'),
    'strings.open.hex': _t('Opens the bytes of the string in the hex view.', 'Shows the raw bytes around it.',
                           'Moves the hex view to the offset.', availability='Needs a known offset.'),
    'strings.export': _t('Writes the listed strings to a file.', 'Lets you share the review list.',
                         'Creates a file you name; secret-like text is hidden unless you ask otherwise.',
                         availability='Needs results.'),
}
