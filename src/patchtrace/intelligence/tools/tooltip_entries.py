"""Tooltip entries of the Capabilities panel (CAP-6a/6b). Pure: no Qt. Every entry has What, Why, Effect and Source;
ids start with `capabilities.` (rule `tip-prefix`), and the wording stays neutral (CLAIMS_NEUTRAL)."""
from __future__ import annotations

from ...tooltips import TooltipEntry

SOURCE = 'Stored capa evidence and the current function pairing of this project.'
SETUP_SOURCE = 'The capa program you chose and its own probe output.'
LOCAL = 'Changes the local view only; nothing is run, stored or sent.'


def _tip(what: str, why: str, effect: str, source: str = SOURCE, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


TIPS = {
    'capabilities.dock': _tip(
        'Compare behaviours recognised by capa in the older and newer functions.',
        'Behaviour changes help choose code to inspect.', 'Read-only; showing this panel runs nothing.'),
    'capabilities.action': _tip('Show or hide the Capabilities panel.', 'Keeps behaviour context beside the comparison.',
                                'Toggles this dock; Ctrl+Shift+A.', 'Panel registry.'),
    'capabilities.tabs': _tip('Choose Changes or Setup and run.',
                              'Separates stored observations from an explicit tool operation.',
                              'Changes the local view; nothing runs on tab selection.', 'Capabilities panel.'),
    'capabilities.table': _tip(
        'Capability changes between matched function pairs, grouped as you chose.',
        'Shows which recognised behaviours differ, and in which pair.',
        'Selecting a row fills the details below; Enter goes to the pair.'),
    'capabilities.filter': _tip('Show only one kind of change.', 'Narrows a long list to the part you are reading.',
                                LOCAL),
    'capabilities.group_by': _tip('Choose how rows are grouped.', 'Grouping by namespace or pair eases reading.',
                                  'Labels used for grouping never change a row or its order.'),
    'capabilities.search': _tip('Filter by rule, namespace or function name.', 'Finds a behaviour you already know.',
                                LOCAL),
    'capabilities.show_noise': _tip(
        'Also list rows where the matched code is unchanged but capa detected differently.',
        'Such rows come from analysis differences, not from new code.', LOCAL),
    'capabilities.show_unattributed': _tip(
        'Also list capa matches that could not be tied to a function.', 'They are not lost, only unplaced.', LOCAL),
    'capabilities.show_library': _tip(
        'Also list building-block rules that capa uses inside other rules.',
        'They are not behaviours on their own, so they are hidden at first.', LOCAL),
    'capabilities.detail': _tip(
        'Why capa matched, what each side holds and what is unknown for the selected row.',
        'Lets you check the row against the code yourself.', 'Read-only text.'),
    'capabilities.goto': _tip(
        'Go to the stored match of the selected function pair.', 'Lets you read the changed functions.',
        'Selects the comparison row and shows the code.',
        availability='Needs a row that belongs to one stored match.'),
    'capabilities.copy': _tip(
        'Copy the provenance of the selected row as plain text.', 'Lets you cite the evidence and the tool setup.',
        'Puts at most 16 KiB of text on the clipboard.'),
    'capabilities.refresh': _tip(
        'Read the saved capa output of this project again.', 'Picks up results written elsewhere.',
        'Re-reads stored data; capa is not run again.'),
    'capabilities.retry': _tip('Try the failed read again.', 'Recovers without reopening the project.',
                               'Repeats only the read that failed.'),
    'capabilities.cancel': _tip(
        'Cancel the running capa operation or the read in progress.', 'Stops work you no longer need.',
        'Earlier results stay as they were.'),
    'capabilities.path': _tip('The capa program to use, as an absolute path.',
                              'PatchTrace never searches PATH or downloads capa.',
                              'Editing only records your choice; the program is not started.', SETUP_SOURCE),
    'capabilities.browse': _tip('Choose an installed capa program on this computer.',
                                'You decide which program is trusted.', 'Fills the path field; nothing is started.',
                                SETUP_SOURCE),
    'capabilities.probe': _tip(
        'Ask the chosen program for its version and options, and hash it.',
        'Shows whether this capa can be used before any file is analysed.',
        'Starts the program with its version options only; no project file is given to it and no network is used.',
        SETUP_SOURCE),
    'capabilities.backend': _tip('Choose how capa analyses code.', 'The two backends can find different functions.',
                                 'Changes the pending options and clears any preview.', SETUP_SOURCE),
    'capabilities.timeout': _tip('Seconds each file may take.', 'Stops a run that does not finish.',
                                 'Changes the pending options and clears any preview.', SETUP_SOURCE),
    'capabilities.run': _tip(
        'Prepare a run of capa on both files and show exactly what would happen.',
        'You confirm the exact program, files and limits first.', 'Shows a preview only; nothing starts yet.',
        SETUP_SOURCE, 'Needs a probed capa that can be used and two project files.'),
    'capabilities.confirm_run': _tip(
        'Start capa on the older and then the newer file, as shown in the preview.',
        'Stores capa output so changes can be compared.',
        'Runs the chosen program locally on private copies; the files themselves are not run and no network is used.',
        SETUP_SOURCE, 'Needs a complete preview.'),
    'capabilities.cancel_preview': _tip('Close the preview without running anything.', 'Lets you change the setup.',
                                        'Nothing starts.', SETUP_SOURCE),
    'capabilities.preview': _tip('Everything the run would use: files, program, version, rules and limits.',
                                 'Lets you check the run before it starts.', 'Read-only text.', SETUP_SOURCE),
    'capabilities.log': _tip('Bounded notes about the last probe or run.', 'Explains a refusal in words.',
                             'Read-only text.', SETUP_SOURCE),
}
TEMPLATES = {
    'capabilities.chip': _tip('{state}', 'Shows the kind of change with a shape as well as a colour.',
                              'Read-only; a missing result is unknown, not a negative one.')}
