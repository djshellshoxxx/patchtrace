"""Tooltip entries of the Build environment panel (DIE D5). Pure data: the panel registers them when it is created,
and `panel_manifest` lint reads them from the spec. Ids start with `build_env.` (panel prefix, GUI plan 6.4)."""
from __future__ import annotations

from ..tooltips import TooltipEntry

SOURCE = 'Hash-checked PE header facts and stored Detect It Easy results of this project.'


def _tip(what: str, why: str, effect: str, source: str = SOURCE, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


TIPS = {
    'build_env.dock': _tip(
        'Dock with the build facts and pre-flight cautions of the current pair.',
        'Keeps the basis of the code comparison visible next to it.',
        'Opening it reads PE header facts and stored results only; no file is executed.',
        'The build-environment delta of the two files.', 'Needs a project with an older and a newer file.'),
    'build_env.action': _tip('Show or hide the Build environment panel.', 'Reach the build facts from the keyboard.',
                             'Toggles the dock.', 'The panel registry.'),
    'build_env.table': _tip(
        'One row per build fact with its older value, newer value, status and basis.',
        'Shows what changed between the builds and how each fact is known.',
        'Selecting a row shows its detail; Ctrl+C copies the selected rows as text.'),
    'build_env.col.fact': _tip(
        'Identify the build field being compared.',
        'Keeps each observation attached to its documented meaning.',
        'Shows the fact name without changing or deriving a value.',
        'The BuildFact key and display label.'),
    'build_env.col.older': _tip(
        'Read this fact for the older artifact.',
        'Shows what the baseline evidence records or leaves unknown.',
        'Displays the retained value without filling missing data.',
        'The older build fingerprint.'),
    'build_env.col.newer': _tip(
        'Read this fact for the newer artifact.',
        'Shows the later evidence separately from the baseline.',
        'Displays the retained value without filling missing data.',
        'The newer build fingerprint.'),
    'build_env.col.status': _tip(
        'Read the comparison status for this fact.',
        'Distinguishes differences, matches and unknown comparisons.',
        'Displays the status without changing the comparison.',
        'The build-fact comparison rules.'),
    'build_env.col.basis': _tip(
        'Read the evidence basis for this build observation.',
        'Distinguishes PE fields, derived facts, signature matches and weak hints.',
        'Displays the recorded source without strengthening the claim.',
        'The build-fact source and basis metadata.'),
    'build_env.detail': _tip(
        'Provenance of the facts: file hashes, tool version, database and cautions, as plain text.',
        'Lets you check where each fact came from.', 'Read-only text; at most 8 KiB.'),
    'build_env.technical': _tip(
        'Also list raw Rich header entries and header anomalies in the detail text.',
        'Lets you check a fact against the raw header values.', 'Changes the detail text only; stores nothing.'),
    'build_env.reread': _tip(
        'Read the build facts of both files again.', 'Picks up stored results prepared elsewhere.',
        'Reads the project files and stored results again; no tool is run and nothing is written.'),
    'build_env.cancel': _tip('Stop reading the build facts.', 'A large file can take a moment.',
                             'Keeps the earlier results; nothing is changed.',
                             availability='Shown while a read is running.'),
    'build_env.copy': _tip(
        'Copy the build facts, hashes and cautions as plain text.', 'Lets you cite the basis of a comparison.',
        'Puts at most 16 KiB on the clipboard.'),
}
TEMPLATES: dict[str, TooltipEntry] = {}
