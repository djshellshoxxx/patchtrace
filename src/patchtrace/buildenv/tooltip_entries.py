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
        'The build-environment property described by this row.',
        'Identifies the compiler, linker, runtime or other recorded build detail.',
        'Explains the heading; displayed values and comparison states stay unchanged.'),
    'build_env.col.older': _tip(
        'The recorded value shown for the older file in this row.',
        'Compare it with NEWER and read Status and Basis together. A dash means no value is shown for this side.',
        'Explains the heading; displayed values and comparison states stay unchanged.'),
    'build_env.col.newer': _tip(
        'The recorded value shown for the newer file in this row.',
        'Compare it with OLDER and read Status and Basis together. A dash means no value is shown for this side.',
        'Explains the heading; displayed values and comparison states stay unchanged.'),
    'build_env.col.status': _tip(
        'The recorded comparison state for this build fact.',
        'Changed, added, removed, same, or unknown (one side) describes this fact only. Unknown is not a difference.',
        'Explains the heading; displayed values and comparison states stay unchanged.',
        'The build-environment comparison of the recorded facts.'),
    'build_env.col.basis': _tip(
        'The recorded source or sources supporting this fact comparison.',
        'Shows where the values came from, such as a PE header or Detect It Easy signature. '
        'Signatures and header fields do not prove how a file was built.',
        'Explains the heading; displayed values and comparison states stay unchanged.'),
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
