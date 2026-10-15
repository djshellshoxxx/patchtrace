"""The Unified panel's declaration for the panel host (SPEC-31 07 s8, GUI plan F5). Pure: Qt loads only when the
factory runs. The panel is a tab of the evidence dock (manifest slot `unified`, Ctrl+Shift+U): the unified result is a
view of the one main window, never a window of its own.

Tips are plain text with WHAT, WHY and EFFECT; the claims profile keeps the panel to function pairing and change
classes (no probability wording, no vulnerability claims)."""
from __future__ import annotations

from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..gui.text import CLAIMS_PAIRING
from ..tooltips import TooltipEntry
from .registry import REGISTRY

_DERIVED = 'Derived by PatchTrace from the stored engine results of this project; rule-based and uncalibrated.'
_NEEDS_RESULT = 'Needs a stored unified result.'
_NEEDS_PROJECT = 'Needs an open project.'


def _tip(what: str, why: str, effect: str, source: str = _DERIVED, availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


_BASE: dict[str, TooltipEntry] = {
    'unified.dock': _tip(
        'Dock tab with the unified comparison of the older and newer build.',
        'See where stored engines agree or disagree on function pairings, next to the primary Ghidriff view.',
        'Read-only view; the primary Ghidriff results stay unchanged.', availability=_NEEDS_PROJECT),
    'unified.action': _tip(
        'Show or hide the Unified panel.', 'Keeps the derived comparison next to the engine evidence.',
        'Toggles the dock tab.'),
    'unified.view_switch': _tip(
        'Switch to the Engine evidence tab next to this one.',
        'That tab shows the per-engine view; this one adds the derived unified view of the same project.',
        'Shows the other tab. Nothing is computed.'),
    'unified.run': _tip(
        'Run unified analysis on the stored engine outputs of this project.',
        'Adds a derived result that pairs functions across all stored engines.',
        'Writes a new result into the project. Never executes a target binary and uses no network.',
        'PatchTrace unified pipeline.',
        'Needs an open project, a finished Ghidriff run, no other job, and the setting unified/enabled.'),
    'unified.cancel': _tip(
        'Cancel the running unified analysis.', 'Stops work you no longer need.',
        'The previous result stays current; nothing partial is published.', availability='Only while a run is active.'),
    'unified.filter_decision': _tip(
        'Show only rows with the chosen pairing decisions.',
        'Contested and ambiguous rows are never hidden unless you leave them out here.',
        'Narrows the table; no data changes.', availability=_NEEDS_RESULT),
    'unified.filter_change': _tip(
        'Show only rows with the chosen change classification.',
        'The default lists material, review, unknown and not-applicable rows; unchanged and structurally '
        'cosmetic rows are counted, not listed.',
        'Narrows the table; no data changes.', availability=_NEEDS_RESULT),
    'unified.filter_class': _tip(
        'Show only rows that carry the chosen change class.', 'Focus on one kind of difference, such as a callee.',
        'Narrows the table; no data changes.', availability=_NEEDS_RESULT),
    'unified.filter_source': _tip(
        'Show only rows that have a record from the chosen engine.',
        'Find the rows one engine pairs, or leaves out.', 'Narrows the table; no data changes.',
        availability=_NEEDS_RESULT),
    'unified.search': _tip(
        'Search function names and hexadecimal addresses, with or without 0x.',
        'Jump to one function in a long list.', 'Narrows the table after a short pause; no data changes.',
        availability=_NEEDS_RESULT),
    'unified.show_hidden': _tip(
        'List the unchanged and structurally cosmetic rows that are collapsed by default.',
        'The count is always visible; one click shows the rows.', 'Widens the table; no data changes.',
        availability=_NEEDS_RESULT),
    'unified.table': _tip(
        'One row per function pairing, with each engine in its own column.',
        'Native values are engine-specific: they carry their own units and are never combined.',
        'Select a row to see its details; Enter shows it in the code panes.', availability=_NEEDS_RESULT),
    'unified.tab': _tip(
        'The unified comparison of this project.', 'Review pairings and change classes in one place.',
        'Read-only.', availability=_NEEDS_PROJECT),
    'unified.detail': _tip(
        'Plain-text details of the selected row.',
        'Shows support by component, contest, change facts, limitations and provenance.',
        'Read-only; text is shown as plain text.', availability='Needs a selected row.'),
    'unified.goto': _tip(
        'Show the selected row in the code panes of the main window.',
        'Compare the code of the pair next to the evidence.',
        'Selects the Ghidriff match, or shows the stored decompiled C or disassembly of this row in this tab.',
        availability='Needs a selected row.'),
    'unified.code_mode': _tip(
        'Choose which code of the selected row to compare: decompiled C or the stored disassembly.',
        'Decompiled C exists only for pairs the analysis decompiled on demand; the disassembly comes from the stored '
        'ProgramIR. A choice without text says why instead of showing code.',
        'Switches the two code panes of this tab; nothing is computed.', 'Stored unified result.',
        'Needs a row shown with Enter or Go to match.'),
    'unified.code_prev': _tip(
        'Jump to the previous changed region in both code panes.', 'Walk through the differences of one function.',
        'Scrolls both panes to the region; nothing changes.', availability='Needs code with at least one change.'),
    'unified.code_next': _tip(
        'Jump to the next changed region in both code panes.', 'Walk through the differences of one function.',
        'Scrolls both panes to the region; stops at the last one.', availability='Needs code with at least one change.'),
    'unified.code_copy': _tip(
        'Copy this side code with its provenance line as plain text.',
        'Keep the exact function, source and artifact digests next to the code you quote.',
        'Puts the text on the clipboard; the view is capped at 200,000 characters.', availability='Needs code on this side.'),
    'unified.code_older': _tip(
        'Older artifact code of the selected row, read only.',
        'Gaps are rows where the older side has no counterpart of the newer code; nothing is invented.',
        'Plain text; scrolls together with the newer pane.', 'Stored unified result.',
        'Needs a row shown with Enter or Go to match.'),
    'unified.code_newer': _tip(
        'Newer artifact code of the selected row, read only.',
        'Gaps are rows where the newer side has no counterpart of the older code; nothing is invented.',
        'Plain text; scrolls together with the older pane.', 'Stored unified result.',
        'Needs a row shown with Enter or Go to match.'),
    'unified.correct': _tip(
        'Correct the function relationship of the selected row.', 'Record an analyst decision with its reason.',
        'Opens the existing correction dialog for the Ghidriff match of this row.',
        'Existing manual correction store.', 'Needs a row that maps to a Ghidriff match and no running job.'),
    'unified.copy': _tip(
        'Copy the provenance of the selected rows as plain text.', 'Keep the exact inputs next to your notes.',
        'Puts at most 16 KiB on the clipboard.', availability='Needs a selected row.'),
    'unified.explain': _tip(
        'Preview the bounded text that describes the selected row.',
        'Review exactly what a later explanation could use before anything leaves the machine.',
        'Shows the text; nothing is transmitted from here.', availability='Needs a selected row.'),
    'unified.retry': _tip(
        'Run the unified analysis again after a failure.', 'Earlier results and the primary view are unchanged.',
        'Starts a new run.', availability='Only after a failed run.'),
    'unified.copy_error': _tip(
        'Copy the error details as plain text.', 'Include the exact code and message in a report.',
        'Puts the text on the clipboard.', availability='Only after a failed run.'),
    'unified.stale_banner': _tip(
        'Notices about this result, such as stale inputs, partial evidence or missing extraction.',
        'A stale or partial result is shown for reference; missing evidence is unknown, not disagreement.',
        'Read-only. Run unified analysis again to refresh a stale result.',
        availability='Shown only when the result has notices.'),
    'unified.source.unknown': _tip(
        'Column of an engine this build does not know.', 'The values are shown as stored, without interpretation.',
        'Read-only.', availability=_NEEDS_RESULT),
}

TEMPLATES: dict[str, TooltipEntry] = {
    'unified.row': TooltipEntry(
        'Unified row for {function}.', 'Review decision {decision} and the change classification {change}.',
        'Read-only.', 'Derived from the stored engines: {sources}.', 'Addresses: {reason}.'),
    'unified.cell': TooltipEntry(
        '{source} native value {value}, unit: {unit}.',
        'Different engines use different scales and are never combined.', 'Read-only.', '{provenance}.',
        'Details: {reason}.'),
    'unified.badge': TooltipEntry(
        '{decision}: {meaning}', 'Decisions concern function pairing only.', 'Read-only.',
        'Rule-based and uncalibrated.', ''),
    'unified.delta': TooltipEntry(
        'Change {kind} between the older and newer function.', 'Review what differs, with its channel and addresses.',
        'Read-only.', '{provenance}.', 'Details: {reason}.'),
}


def source_tips() -> dict[str, TooltipEntry]:
    """One tip per registry source (`unified.source.<id>`), worded from its registry row."""
    out = {}
    for source in REGISTRY.sources:
        out[source.tooltip_id] = _tip(
            f'Column with the native values of {source.display}.',
            f'Each value is in {source.unit_caption or "its own unit"} and is never compared with another engine.',
            'Read-only.', source.licence_note or _DERIVED, _NEEDS_RESULT)
    return out


TIPS: dict[str, TooltipEntry] = _BASE | source_tips()


def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_unified import UnifiedController
    return UnifiedController(ctx)


PANEL = PanelSpec(
    id='unified', title='Unified', factory=_factory, area='right', tabify_with='evidence', shortcut='Ctrl+Shift+U',
    claims=CLAIMS_PAIRING, requires=('project',), tips=TIPS, tip_templates=TEMPLATES, minimum_em=(48, 16))
