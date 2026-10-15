"""Tooltip entries of the KEV dock (KEV-integration-plan section 8), pure data for the host to register.

The panel registry (or ``tooltips.register_entries``) merges ``KEV_TOOLTIPS`` into ``tooltips.REGISTRY`` and
``KEV_TEMPLATES`` into ``tooltips.TEMPLATES``; nothing is registered here, so importing this module changes no global.
Rules (tests/test_kev_view_model.py): every id starts ``kev.``, texts hold no angle brackets, every What is unique, Why
is one sentence that names the analyst benefit, a control that can be disabled says when under Availability, and an
entry that shows catalog data ends its Source with ``CISA KEV catalog, CC0 1.0``.
"""
from __future__ import annotations

from ..tooltips import TooltipEntry

SOURCE = 'CISA KEV catalog, CC0 1.0'
DOCK_SHORTCUT = 'Ctrl+Shift+X'           # the GUI plan (8.2) gives KEV X; K stays with the KB dock


def _e(what: str, why: str, effect: str, source: str = '', availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


KEV_TOOLTIPS: dict[str, TooltipEntry] = {
    'kev.action': _e(
        'Show or hide the Exploitation context (CISA KEV) dock.',
        'Keeps exploitation context one shortcut away without cluttering the comparison.',
        f'Showing it downloads nothing. Shortcut {DOCK_SHORTCUT}.'),
    'kev.dock': _e(
        "Context from CISA's Known Exploited Vulnerabilities catalog for the CVEs you are investigating.",
        'Shows whether CISA lists a CVE without leaving the comparison.',
        'Read-only. KEV is about a CVE, not about any function in your comparison.', SOURCE),
    'kev.update': _e(
        'Download the KEV catalog from CISA after you confirm the exact request.',
        'Keeps the exploitation context current without sending any of your data.',
        'Opens a confirmation first; the file replaces the catalog in use only after it passes checks.',
        availability='Disabled while a download runs or when network updates are off.'),
    'kev.import': _e(
        'Load a KEV JSON file you saved yourself.',
        'Lets you work offline or behind a proxy with a catalog you obtained elsewhere.',
        'Works offline. CSV is refused because it has no release date.'),
    'kev.consent_download': _e(
        'Send the request shown above and download the KEV catalog.',
        'Makes the one network request you just reviewed, and nothing else.',
        'Only that address and two fixed headers leave this computer.'),
    'kev.consent_cancel': _e(
        'Close this confirmation without contacting CISA.',
        'Lets you back out before anything is sent.',
        'Nothing is sent and the catalog in use stays as it is.'),
    'kev.source_cisa': _e(
        "Use CISA's website as the download source.",
        'Fetches the catalog from its original publisher.',
        'The same file contents are expected from either source.'),
    'kev.source_mirror': _e(
        "Use CISA's GitHub copy as the download source.",
        'Offers a second route to the same catalog when the website is unreachable.',
        "Same file contents expected; the mirror is CISA's own copy."),
    'kev.changes': _e(
        'Compare the catalog in use with the previous one on this computer.',
        'Shows which CVEs CISA added or changed since you last updated.',
        'Read-only list; nothing is downloaded or deleted.', SOURCE,
        'Needs two stored catalogs.'),
    'kev.copy': _e(
        "Copy the selected CVE's KEV details with snapshot and source as plain text.",
        'Gives you a reproducible record of what the catalog said and when.',
        'Clipboard only.', SOURCE),
    'kev.copy_url': _e(
        "Copy the address of CISA's KEV catalog page.",
        'Lets you open the official catalog in your own browser to check an entry.',
        'Clipboard only.'),
    'kev.lookup_box': _e(
        'Type or paste CVE IDs to look up in the loaded catalog.',
        'Checks the CVEs of an advisory or a KB against CISA\'s list in one step.',
        'Nothing is looked up until you press Enter or Look up.',
        availability='Needs a loaded catalog.'),
    'kev.lookup_button': _e(
        'Look up the typed CVE IDs.',
        'Answers whether each typed CVE is in the loaded catalog.',
        'Fills the table below; nothing is sent over the network.',
        availability='Needs a loaded catalog.'),
    'kev.filter': _e(
        'Show only CVEs with a chosen KEV status.',
        'Narrows a long list to the CVEs that matter for the question you are asking.',
        'Hides rows from the list only; the catalog and the lookups are unchanged.'),
    'kev.sort': _e(
        'Choose the reading order of the CVE list.',
        'Lets you read the listed CVEs first when time is short.',
        'KEV-listed first keeps the input order inside each group. It is not a score and function rankings are '
        'unaffected.'),
    'kev.table': _e(
        'One row per CVE with its KEV status and CISA dates.',
        'Gives an overview you can scan before opening any CVE.',
        'Read-only. Select a row to see its details.', SOURCE),
    'kev.detail': _e(
        'Exact CISA wording for the selected CVE with provenance.',
        'Lets you quote CISA correctly and see which snapshot said it.',
        'Read-only plain text; nothing here is clickable or executed.', SOURCE),
    'kev.goto': _e(
        'Show the selected CVE in the patch-intelligence view.',
        'Takes you from the exploitation context to the changed code that may relate to the CVE.',
        'Switches to that view for this CVE; nothing is downloaded.',
        availability='Needs a comparison linked to this CVE.'),
}

# {cve}, {state}, {version} and {meaning} are filled from control-stripped, escaped values by tooltips.template.
KEV_TEMPLATES: dict[str, TooltipEntry] = {
    'kev.cell': _e(
        '{cve}: KEV status {state}, catalog {version}.',
        'States the CVE and the catalog in the cell itself, so a screenshot of one cell is self-describing.',
        'Read-only.', SOURCE),
    'kev.badge': _e(
        '{state}: {meaning}',
        'The words carry the meaning; no colour implies severity.',
        'Read-only.', SOURCE),
    'kev.column': _e(
        '{meaning}',
        'Explains what this column states and what it does not.',
        'Read-only.', SOURCE),
    'kev.row_header': _e(
        'CVE {cve} in catalog {version}.',
        'Names the row\'s CVE and the snapshot that answers for it.',
        'Read-only.', SOURCE),
}
