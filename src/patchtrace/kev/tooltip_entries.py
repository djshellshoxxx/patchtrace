"""Tooltip entries for the KEV dock (KEV-integration-plan section 8). Pure data merged into ``tooltips`` by the owner.

Rules the registry audit enforces: no angle brackets, a unique What, Availability on conditionally disabled
controls, and data-bearing ids end with the Source line.
"""
from __future__ import annotations

from ..tooltips import TooltipEntry
from . import teach

SOURCE = 'CISA KEV catalog, CC0 1.0'
_MIRROR_NOTE = "Same file contents expected; the mirror is CISA's own copy"


def _e(what: str, why: str, effect: str, source: str = '', availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


KEV_TOOLTIPS: dict[str, TooltipEntry] = {
    'kev.action': _e('Show or hide the Exploitation context (CISA KEV) dock.',
                     'Keeps CISA exploitation context one shortcut away while you work on a CVE.',
                     'Showing it downloads nothing. Shortcut Ctrl+Shift+K.'),
    'kev.dock': _e("Context from CISA's Known Exploited Vulnerabilities catalog for the CVEs you are investigating.",
                   'Shows whether CISA lists a CVE as exploited, next to the evidence you already have.',
                   'Read-only. KEV is about a CVE, not about any function in your comparison.', SOURCE),
    'kev.update': _e('Download the KEV catalog from CISA after you confirm the exact request.',
                     'Gets a current catalog without sending any project data or CVE ID.',
                     'Opens a confirmation first; the file replaces the catalog in use only after it passes checks.',
                     availability='Disabled while a download runs or when network updates are off.'),
    'kev.import': _e('Load a KEV JSON file you saved yourself.',
                     'Lets you use the catalog on a computer that is not allowed to download it.',
                     'Works offline. CSV is refused because it has no release date.'),
    'kev.consent_download': _e('Send the request shown above and download the KEV catalog.',
                               'Makes the one network request you reviewed, and no other.',
                               'Only that address and two fixed headers leave this computer.'),
    'kev.consent_cancel': _e('Close this confirmation without contacting CISA.',
                             'Lets you back out before anything is sent.',
                             'Nothing is sent; the catalog in use stays as it is.'),
    'kev.source_cisa': _e("Use CISA's website as the download source.",
                          'Takes the catalog from the publisher itself.', f'{_MIRROR_NOTE}.'),
    'kev.source_mirror': _e("Use CISA's GitHub copy as the download source.",
                            'Offers a second source if the website is unreachable from your network.',
                            f'{_MIRROR_NOTE} and may lag the website.'),
    'kev.changes': _e('Compare the catalog in use with the previous one on this computer.',
                      'Shows which CVEs CISA added or changed since you last updated.',
                      'Read-only list in the detail pane.', SOURCE, 'Needs two stored catalogs.'),
    'kev.copy': _e("Copy the selected CVE's KEV details with snapshot and source as plain text.",
                   'Lets you paste exact CISA wording and its provenance into notes or a ticket.',
                   'Clipboard only.', SOURCE),
    'kev.copy_url': _e("Copy the address of CISA's KEV catalog page.",
                       'Lets you open the official page in your own browser to check a listing.',
                       'Clipboard only. PatchTrace does not open the page.'),
    'kev.lookup_box': _e('Type or paste CVE IDs to look up in the loaded catalog.',
                         'Checks several CVEs at once without leaving the dock.',
                         'Nothing is sent anywhere; the lookup reads the catalog on this computer.',
                         availability='Needs a loaded catalog.'),
    'kev.lookup_button': _e('Look up the typed CVE IDs.',
                            'Fills the table with the KEV status of each ID.',
                            'Read-only; invalid IDs are listed as invalid, never as not listed.',
                            availability='Needs a loaded catalog.'),
    'kev.filter': _e('Show only CVEs with a chosen KEV status.',
                     'Narrows a long list to the CVEs that matter for the question you have.',
                     'Hides rows in this table only; nothing is deleted.'),
    'kev.sort': _e('Choose the reading order of the CVE list.',
                   'Puts CVEs CISA lists first when you want to read them first.',
                   'KEV-listed first keeps the input order inside each group. It is not a score and function '
                   'rankings are unaffected.'),
    'kev.table': _e('One row per CVE with its KEV status and CISA dates.',
                    'Gives a scannable overview of the CVEs under review.', 'Read-only.', SOURCE),
    'kev.detail': _e('Exact CISA wording for the selected CVE with provenance.',
                     'Shows what CISA actually says, and where this copy came from.', 'Read-only plain text.', SOURCE),
    'kev.goto': _e('Show the selected CVE in the patch-intelligence view.',
                   'Takes you from CISA context to the candidate functions for the same CVE.',
                   'Switches the view; nothing is recomputed.', availability='Needs a comparison linked to this CVE.'),
}

KEV_TEMPLATES: dict[str, TooltipEntry] = {
    'kev.cell': _e('{cve}: KEV status {state}, catalog {version}.', 'Meaning: {meaning}',
                   'Read-only. KEV is about the CVE, not about any function.', SOURCE),
    'kev.badge': _e('{state}: {meaning}', 'The word carries the meaning; no colour implies severity.',
                    'Read-only.', SOURCE),
    'kev.column': _e('Column {state}: {meaning}', 'Know what the column does and does not say.',
                     'Read-only.', SOURCE),
    'kev.row_header': _e('{cve}: KEV status {state}.', 'Row meaning: {meaning}', 'Read-only.', SOURCE),
}

# Column header tooltips fill kev.column with state = the column name and meaning = this text.
COLUMN_MEANINGS = {
    'KEV': teach.MEANING_KEV, 'Added to KEV': teach.MEANING_ADDED, 'CISA due date': teach.MEANING_DUE,
    'Known ransomware campaign use': teach.MEANING_RANSOMWARE,
}
