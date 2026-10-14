"""Fixed analyst-facing copy for the KEV context (KEV-integration-plan section 8). Pure strings, no markup.

The wording keeps three claims apart: KEV says a CVE is listed as exploited, it does not locate any function, and
"Not listed" is not "safe". Only the sanctioned negations (see ``SANCTIONED_NEGATIONS``) may mention exploitation.
"""
from __future__ import annotations

NOT_EXPLOITED_NEGATION = 'does not mean not exploited'
UNEXPLOITED_NEGATION = 'not evidence that the CVE is unexploited'
SANCTIONED_NEGATIONS = (NOT_EXPLOITED_NEGATION, UNEXPLOITED_NEGATION, 'has not been shown to be unexploited')

# Cell texts (the KEV column).
CELL_LISTED = 'Listed'
CELL_LISTED_RANSOMWARE = 'Listed - ransomware known'
CELL_NOT_LISTED = 'Not listed'
CELL_NO_CATALOG = 'No catalog'
CELL_INVALID = 'Invalid CVE ID'
COLUMNS = ('CVE', 'KEV', 'Added to KEV', 'CISA due date', 'Known ransomware campaign use')

RANSOMWARE_KNOWN = 'CISA reports this vulnerability has been leveraged as part of a ransomware campaign.'
RANSOMWARE_UNKNOWN = ('CISA lacks confirmation that this vulnerability has been utilized for ransomware. '
                      'This is not a statement that it has not been.')
MEANING_ADDED = 'The date CISA added this CVE to the catalog. It is not the date exploitation began or the date a fix shipped.'
MEANING_DUE = ('The date CISA lists for completing the required action. It is a CISA date for the organizations its '
               'directive covers, not a Microsoft date and not a severity rating.')
MEANING_RANSOMWARE = f'Known: {RANSOMWARE_KNOWN} Unknown: {RANSOMWARE_UNKNOWN}'
MEANING_KEV = ('Listed: CISA lists this CVE as a known exploited vulnerability. Not listed: absent from this catalog '
               f'snapshot, which {NOT_EXPLOITED_NEGATION}. No catalog: nothing is loaded.')

WHAT_THIS_MEANS_LISTED = ('CISA lists this CVE as a known exploited vulnerability. It does not say which builds, KBs, '
                          'files or functions were involved, and it does not show that any function changed in your '
                          'comparison relates to this CVE.')
WHAT_THIS_MEANS_NOT_LISTED = ('this snapshot does not list the CVE. That is not evidence that the CVE is unexploited: '
                              'CISA lists only entries that meet its own requirements, and the catalog may have '
                              'changed since this snapshot.')
NO_CATALOG_DETAIL = ('Nothing can be said about this CVE until a catalog is loaded. '
                     'Use Update from CISA... or Import file...')
INVALID_ID_DETAIL = 'Expected CVE-YYYY-NNNN with ASCII digits (for example CVE-2024-38063).'
FOOTER = ('KEV is context about a CVE. It does not locate the fix in code. Data: CISA Known Exploited Vulnerabilities '
          'catalog (CC0 1.0); not endorsed by CISA or DHS.')
SUMMARY_NOT_STATED = 'Not stated in this catalog entry'
SUMMARY_UNRECOGNIZED = 'Unrecognized value'

# States K0-K9 (inline panel pages and banners).
K0_NO_CATALOG = ('No KEV catalog is loaded. PatchTrace works without it. Update from CISA... downloads about 1.8 MB '
                 'after you confirm the exact request. Import file... reads a KEV JSON file you saved yourself '
                 '(known_exploited_vulnerabilities.json).')
K1_TITLE = 'Download the KEV catalog from CISA?'
K1_SENT = ('Sent: only this address and the headers Accept: application/json and User-Agent: PatchTrace. '
           'No project data and no CVE IDs. Environment proxies are ignored.')
K1_RECEIVED = ('Received: one JSON file, about 1.8 MB (limit 16 MiB). It is saved on this computer and checked before '
               'it replaces the catalog in use.')
K1_CHOICE_SITE = 'CISA website (www.cisa.gov)'
K1_CHOICE_MIRROR = ("CISA GitHub mirror (raw.githubusercontent.com): CISA's own copy, synchronized within minutes.")
K3_CHECKING = 'Downloading from {host}... {received} of about {expected} MB'
K3_VERIFYING = 'Checking the downloaded file...'
K5_AGING = 'This catalog is {n} days old. CVEs CISA added since then are not shown as listed.'
K6_STALE = ('This catalog is {n} days old. A CVE shown as Not listed may have been added since. '
            'Update from CISA... or import a newer file.')
K6_FUTURE = ("The catalog's release time is in the future. Check this computer's clock and treat results as "
             'unverified.')
K7_ERROR = 'Could not update the KEV catalog: {reason}. {kept}'
K7_KEPT = 'The catalog {version} from {date} is still in use.'
K7_NONE = 'No catalog is loaded.'
K7_REASONS = {
    'PT-KEV-NETWORK': 'the connection failed or timed out',
    'PT-KEV-PROVIDER': 'the server answered HTTP {status}',
    'PT-KEV-LIMIT': 'the file is larger than 16 MiB',
    'PT-KEV-FORMAT': 'the file is not a KEV JSON catalog',
    'PT-KEV-VALIDATE': 'the file failed checks ({check})',
    'PT-KEV-SHRINK': 'the new catalog has {n} fewer entries than the one in use',
    'PT-KEV-STORAGE': 'the catalog folder cannot be written',
}
K8_BLOCKED = 'Network updates are switched off here. Import file... still works.'
K9_LOADING = 'Loading the KEV catalog from this computer...'
K9_OLDER = 'The downloaded catalog ({v1}) is older than the one in use ({v2}); the newer one was kept.'
EMPTY_LIST = 'Type or paste CVE IDs above, or open a KB or CVE view that passes its CVEs here.'

FILTERS = (('all', 'All CVEs'), ('listed', 'Listed in KEV'), ('listed-ransomware', 'Listed, ransomware use known'),
           ('not-listed', 'Not listed'), ('no-catalog-or-invalid', 'No catalog or invalid ID'))
SORTS = (('input', 'Input order'), ('kev-first', 'KEV-listed first (reading order, not a score)'))

SOURCE_LABELS = {'cisa-site': 'the CISA website', 'cisa-github': 'the CISA GitHub mirror',
                 'local-import': 'a local file'}

CHANGES_HEADLINE = '{a} new, {c} changed, {r} removed since catalog {previous}.'

ACCESSIBLE_NAMES = {
    'dock': 'Exploitation context (CISA KEV) panel', 'freshness': 'KEV catalog freshness',
    'update': 'Update KEV catalog from CISA', 'import': 'Import KEV catalog file',
    'changes': 'Show KEV changes since the previous catalog', 'copy': 'Copy KEV details',
    'lookup_box': 'CVE IDs to look up', 'lookup_button': 'Look up CVE IDs', 'filter': 'Filter by KEV status',
    'sort': 'CVE order', 'table': 'KEV lookup results', 'detail': 'Selected CVE KEV details',
    'goto': 'Show candidate functions for the selected CVE', 'copy_url': 'Copy CISA catalog page address',
}
