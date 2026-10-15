"""Numbers and versions of the kev/1 package (KEV-integration-plan sections 7 and 8), the single code source.

Stdlib only. Plain integers: seconds in ``_S``, milliseconds in ``_MS``, bytes in ``_BYTES`` or a ``MIB`` product.
Parse, join, view model and store read these today; the network numbers wait for the transport slice (K2) and the
panel row cap for the GUI slice (K3), so the code never repeats a literal.
"""
from __future__ import annotations

KIB = 1024
MIB = 1024 ** 2

PARSER_VERSION = 1                 # part of every snapshot id: a parser change makes new snapshots, never silent edits
JOIN_VERSION = 1                   # part of every project row id

# --- the catalog (9.4x headroom over today's 1.7 MiB, about 59 years of growth at 250 entries a year)
MAX_CATALOG_BYTES = 16 * MIB       # download and import
MAX_ENTRIES = 20_000
EXPECTED_DOWNLOAD_BYTES = 1_800_000  # shown to a person before consent ("about 1.8 MB"); never enforced or hashed

# --- text caps, in characters (the real maxima today: product 179, name 161, description 821, action 520, notes 1,092)
MAX_VENDOR_CHARS = 128
MAX_PRODUCT_CHARS = 256
MAX_NAME_CHARS = 256
MAX_DESCRIPTION_CHARS = 4096
MAX_ACTION_CHARS = 2048
MAX_NOTES_CHARS = 4096
MAX_VERSION_CHARS = 32
MAX_CWES = 16                      # per entry; the real maximum is 4
MAX_UNKNOWN_FIELDS = 16            # names of fields this parser does not know, reported never silently dropped
MAX_UNKNOWN_NAME_CHARS = 64
MAX_WARNINGS = 20
MAX_WARNING_CHARS = 200
MAX_ECHO_CHARS = 64                # an invalid CVE ID typed by a person is echoed at most this long, cleaned

# --- lookups, project rows, snapshot delta, panel
MAX_LOOKUP_CVES = 5_000
MAX_CONTEXT_CVES = 256
MAX_CONTEXT_ROW_BYTES = 256 * KIB
MAX_DELTA_IDS = 500
MAX_PANEL_ROWS = 5_000             # K3
MAX_CHANGE_LINES = 200             # lines of "Show changes"
MAX_NOTE_LINES = 20                # note segments shown in one CVE detail

# --- freshness, in whole UTC calendar days since the catalog's release (about 12 new entries per 14 days)
FRESH_MAX_DAYS = 3
AGING_MAX_DAYS = 14                # 15 days and more is stale

# --- replacing the catalog in use: a new catalog with fewer than this percent of the entries needs an explicit accept
SHRINK_KEEP_PERCENT = 90

# --- network (K2): one GET per consent, same-host redirects only
CONNECT_TIMEOUT_S = 10
REQUEST_TIMEOUT_S = 60
PLAN_TIMEOUT_S = 120
ATTEMPTS = 3                       # on 429, 502, 503 and 504
RETRY_AFTER_MAX_S = 60
MAX_REDIRECTS = 2

# --- store: Windows antivirus and indexers can hold a freshly written file for a moment
REPLACE_ATTEMPTS = 3
REPLACE_BACKOFF_MS = 100
STORE_WARN_BYTES = 256 * MIB       # a warning in the status, never a deletion
