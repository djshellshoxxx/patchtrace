"""Fixed limits, thresholds and source URLs for ``kev/1`` (KEV-integration-plan section 7). Pure constants.

The sizes follow measured catalog facts (1.7 MiB and 1,741 entries on 2026-10-13): the byte cap is about nine times
today's file and the entry cap about eleven times today's count.
"""
from __future__ import annotations

CONTRACT = 'kev/1'
PARSER_VERSION = 1
PARSER_NAME = f'kev-parse/{PARSER_VERSION}'
JOIN_VERSION = 1
LICENSE = 'CC0-1.0'

MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_JSON_DEPTH = 16
MAX_LOOKUP_CVES = 5_000
MAX_PROJECT_CVES = 256
MAX_TABLE_ROWS = 5_000
MAX_DELTA_IDS = 500
MAX_DELTA_LINES = 200
MAX_UNKNOWN_FIELDS = 16
MAX_WARNINGS = 20
MAX_WARNING_CHARS = 200
MAX_CWES = 16
SHRINK_FLOOR_PERCENT = 90

# Freshness by whole UTC calendar days since the catalog's release (about 12 new entries per 14 days).
FRESH_MAX_DAYS = 3
AGING_MAX_DAYS = 14

CONNECT_TIMEOUT_S = 10
REQUEST_TIMEOUT_S = 60
PLAN_TIMEOUT_S = 120
MAX_ATTEMPTS = 3
RETRY_AFTER_MAX_S = 60
MAX_REDIRECTS = 2
EXPECTED_BYTES_HINT = 1_800_000
PARSE_CEILING_S = 1.0

# cisa-site is the recalled canonical feed (plan fact F11, unverified until gate K6); cisa-github is CISA's own mirror.
SOURCE_URLS = {
    'cisa-site': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'cisa-github': 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
}
CATALOG_PAGE_URL = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
