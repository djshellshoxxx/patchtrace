"""Versioned product alias catalog (KB-integration-plan 7.2 `ProductScope`, slice K1). PURE DATA: no logic.

`products.py` compiles these patterns and derives `family`, `release`, `architecture`, `channel`, `edition` and a
Winbindex key from a product's display name. A scope derived from a string is a *candidate*, never `verified`: the
catalog says what a name probably means, not what a vendor document proves. Bump `ALIAS_CATALOG_VERSION` for any
change in meaning; `products.catalog_digest()` also changes when a pattern is edited, and the version belongs to the
parse key (`{doc_sha256, dialect, parser_version, alias_catalog_version}`).

Patterns are matched against the lower-cased, whitespace-collapsed name with `re.search`; only
`IMPLIED_CLIENT_NAME_PATTERN` must match the whole name.

Version 2 (audit KBA-08, spec 31-C C1): `Version 2004` is a release token, and the exact client names that carry no
release token get the first release of their generation. Only names with the token `version 2004` or of that exact
form derive other attributes than under version 1; the scope id of every other name is unchanged.
"""
from __future__ import annotations

ALIAS_CATALOG_VERSION = 2

# (family, pattern); the first match wins, so "windows server" must precede the client rule.
FAMILY_PATTERNS = (
    ('windows-server', r'\bwindows server\b'),
    ('windows-client', r'\bwindows (?:10|11)\b'),
    ('other', r'\b(?:microsoft|office|edge|azure|visual studio|\.net|sql server|exchange|sharepoint|mariner|'
              r'teams|dynamics|power bi)\b'),
)

# Client generation ("Windows 11" -> "11"); used only for the Winbindex key.
CLIENT_VERSION_PATTERN = r'\bwindows (10|11)\b'

# Release tokens, tried in order; the first capture group (upper-cased) is the release.
RELEASE_PATTERNS = (
    r'\b((?:19|2[0-9])h[12])\b',
    r'\bversion (1[5-9][0-9]{2}|2004)\b',
)
# A client name without a release token names the first release of its generation, but only in this exact vendor
# form (the whole name; the group is the generation). LTSC/LTSB, IoT and any other wording stay without a release.
IMPLIED_CLIENT_NAME_PATTERN = r'windows (10|11) for (?:x64-based|32-bit|arm64-based) systems'
IMPLIED_CLIENT_RELEASES = (('10', '1507'), ('11', '21H2'))
SERVER_YEAR_PATTERN = r'\bwindows server (20[0-9]{2}(?: r2)?)\b'

# (value, pattern); every distinct matching value is collected. Exactly one value is kept, otherwise `unknown`.
ARCH_PATTERNS = (
    ('arm64', r'\barm64\b|\barm-based\b'),
    ('amd64', r'\bx64\b|\bx86[_-]64\b|\bamd64\b|\b64-bit\b'),
    ('x86', r'\bx86\b|\b32-bit\b'),
)
EDITION_PATTERNS = (
    ('core', r'\b(?:server )?core(?: installation)?\b'),
    ('iot', r'\biot\b'),
)
CHANNEL_PATTERNS = (
    ('ltsc', r'\bltsc\b|\bltsb\b'),
    ('preview', r'\bpreview\b'),
    ('insider', r'\binsider\b'),
)

# Winbindex covers Windows 10/11 client x64 only (RK2 s1), so only this family gets a key, `<10|11>-<release>`.
WINBINDEX_FAMILIES = ('windows-client',)
FAMILY_VALUES = ('windows-client', 'windows-server', 'other', 'unknown')
ARCH_VALUES = ('amd64', 'arm64', 'x86', 'unknown')
