"""Channel packs (LBL-13; LBL plan s7.6): one scorer per channel, reported separately.

Packs never pool or average with each other: `PACKS` lists them all, a pack without input is `not-run` and `rules`
is `blocked` while YARA-X is unavailable. Listed, never skipped.
"""
from __future__ import annotations

PACKS = ('strings', 'capabilities', 'environment', 'rules', 'leadlist')
