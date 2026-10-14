"""Teach hooks for the guided teacher (E-5, deferred by the owner): what a KEV answer means and what to do next.

Data only. Each hook names the tooltip that explains the control it concerns; the wording is the plan's (section 4) and
is swept for claims by the tests together with every other KEV string. Hooks claim nothing about code.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TeachHook:
    id: str
    meaning: str
    next_step: str
    tooltip_id: str


TEACH_HOOKS = (
    TeachHook('kev.listed', 'CISA lists this CVE as a known exploited vulnerability.',
              'Open its expected patch changes and candidate functions; KEV does not say where the fix is.',
              'kev.table'),
    TeachHook('kev.not-listed', 'Not in this catalog snapshot; that is not evidence of safety.',
              'Judge by the advisory and the code evidence, and check the catalog age.', 'kev.table'),
    TeachHook('kev.no-catalog', 'No catalog is loaded.',
              'Update from CISA or import a file if you want exploitation context.', 'kev.update'),
    TeachHook('kev.stale', 'The catalog is old.', 'Refresh before relying on Not listed.', 'kev.update'),
    TeachHook('kev.no-detector', 'PatchTrace has no detector for this weakness class.',
              'An empty candidate list is unknown; read the changed functions yourself.', 'kev.detail'),
)
