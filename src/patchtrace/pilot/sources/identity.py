"""The pairing verdict map: which pairing source speaks for a candidate (PIL-integration-plan.md s7 "Identity map").

Identity says whether the older and the newer function are the same function. Two sources judge it: the unified
engine (SPEC-31, a `Decision` per row) and, when no current unified result exists, the secondary-engine adjudication
(SPEC-26, a `Verdict` per match). Both start from the same Ghidriff match, so their opinions are one origin and only the
source that speaks is read, never both: a secondary verdict can neither upgrade nor downgrade a unified decision.
Nothing (no row, no verdict) is `unassessed`, never a negative vote, and an unknown word fails closed.

The engines' vocabularies are mirrored as strings, so this module imports no other feature; a test pins the tables to
the engines' own literals.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from ..contracts import Identity
from ..limits import PilotError

UNIFIED_IDENTITY: Mapping[str, Identity] = MappingProxyType({
    'matched': 'corroborated',
    'tentative': 'unassessed', 'candidate': 'unassessed', 'older-only': 'unassessed', 'newer-only': 'unassessed',
    'unknown': 'unassessed',
    'contested': 'contested', 'ambiguous': 'contested'})
SECONDARY_IDENTITY: Mapping[str, Identity] = MappingProxyType({
    'corroborated': 'corroborated',
    'single-engine': 'unassessed', 'insufficient': 'unassessed',
    'contested': 'contested'})


def _identity(table: Mapping[str, Identity], state: str | None, source: str) -> Identity:
    if state is None:
        return 'unassessed'
    if not isinstance(state, str) or state not in table:
        raise PilotError('PT-PILOT-INPUT', f'Unknown {source} pairing state', reason='unknown-pairing-state')
    return table[state]


def identity_from_unified(decision: str | None) -> Identity:
    """Identity of a unified row's `Decision`; None means the current unified result holds no row for the candidate."""
    return _identity(UNIFIED_IDENTITY, decision, 'unified')


def identity_from_secondary(verdict: str | None) -> Identity:
    """Identity of a secondary-engine `Verdict`; None means no engine judged the match."""
    return _identity(SECONDARY_IDENTITY, verdict, 'secondary')


def pairing_identity(*, unified: str | None, secondary: str | None, unified_current: bool) -> Identity:
    """The identity of one candidate. With a current unified result only it speaks (even for a candidate it does
    not hold); otherwise, including when the unified result is stale, only the secondary verdict does."""
    if unified_current:
        return identity_from_unified(unified)
    return identity_from_secondary(secondary)
