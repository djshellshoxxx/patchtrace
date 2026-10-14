"""Review order of string changes (spec WB3 s7): ordinal tiers R1..R7 with fixed-vocabulary reasons. Pure.

A tier is a reading order, not a score and not a confidence: it is never combined with function attention or any
other signal, and it carries no vulnerability claim. Precedence, strongest statement first: representation and
look-alike changes (R6), emulation-derived strings (R5), noise and resource text (R7), then the content rules
R1-R4, and R5 for every other difference.
"""
from __future__ import annotations

from collections.abc import Collection, Sequence

from .contracts import Cue, StringChange, StringLink

REASONS = ('pair-modified', 'pair-added', 'pair-removed', 'relocated', 'representation', 'lookalike', 'format-spec',
           'emulation', 'noise', 'resource', 'api', 'not-established', 'other-difference')
_WORDING = frozenset({'message', 'format', 'advisory-text'})
_API_LIKE = frozenset({'api-name', 'dynamic-api', 'path', 'registry', 'url', 'guid', 'dll-name', 'advisory-api'})
_OLDER_TEXT = frozenset({'message', 'format', 'path', 'registry'})


def review_tier(status: str, cues: Collection[Cue], links: Sequence[StringLink], *, emulation: bool = False,
                lookalike: bool = False, format_spec: bool = False) -> tuple[int, tuple[str, ...]]:
    """`(tier, reasons)` for a change that is not an unchanged string. Reasons are ids from `REASONS`."""
    if status == 'both':
        return 7, ('relocated',)  # a moved string carries no reading priority; it is listed for its links
    pairs = {link.pair_status for link in links}
    reasons = [f'pair-{p}' for p in ('modified', 'added', 'removed') if p in pairs]
    if format_spec:
        reasons.append('format-spec')
    if status == 'representation-changed' or lookalike:
        return 6, tuple(['lookalike' if lookalike else 'representation', *reasons])
    if emulation:
        return 5, ('emulation', *reasons)
    if 'noise-like' in cues:
        return 7, ('noise', *reasons)
    if 'resource' in cues:
        return 7, ('resource', *reasons)
    if status == 'indeterminate':
        return 5, ('not-established',)
    cue_set = set(cues)
    newer_side = status in ('only-newer', 'edited')
    if newer_side and cue_set & _WORDING and 'modified' in pairs:
        return 1, tuple(reasons)
    if status == 'only-newer' and pairs & {'modified', 'added'}:
        return 2, tuple(reasons)
    if newer_side and cue_set & _API_LIKE:
        return 3, ('api', *reasons)
    if status == 'only-older' and cue_set & _OLDER_TEXT and pairs & {'modified', 'removed'}:
        return 4, tuple(reasons)
    return 5, ('other-difference', *reasons)


def sort_key(change: StringChange) -> tuple:
    """Tier, then known function RVA first, then casefolded text, then id."""
    rvas = [link.function.rva for link in change.links if link.function.rva is not None]
    return (change.review_tier, not rvas, min(rvas, default=0), change.display.casefold(), change.id)
