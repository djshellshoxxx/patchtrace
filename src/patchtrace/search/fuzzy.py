"""Name suggestions and rename hints (WB1 section 7 'Limits', fuzzy rule). Names only, never code.

RapidFuzz is an optional extra: without it nothing here returns an empty answer that looks like "no
suggestions"; callers ask `available()` first and report the feature as unavailable. Distances are
integer `OSA` edits on folded names; a suggestion or hint is never a match.
"""
from __future__ import annotations

from collections.abc import Sequence

from patchtrace import optional_deps
from patchtrace.search.contracts import CounterpartHint, FunctionRef
from patchtrace.search.limits import DEFAULT_LIMITS, SearchLimits
from patchtrace.search.normalize import fold, is_auto_name
from patchtrace.search.tokenize import name_words

UNAVAILABLE = 'Typo suggestions are unavailable: install the search extra (RapidFuzz) to enable them.'


def available() -> bool:
    return optional_deps.available('rapidfuzz')


def max_edits(length: int) -> int:
    """Allowed edit distance for a name of `length` folded characters: 0 for <=2, 1 for <=4, 2 for <=9, else 3."""
    return 0 if length <= 2 else 1 if length <= 4 else 2 if length <= 9 else 3


def _nearest(query: str, choices: Sequence[str], cutoff: int) -> tuple[int, int] | None:
    """(index, edits) of the unique closest choice within `cutoff`, or None when none or a tie."""
    from rapidfuzz import process
    from rapidfuzz.distance import OSA
    found = process.extract(query, choices, scorer=OSA.distance, score_cutoff=cutoff, limit=2)
    if not found or (len(found) == 2 and found[0][1] == found[1][1]):
        return None
    return found[0][2], int(found[0][1])


def suggest(query: str, names: Sequence[str], *, limits: SearchLimits = DEFAULT_LIMITS) -> list[tuple[int, int]]:
    """(index into `names`, edits) of names within the allowed distance of `query`, closest first then by name;
    exact (0-edit) names and auto names are left out. `names` are unique display names."""
    from rapidfuzz import process
    from rapidfuzz.distance import OSA
    target = fold(query)
    allowed = max_edits(len(target))
    if not allowed:
        return []
    usable = [(i, fold(n)) for i, n in enumerate(names[:limits.fuzzy_candidates]) if not is_auto_name(n)]
    found = process.extract(target, [folded for _, folded in usable], scorer=OSA.distance,
                            score_cutoff=allowed, limit=None)
    rows = [(usable[index][0], int(edits)) for _, edits, index in found if edits > 0]
    return sorted(rows, key=lambda row: (row[1], fold(names[row[0]]), names[row[0]]))[:limits.suggestions]


def counterpart_hints(older: Sequence[FunctionRef], newer: Sequence[FunctionRef], *,
                      limits: SearchLimits = DEFAULT_LIMITS) -> tuple[CounterpartHint, ...]:
    """Removed-vs-added name pairs that are each other's unique nearest name (possible renames)."""
    olds = [(r, fold(r.name)) for r in older if not is_auto_name(r.name)][:limits.fuzzy_candidates]
    news = [(r, fold(r.name)) for r in newer if not is_auto_name(r.name)][:limits.fuzzy_candidates]
    old_names, new_names = [f for _, f in olds], [f for _, f in news]
    hints = []
    for i, (old, folded) in enumerate(olds):
        forward = _nearest(folded, new_names, max_edits(len(folded)))
        if forward is None:
            continue
        j, edits = forward
        back = _nearest(new_names[j], old_names, max_edits(len(new_names[j])))
        if back is None or back[0] != i or edits > max_edits(min(len(folded), len(new_names[j]))):
            continue
        new = news[j][0]
        shared = sorted(set(name_words(old.name).split()) & set(name_words(new.name).split()))[:8]
        hints.append(CounterpartHint(older=old, newer=new, edits=edits, shared_words=tuple(shared)))
    hints.sort(key=lambda h: (h.edits, fold(h.older.name), h.older.function_id))
    return tuple(hints[:limits.counterpart_hints])
