"""S3b row selection (SPEC-31 05 s2.8). Pure.

After the facts, a row in `review` whose first semantic delta is a constant, a comparison, a condition or a struct
offset, and that has no canonical pseudo-code (C6 `unavailable`), is worth a decompile: the decompiler may show the
same change (MAT-ANCHOR then promotes it to `material`) or not (it stays `review`). At most L-41 pairs are chosen per
run, in the review order of 2.6; the rows whose constants only feed a tracing call (hint `trace-arg`) come last.
Nothing here decides a verdict: the chosen pairs are decompiled by the extractor and judged again by `verdict.judge`.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..contracts import SEMANTIC_CLASSES, Delta
from ..limits import DEFAULT_LIMITS
from . import severity
from .verdict import Judged

WORTH_A_DECOMPILE = ('constant', 'comparison', 'condition', 'struct-offset')


def first_semantic_delta(judged: Judged) -> Delta | None:
    """The leading semantic delta of the row (the deltas are in severity order, 2.6)."""
    return next((d for d in judged.facts.deltas if d.cls in SEMANTIC_CLASSES), None)


def wants_decompile(judged: Judged) -> bool:
    facts = judged.facts
    if facts.verdict != 'review' or dict(facts.channels).get('C6') != 'unavailable':
        return False
    first = first_semantic_delta(judged)
    return first is not None and first.cls in WORTH_A_DECOMPILE


def select_for_decompile(rows: Iterable[tuple[tuple[int, int], Judged]],
                         limit: int = DEFAULT_LIMITS.l41_decompile_pairs) -> list[tuple[int, int]]:
    """The (older rva, newer rva) pairs to decompile: eligible rows by severity of their first semantic delta (a
    constant in a compare, test, mask or shift context ranks right after a comparison), `trace-arg` rows last, ties by
    RVA; the first `limit` of them. The result does not depend on the order of `rows`."""
    ranked = []
    for pair, judged in rows:
        if wants_decompile(judged):
            ranked.append(('trace-arg' in judged.hints, severity(first_semantic_delta(judged)), pair))
    ranked.sort()
    return [pair for _trace, _rank, pair in ranked[:limit]]
