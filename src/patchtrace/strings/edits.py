"""Edited-string pairing (spec WB3 s5, WB3-S5): an only-older and an only-newer value that are one string edited.

Two routes, both conservative. Look-alikes pair globally when their folded keys agree one-to-one. Other edits pair
only inside one matched function, when the two values are each other's clear best match (a tie pairs nothing),
bounded to `MAX_EDIT_PAIRS` x `MAX_EDIT_PAIRS` candidates per function. A pair is a hint about reading order, not
a claim that the author edited that string. Pure.
"""
from __future__ import annotations

import difflib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from .limits import MAX_EDIT_PAIRS
from .lookalike import pair_lookalikes

MIN_RATIO = 0.6
_SPEC = re.compile(r'%[-+ #0-9.*hlLjztI]*[A-Za-z]')


@dataclass(frozen=True)
class Candidate:
    """One unmatched value. `text` is the escaped display; `functions` the matched-function keys it is linked to."""
    key: bytes
    text: str
    functions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class EditPair:
    older: bytes
    newer: bytes
    kind: str
    lookalike: bool = False
    format_spec: bool = False


@dataclass(frozen=True)
class EditResult:
    pairs: tuple[EditPair, ...]
    notes: tuple[str, ...] = field(default=())


def edit_kind(older: str, newer: str) -> str:
    """One insertion or deletion is `prefix` (at the start), `suffix` (at the end) or `insert`/`delete`; any other
    shape is `replace`."""
    ops = [op for op in difflib.SequenceMatcher(None, older, newer, autojunk=False).get_opcodes()
           if op[0] != 'equal']
    if len(ops) != 1 or ops[0][0] == 'replace':
        return 'replace'
    tag, i1, i2, j1, j2 = ops[0]
    if i1 == 0 and j1 == 0:
        return 'prefix'
    if i2 == len(older) and j2 == len(newer):
        return 'suffix'
    return tag


def _specs_changed(older: str, newer: str) -> bool:
    before, after = _SPEC.findall(older), _SPEC.findall(newer)
    return bool(before or after) and before != after


def _pair(older: Candidate, newer: Candidate, *, lookalike: bool = False) -> EditPair:
    return EditPair(older.key, newer.key, edit_kind(older.text, newer.text), lookalike,
                    _specs_changed(older.text, newer.text))


def pair_edits(older: Sequence[Candidate], newer: Sequence[Candidate]) -> EditResult:
    pairs: list[EditPair] = []
    used_old: set[bytes] = set()
    used_new: set[bytes] = set()
    by_old = _unique_by_text(older)
    by_new = _unique_by_text(newer)
    for found in pair_lookalikes(by_old, by_new):
        a, b = by_old[found.older], by_new[found.newer]
        pairs.append(_pair(a, b, lookalike=True))
        used_old.add(a.key)
        used_new.add(b.key)
    notes: list[str] = []
    functions = sorted({f for c in (*older, *newer) for f in c.functions})
    for function in functions:
        olds = [c for c in older if function in c.functions and c.key not in used_old]
        news = [c for c in newer if function in c.functions and c.key not in used_new]
        if len(olds) > MAX_EDIT_PAIRS or len(news) > MAX_EDIT_PAIRS:
            notes.append(f'edit pairing skipped for a function with more than {MAX_EDIT_PAIRS} unmatched strings')
            continue
        for a, b in _mutual_best(olds, news):
            if a.key in used_old or b.key in used_new:
                continue
            pairs.append(_pair(a, b))
            used_old.add(a.key)
            used_new.add(b.key)
    return EditResult(tuple(sorted(pairs, key=lambda p: (p.older, p.newer))), tuple(notes))


def _unique_by_text(items: Sequence[Candidate]) -> dict[str, Candidate]:
    """Texts that map to exactly one candidate; a repeated display text cannot be paired without guessing."""
    seen: dict[str, Candidate | None] = {}
    for item in items:
        seen[item.text] = None if item.text in seen else item
    return {text: item for text, item in seen.items() if item is not None}


def _scores(olds: Sequence[Candidate], news: Sequence[Candidate]) -> list[list[float]]:
    table = []
    for a in olds:
        row = []
        for b in news:
            matcher = difflib.SequenceMatcher(None, a.text.casefold(), b.text.casefold(), autojunk=False)
            row.append(matcher.ratio())
        table.append(row)
    return table


def _best(scores: Sequence[float]) -> int | None:
    """Index of the clear winner at or above `MIN_RATIO`; a tie for first has no winner."""
    if not scores:
        return None
    top = max(scores)
    if top < MIN_RATIO or scores.count(top) > 1:
        return None
    return list(scores).index(top)


def _mutual_best(olds: Sequence[Candidate], news: Sequence[Candidate]) -> list[tuple[Candidate, Candidate]]:
    table = _scores(olds, news)
    out = []
    for i, row in enumerate(table):
        j = _best(row)
        if j is not None and _best([table[k][j] for k in range(len(olds))]) == i:
            out.append((olds[i], news[j]))
    return out


__all__ = ['Candidate', 'EditPair', 'EditResult', 'edit_kind', 'pair_edits']
