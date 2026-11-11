"""Tier-W evaluator (SPEC-33 s10): score one-to-one engine matches against symbol-derived labels.

Per (engine, condition) cell, and never pooled across engines or conditions, each match is `correct` (a `same` truth
pair), `wrong` (labelled `different`, or an endpoint has another truth counterpart) or `unscored`. Precision is
correct / (correct + wrong); recall is the share of `same` truth pairs found; unscored matches are neither. Intervals
are item-level Wilson 95%, explicitly not lineage-adjusted (the aggregate adds lineage bootstraps). Symbol-derived
labels never score a run that could see symbols: that cell reports `insufficient-labels` with reason `circular`.
"""
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

CONTRACT = 'tier-w-evaluation/1'
Z95 = 1.959963984540054
BLIND = ('symbols-hidden', 'n/a')
SYMBOL_DERIVED = 'symbol-derived'
TAG_ALL = 'all'
NON_EXPORTED = 'non-exported'


class TruthLabelLike(Protocol):
    pair: str
    older_rva: int | None
    newer_rva: int | None
    answer: str
    source: str
    tags: tuple[str, ...]


class EngineMatchLike(Protocol):
    pair: str
    engine: str
    condition: str
    older_rva: int | None
    newer_rva: int | None


@dataclass(frozen=True)
class TruthLabel:
    pair: str
    older_rva: int | None
    newer_rva: int | None
    answer: Literal['same', 'different']
    source: str = SYMBOL_DERIVED
    tags: tuple[str, ...] = ()


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials; None when n is 0."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _slice(correct: int, wrong: int, unscored: int, truth: int, found: int) -> dict:
    precision, recall = _ratio(correct, correct + wrong), _ratio(found, truth)
    f1 = None if not precision or not recall else 2 * precision * recall / (precision + recall)
    return {'correct': correct, 'wrong': wrong, 'unscored': unscored, 'truth': truth, 'found': found,
            'precision': precision, 'recall': recall, 'f1': f1,
            'precision_wilson': wilson(correct, correct + wrong), 'recall_wilson': wilson(found, truth)}


class _Tally:
    def __init__(self):
        self.correct = self.wrong = self.unscored = 0
        self.truth: set = set()
        self.found: set = set()

    def merge(self, other: _Tally) -> None:
        self.correct += other.correct
        self.wrong += other.wrong
        self.unscored += other.unscored
        self.truth |= other.truth
        self.found |= other.found

    def freeze(self) -> dict:
        return _slice(self.correct, self.wrong, self.unscored, len(self.truth), len(self.found))


def _tags(label: TruthLabelLike) -> tuple[str, ...]:
    return (TAG_ALL, *label.tags, *(() if 'exported' in label.tags else (NON_EXPORTED,)))


class _Index:
    """Truth lookups for one condition: exact pair, and the same-counterpart of each endpoint."""

    def __init__(self, labels: Sequence[TruthLabelLike]):
        self.exact: dict[tuple, TruthLabelLike] = {}
        self.by_old: dict[tuple, TruthLabelLike] = {}
        self.by_new: dict[tuple, TruthLabelLike] = {}
        for label in labels:
            self.exact[(label.pair, label.older_rva, label.newer_rva)] = label
            if label.answer == 'same':
                self.by_old[(label.pair, label.older_rva)] = label
                self.by_new[(label.pair, label.newer_rva)] = label

    def score(self, m: EngineMatchLike) -> tuple[Literal['correct', 'wrong', 'unscored'], TruthLabelLike | None]:
        exact = self.exact.get((m.pair, m.older_rva, m.newer_rva))
        if exact is not None:
            return ('correct' if exact.answer == 'same' else 'wrong'), exact
        other = self.by_old.get((m.pair, m.older_rva)) or self.by_new.get((m.pair, m.newer_rva))
        return ('wrong', other) if other is not None else ('unscored', None)


def _evaluate_cell(labels: Sequence[TruthLabelLike], matches: Sequence[EngineMatchLike],
                   lineage_of: Mapping[str, str]) -> dict:
    index = _Index(labels)
    tally: dict[tuple[str, str], _Tally] = defaultdict(_Tally)  # (tag, lineage)
    for label in labels:
        if label.answer == 'same':
            for tag in _tags(label):
                tally[(tag, lineage_of.get(label.pair, label.pair))].truth.add(
                    (label.pair, label.older_rva, label.newer_rva))
    for m in matches:
        verdict, label = index.score(m)
        for tag in _tags(label) if label else (TAG_ALL,):
            t = tally[(tag, lineage_of.get(m.pair, m.pair))]
            setattr(t, verdict, getattr(t, verdict) + 1)
            if verdict == 'correct':
                t.found.add((m.pair, m.older_rva, m.newer_rva))
    by_tag: dict[str, _Tally] = defaultdict(_Tally)
    tag_lineages: dict[str, dict[str, dict]] = defaultdict(dict)
    for (tag, lineage), t in sorted(tally.items()):
        tag_lineages[tag][lineage] = t.freeze()
        by_tag[tag].merge(t)
    tags = {tag: t.freeze() for tag, t in sorted(by_tag.items())}
    return {'status': 'scored', 'overall': tags.get(TAG_ALL) or _slice(0, 0, 0, 0, 0), 'tags': tags,
            'lineages': tag_lineages.get(TAG_ALL, {}), 'tag_lineages': dict(tag_lineages)}


def evaluate(labels: Sequence[TruthLabelLike], engine_matches: Sequence[EngineMatchLike],
             lineage_of: Mapping[str, str] | None = None) -> dict:
    """`tier-w-evaluation/1`: {engine: {condition: cell}}. A pair absent from `lineage_of` is its own lineage."""
    lineage_of = lineage_of or {}
    runs: dict[tuple[str, str], list[EngineMatchLike]] = defaultdict(list)
    for m in engine_matches:
        runs[(m.engine, m.condition)].append(m)
    cells: dict[str, dict[str, dict]] = {}
    for (engine, condition), matches in sorted(runs.items()):
        usable = [lb for lb in labels if condition in BLIND or lb.source != SYMBOL_DERIVED]
        cells.setdefault(engine, {})[condition] = (
            _evaluate_cell(usable, matches, lineage_of) if usable
            else {'status': 'insufficient-labels', 'reason': 'circular'})
    return {'contract': CONTRACT, 'tier': 'W', 'cells': cells,
            'method': {'intervals': 'wilson-95-item-level', 'lineage_adjusted': False, 'pooled': False}}
