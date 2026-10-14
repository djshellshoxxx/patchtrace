"""Three-valued evaluation of one rule's expected changes against one candidate's evidence (plan s7, tier step 2).

Pure and total: no fusion, no tiers, no ranking, no display text (PIL-B2 owns those). The caller reads each observation
of the candidate into an `Evidence` and passes the channel states of the run and the API hints of the hypothesis's own
K rule (the table never copies them). The result depends on the set of evidence only, so order and duplicates never
matter.

- `met`: some leaf of the change matches `shape` evidence (every matching observation id is kept).
- `contradicted`: not met, and `conflict` evidence matches one of the rule's conflict leaves (a cosmetic or unchanged
  proof); a met change stays `met`, and PIL-B2 reads `conflict_ids` to force `contested`.
- `not-observed`: not met, no conflict, and every channel the change reads is `available` (a complete channel).
- `unknown`: otherwise. Missing evidence is never a negative vote.
Strings and build flags are context only: no leaf can read them, so they never change a state.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import NamedTuple

from ..contracts import ExpectedChange
from .contracts import LEVELS, Leaf, PilotRule


@dataclass(frozen=True)
class Evidence:
    """One observation of the candidate as the rules read it.

    `kind` and `role` are the observation's. `level` is the B1 signal confidence (weak, moderate, strong) of `b1:*`
    kinds, `subject` the API name of a `call:*` kind or the capability namespace of a `capa:*` kind. The A1
    `Observation` has no field for either, so the caller supplies them."""
    obs_id: str
    kind: str
    role: str
    level: str | None = None
    subject: str | None = None


class Evaluation(NamedTuple):
    changes: tuple[ExpectedChange, ...]  # one per change of the rule, in the rule's order
    conflict_ids: tuple[str, ...]  # sorted ids of the evidence that matches a conflict leaf of the rule


def api_key(name: str) -> str:
    """Join key of an API name (the rule of CAP's `apiobs/1`): lower case, no module prefix, a trailing A or W
    (ANSI or wide variant) folded when four or more characters remain. For matching only, never shown."""
    key = name.rsplit('!', 1)[-1].lower()
    return key[:-1] if len(key) >= 5 and key[-1] in 'aw' else key


@lru_cache(maxsize=256)
def _hint_keys(hints: tuple[str, ...]) -> frozenset[str]:
    return frozenset(api_key(hint) for hint in hints)


def _within(subject: str, namespace: str) -> bool:
    return subject == namespace or subject.startswith(namespace + '/')


def _matching(leaf: Leaf, by_kind: Mapping[str, list[Evidence]], by_prefix: Mapping[str, list[Evidence]],
              hints: frozenset[str]) -> Iterable[Evidence]:
    if leaf.prefix == 'b1':
        floor = LEVELS.index(leaf.floor)
        return [e for e in by_kind.get(leaf.kind, ()) if e.level in LEVELS and LEVELS.index(e.level) >= floor]
    if leaf.prefix == 'call':
        return [e for e in by_kind.get(leaf.kind, ()) if e.subject and api_key(e.subject) in hints]
    if leaf.prefix == 'capa':
        return [e for e in by_prefix.get('capa', ()) if e.subject and _within(e.subject, leaf.name)]
    return by_kind.get(leaf.kind, ())


def evaluate_rule(rule: PilotRule, evidence: Iterable[Evidence], channels: Mapping[str, str],
                  api_hints: Sequence[str] = ()) -> Evaluation:
    """States of the rule's expected changes for one candidate. `channels` maps a channel name (code, calls, capa) to
    its state for this run; a channel that is absent is unknown."""
    if isinstance(api_hints, str):
        raise TypeError('api_hints is a collection of API names, not a string')
    unique = set(evidence)
    by_kind: dict[str, list[Evidence]] = {}
    by_prefix: dict[str, list[Evidence]] = {}
    for item in unique:
        if item.role == 'shape':
            by_kind.setdefault(item.kind, []).append(item)
            by_prefix.setdefault(item.kind.partition(':')[0], []).append(item)
    conflict_kinds = {leaf.kind for leaf in rule.conflicts}
    conflict_ids = tuple(sorted({e.obs_id for e in unique if e.role == 'conflict' and e.kind in conflict_kinds}))
    hints = _hint_keys(tuple(api_hints))
    changes = []
    for spec in rule.changes:
        met = sorted({e.obs_id for leaf in spec.leaves for e in _matching(leaf, by_kind, by_prefix, hints)})
        if met:
            state, ids = 'met', tuple(met)
        elif conflict_ids:
            state, ids = 'contradicted', conflict_ids
        elif all(channels.get(name) == 'available' for name in spec.channels):
            state, ids = 'not-observed', ()
        else:
            state, ids = 'unknown', ()
        changes.append(ExpectedChange(id=spec.id, state=state, required=spec.required, observation_ids=ids,
                                      teach_id=spec.teach_id))
    return Evaluation(tuple(changes), conflict_ids)
