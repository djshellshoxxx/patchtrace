"""The order of leads: integer keys only, ties explicit (PIL-integration-plan.md s7 "Order key", s6 "False precision").

A key is a tuple of small integers compared left to right: there is no weight, no score and no float, so nothing can be
averaged, and an evidence difference that the key does not name cannot reorder two leads. Leads whose keys are equal
form a tie group (`Tie`: "n-m (tie)"); the position inside the group is `candidate_key` order (the plan puts the
read-only attention/1 rank first; no source supplies one yet), never the RVA. Pure.

Order key (ascending), per context:

* with an advisory: class, mechanism, pairing (a contested one last), -expected changes met, -independent components,
  basis of the CWE (stated, named in the text, vocabulary), -locality, no anchored second channel, ChangeFacts
  severity rank (SPEC-31 05 s2.6), nuisance count;
* code evidence only (no advisory, so no hypothesis): class, severity rank, -distinct shape kinds, no anchored second
  channel, nuisance count.
"""
from __future__ import annotations

from collections.abc import Iterable
from itertools import groupby
from types import MappingProxyType
from typing import NamedTuple

from .contracts import CLASS_RANK, Observation
from .quality import parts

Key = tuple[int, ...]

# SPEC-31 05 s2.6, most severe first. The class `constant` does not say whether the constant sits in a compare, test,
# mask, shift or size argument; it takes the position of the compare context, the reading that cannot hide a bound fix.
# A class the list does not name ranks last.
SEVERITY_ORDER: tuple[frozenset[str], ...] = tuple(frozenset(group.split()) for group in (
    'callee call-added call-removed', 'condition comparison', 'constant', 'struct-offset', 'data-ref',
    'block-added block-removed', 'eh', 'cfg', 'string', 'frame', 'size-only', 'refcount-only', 'address-only',
    'register-only', 'name-only'))
NO_SEVERITY = len(SEVERITY_ORDER)
MECHANISM_INDEX = MappingProxyType({'moderate': 0, 'contested': 1, 'tentative': 2, 'unexplained': 3,
                                    'not-assessed': 4})  # `strong` is not assignable, so it has no index
BASIS_INDEX = MappingProxyType({'explicit-csaf-cwe': 0, 'cwe-id-in-text': 1, 'curated-vocabulary': 2})
NO_BASIS = len(BASIS_INDEX)


class Place(NamedTuple):
    """A lead's position: `rank` is unique, `first`..`last` is its tie group, `key` is what put it there."""
    candidate_key: str
    rank: int
    first: int
    last: int
    key: Key


def severity_of(change_class: str) -> int:
    for rank, group in enumerate(SEVERITY_ORDER):
        if change_class in group:
            return rank
    return NO_SEVERITY


def severity(observations: Iterable[Observation]) -> int:
    """The most severe ChangeFacts class among the observations (a proof is not a change); none ranks last."""
    found = (severity_of(name) for prefix, name in (parts(o.kind) for o in observations if o.role != 'conflict')
             if prefix == 'cf')
    return min(found, default=NO_SEVERITY)


def advisory_key(*, lead_class: str, mechanism: str, contested: bool, met: int, components: int, basis: int,
                 local_hits: int, anchored: bool, severity: int, nuisance: int) -> Key:
    return (CLASS_RANK[lead_class], MECHANISM_INDEX[mechanism], int(contested), -met, -components, basis, -local_hits,
            int(not anchored), severity, nuisance)


def code_key(*, lead_class: str, severity: int, shape_kinds: int, anchored: bool, nuisance: int) -> Key:
    return (CLASS_RANK[lead_class], severity, -shape_kinds, int(not anchored), nuisance)


def place(rows: Iterable[tuple[Key, str]]) -> list[Place]:
    """Positions of (key, candidate key) rows: ordered by key, then candidate key; equal keys share a tie group."""
    placed: list[Place] = []
    done = 0
    for key, group in groupby(sorted(rows), key=lambda row: row[0]):
        members = [candidate for _, candidate in group]
        first, last = done + 1, done + len(members)
        placed += [Place(candidate, first + offset, first, last, key) for offset, candidate in enumerate(members)]
        done = last
    return placed
