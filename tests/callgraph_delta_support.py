"""Shared builders for the call-delta, lead and synergy tests (WB2 G3). All inputs are synthetic."""
from __future__ import annotations

import copy
import json
import re
from collections import Counter

from callgraph_graph_support import project_and_raw, reader_for

from patchtrace.callgraph.apis import HintRule, RuleHints
from patchtrace.callgraph.contracts_delta import CallDelta
from patchtrace.callgraph.delta import DeltaContext, compute_deltas, diff_types_by_match
from patchtrace.callgraph.project_input import read_project_input
from patchtrace.callgraph.snapshot import CallSnapshot, build_snapshot

HINTS = RuleHints([HintRule('R-MEMORY-READ', '1', 'memory-read', ('ProbeForRead',)),
                   HintRule('R-POINTER', '1', 'pointer', ('ProbeForRead',))])


class Entries:
    def __init__(self, *labels: str) -> None:
        self._labels = labels

    def entries(self, side):
        return self._labels


def analysis(name: str, mutate=None, with_raw: bool = True) -> tuple[CallSnapshot, tuple[CallDelta, ...]]:
    project, raw = project_and_raw(name, mutate)
    snap = build_snapshot(read_project_input(project, None, reader_for(raw) if with_raw else None))
    ctx = DeltaContext(HINTS, diff_types=diff_types_by_match(project))
    return snap, compute_deltas(snap, ctx)


def by_label(deltas, label: str) -> CallDelta:
    return next(d for d in deltas if d.older_label == label)


def classes(delta: CallDelta, skip_same: bool = True) -> list[tuple[str, str]]:
    return sorted((c.cls, c.newer_label or c.older_label or '') for c in delta.changes
                  if not (skip_same and c.cls == 'same-link'))


def modified(raw: dict, label: str) -> dict:
    return next(m for m in raw['functions']['modified'] if m['old']['name'] == label)


def swap_raw(raw: dict) -> dict:
    """The same comparison seen from the other side: older and newer exchanged everywhere."""
    swapped = copy.deepcopy(raw)
    functions = swapped['functions']
    functions['added'], functions['deleted'] = functions['deleted'], functions['added']
    for item in functions['modified']:
        item['old'], item['new'] = item['new'], item['old']
    swapped['old_meta'], swapped['new_meta'] = swapped['new_meta'], swapped['old_meta']
    for table, items in swapped.get('matches', {}).items():
        inverted: dict = {}
        for key, targets in items.items():
            for target, kinds in targets:
                inverted.setdefault(target, []).append([key, kinds])
        swapped['matches'][table] = inverted
    return swapped


def rename_defaults(raw: dict) -> dict:
    """Every Ghidra default name renumbered consistently in both builds."""
    return json.loads(re.sub(r'FUN_([0-9a-f]+)', r'FUN_7\1', json.dumps(raw)))


def transform(function):
    """A `mutate` argument that replaces the raw dict's content with `function(raw)`."""
    def apply(raw: dict) -> None:
        replacement = function(raw)
        raw.clear()
        raw.update(replacement)
    return apply


def class_counts(deltas) -> Counter:
    return Counter(c.cls for d in deltas for c in d.changes)
