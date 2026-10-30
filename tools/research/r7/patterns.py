"""R7 synthetic-only structural guard delta motif. NOT a binary security or CWE detector.

Checks for an explicitly *declared* control edge from a predicate branch to a
load/store and a common operand. It cannot verify actual dominators, guard
polarity, old/new matching, path feasibility, aliasing, or input trust.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import islice
from typing import Iterable, Literal

from .slicer import MAX_INPUT_OPS, Op, Scope

RULE = 'R7-STRUCTURAL-GUARD-DELTA/0'
COMPARISONS = frozenset({'INT_LESS', 'INT_LESSEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL',
                         'INT_EQUAL', 'INT_NOTEQUAL'})
SINKS = frozenset({'LOAD', 'STORE'})


@dataclass(frozen=True, slots=True)
class GuardAssessment:
    rule_id: str
    status: Literal['candidate', 'not-observed', 'inconclusive']
    older_scope: Scope
    newer_scope: Scope
    sink_types: tuple[str, str]
    evidence_uids: tuple[str, ...]
    unknowns: tuple[str, ...]


def _collect(items: Iterable[Op]) -> dict[str, Op]:
    rows = list(islice(items, MAX_INPUT_OPS + 1))
    if len(rows) > MAX_INPUT_OPS:
        raise ValueError('too many operations')
    out: dict[str, Op] = {}
    for row in rows:
        if not isinstance(row, Op) or row.uid in out:
            raise ValueError('invalid or duplicate operation')
        out[row.uid] = row
    return out


def _inspect(by_id: dict[str, Op], sink: Op) -> tuple[str, tuple[str, ...], set[str]]:
    """Returns observed / absent / unknown within caller-supplied graph only."""
    if not sink.controls:
        return ('absent', (), set())
    defs: dict[str, list[Op]] = defaultdict(list)
    for item in by_id.values():
        if item.output is not None:
            defs[item.output].append(item)
    incomplete: set[str] = set()
    observed: tuple[str, ...] = ()
    for control_id in sink.controls:
        branch = by_id.get(control_id)
        if branch is None:
            incomplete.add(f'missing-control:{control_id}')
            continue
        if branch.opcode != 'CBRANCH' or not branch.inputs:
            incomplete.add('opaque-control:' + control_id)
            continue
        pred = branch.inputs[0]
        candidates = defs.get(pred, [])
        if len(candidates) != 1:
            incomplete.add(('multiple' if candidates else 'missing') + f'-defs:{pred}')
            continue
        cmp_op = candidates[0]
        if cmp_op.opcode not in COMPARISONS:
            incomplete.add('unknown-condition:' + cmp_op.uid)
            continue
        common = set(cmp_op.inputs).intersection(sink.inputs)
        if not any(not v.startswith('const:') for v in common):
            continue
        observed = (cmp_op.uid, branch.uid, sink.uid)
    if incomplete:
        return ('unknown', (), incomplete)
    if observed:
        return ('observed', observed, set())
    return ('absent', (), set())


def assess_guard_to_sink(
    older_ops: Iterable[Op], newer_ops: Iterable[Op], *,
    old_scope: Scope, new_scope: Scope,
    old_sink_uid: str, new_sink_uid: str,
) -> GuardAssessment:
    if not isinstance(old_scope, Scope) or not isinstance(new_scope, Scope):
        raise ValueError('invalid scopes')
    if old_scope.artifact_sha256 == new_scope.artifact_sha256:
        raise ValueError('not an older/newer artifact pair')
    old_map = _collect(older_ops)
    new_map = _collect(newer_ops)
    if old_sink_uid not in old_map or new_sink_uid not in new_map:
        raise ValueError('sink is absent')
    old_sink = old_map[old_sink_uid]
    new_sink = new_map[new_sink_uid]
    kinds = (old_sink.opcode, new_sink.opcode)
    if old_sink.opcode not in SINKS or kinds[0] != kinds[1]:
        return GuardAssessment(RULE, 'inconclusive', old_scope, new_scope, kinds, (),
                               ('sink-match-unsupported',))
    new_state, new_support, new_unknowns = _inspect(new_map, new_sink)
    old_state, _, old_unknowns = _inspect(old_map, old_sink)
    if old_state == 'unknown':
        return GuardAssessment(RULE, 'inconclusive', old_scope, new_scope, kinds, (),
                               tuple(sorted({'older-unresolved-control', *old_unknowns})))
    if new_state == 'unknown':
        return GuardAssessment(RULE, 'inconclusive', old_scope, new_scope, kinds, (),
                               tuple(sorted(new_unknowns)))
    if new_state == 'absent' or old_state == 'observed':
        return GuardAssessment(RULE, 'not-observed', old_scope, new_scope, kinds, (), ())
    return GuardAssessment(RULE, 'candidate', old_scope, new_scope, kinds, new_support,
                           ('control-dependence-not-verified', 'input-trust-not-verified',
                            'memory-alias-not-verified', 'old-new-sink-correspondence-not-verified',
                            'path-feasibility-not-verified', 'predicate-polarity-not-verified'))
