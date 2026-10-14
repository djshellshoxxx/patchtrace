"""PIL-B1 rule table: closed leaf vocabulary, validation, versioned digest, the table for the K rules and the
three-valued evaluation of expected changes (docs/specs/program-e/PIL-integration-plan.md s7 "Rule data", s9).
Synthetic evidence only; nothing here is live evidence.

Mandatory gates of PIL-B1: `test_every_k_rule_has_expected_changes`, one positive and one negative fixture per
family (ids = family names), `test_cwe_detector_map_consistent_with_rules`.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import patchtrace.pilot.rules as rules_package
from patchtrace.enrichment import cve as b3
from patchtrace.enrichment import signals as b1
from patchtrace.enrichment.contracts import Confidence
from patchtrace.intelligence import hypotheses as k_rules
from patchtrace.intelligence import lexicon
from patchtrace.pilot import keys
from patchtrace.pilot.contracts import KIND_CHANNEL, ChannelState, ObsRef, Role
from patchtrace.pilot.limits import DEFAULT_LIMITS, PilotError
from patchtrace.pilot.rules import contracts as rc
from patchtrace.pilot.rules import data
from patchtrace.pilot.rules import evaluate as ev
from patchtrace.unified import contracts as unified

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(rules_package.__file__).parent  # the package under test, wherever it is imported from
FAMILIES = tuple(lexicon.FAMILIES)
K_BY_FAMILY = {rule.family: rule for rule in k_rules.RULES}
AVAILABLE = {name: 'available' for name in ('code', 'calls', 'capa', 'strings')}
PROPS = settings(deadline=None, max_examples=80, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
# Re-baseline deliberately: a changed digest makes every stored localization result stale (plan s7 `result_id`).
PINNED_DIGEST = '33c9cad941c718c55a09094c07c79bebba2d0a1bdbab9e71f8c78df071272122'


def oid(*parts) -> str:
    return hashlib.sha256('|'.join(map(str, parts)).encode()).hexdigest()


def obs(kind: str, role: str = 'shape', level: str | None = None, subject: str | None = None,
        tag: str = '') -> ev.Evidence:
    return ev.Evidence(oid(kind, role, level, subject, tag), kind, role, level, subject)


def obs_ids(*evidence: ev.Evidence) -> tuple[str, ...]:
    return tuple(sorted(e.obs_id for e in evidence))


def run(family: str, evidence, channels=AVAILABLE) -> ev.Evaluation:
    k = K_BY_FAMILY[family]
    return ev.evaluate_rule(data.find_rule(k.id, k.revision), evidence, channels, k.api_hints)


def states(result: ev.Evaluation) -> dict[str, str]:
    return {change.id: change.state for change in result.changes}


def change(id_: str, *leaves: str, required: bool = True, teach: str | None = None) -> rc.ChangeSpec:
    return rc.ChangeSpec(id_, required, leaves, teach or f'pilot.change.{id_}')


def rule(*changes: rc.ChangeSpec, rule_id: str = 'R-TEST', revision: int = 1,
         counters: tuple[str, ...] = ('cf:cosmetic', 'cf:unchanged')) -> rc.PilotRule:
    return rc.PilotRule(rule_id, revision, changes or (change('a', 'cf:comparison'),), counters)


def synthetic(floor: str = 'weak') -> rc.PilotRule:
    return rule(change('guard', f'b1:INT@{floor}', 'cf:comparison'),
                change('api', 'call:added@api_hints', required=False),
                change('cap', 'capa:ns=host-interaction/process', required=False))


# --- coverage of the K rules (gate) and the rows of plan s7 ---------------------------------------------------------

def test_every_k_rule_has_expected_changes():
    for k in k_rules.RULES:
        found = data.find_rule(k.id, k.revision)
        assert found is not None, f'{k.id} r{k.revision} has no expected changes: PIL would fail closed to unexplained'
        assert found.changes and found.changes[0].required
    assert {(r.rule_id, r.revision) for r in data.RULES} == {(k.id, k.revision) for k in k_rules.RULES}


def test_an_unknown_rule_or_revision_is_none_so_the_lead_fails_closed():
    assert data.find_rule('R-MEMORY-WRITE', 99) is None and data.find_rule('R-NO-SUCH-RULE', 1) is None


_MEMORY = (('guard-added', True), ('size-recomputed', False), ('checked-arithmetic', False))
_PROBE = (('check-or-probe', True),)
_API = (('api-level', True),)
SHAPE = {
    'R-MEMORY-WRITE': _MEMORY, 'R-MEMORY-READ': _MEMORY, 'R-BOUNDS': _MEMORY,
    'R-INTEGER': (('overflow-check', True), ('range-check', False)),
    'R-INFO': (('zeroed', True),), 'R-UNINIT': (('zeroed', True),),
    'R-INPUT': (('validation-added', True),),
    'R-LIFETIME': (('ref-release', True), ('state-check', False)),
    'R-NULL-DEREF': _PROBE, 'R-POINTER': _PROBE, 'R-TYPE': _PROBE,
    'R-RACE': _API, 'R-AUTHN': _API, 'R-AUTHZ': _API, 'R-PATH': _API, 'R-RESOURCE': _API, 'R-INJECTION': _API,
    'R-DESERIALIZATION': _API, 'R-SEARCH-PATH': _API, 'R-CRYPTO-VERIFY': _API,
    'R-FORMAT-STRING': (('constant-format', True),), 'R-OFF-BY-ONE': (('bound-adjusted', True),),
}
WITHOUT_B1 = {'R-LIFETIME', 'R-NULL-DEREF', 'R-POINTER', 'R-TYPE', 'R-RACE', 'R-AUTHN', 'R-AUTHZ', 'R-PATH',
              'R-RESOURCE', 'R-INJECTION', 'R-DESERIALIZATION', 'R-SEARCH-PATH', 'R-CRYPTO-VERIFY', 'R-FORMAT-STRING'}


def test_table_reproduces_the_rows_of_plan_s7_required_change_first():
    assert {r.rule_id: tuple((c.id, c.required) for c in r.changes) for r in data.RULES} == SHAPE
    assert all(r.revision == 1 for r in data.RULES)


def test_rows_without_a_b1_detector_are_the_api_level_and_check_rows():
    """PIL-B2 holds these rows at tentative unless two components agree (plan s7 rule data)."""
    assert {r.rule_id for r in data.RULES if not r.detectors} == WITHOUT_B1
    assert data.find_rule('R-MEMORY-WRITE', 1).detectors == ('BND', 'OVF', 'SIZE')
    assert data.find_rule('R-INPUT', 1).detectors == ('BND', 'ERR', 'VAL')


def test_every_rule_lists_both_conflict_leaves_and_no_capa_leaf():
    for r in data.RULES:
        assert r.counters == ('cf:cosmetic', 'cf:unchanged'), r.rule_id
        assert not [leaf for c in r.changes for leaf in c.leaves if leaf.prefix in ('capa', 'str')], r.rule_id


def test_teach_ids_follow_the_change_id_and_cover_the_plan_hooks():
    taught = {c.teach_id for r in data.RULES for c in r.changes}
    assert all(c.teach_id == f'pilot.change.{c.id}' for r in data.RULES for c in r.changes)
    assert {'pilot.change.guard-added', 'pilot.change.size-recomputed', 'pilot.change.checked-arithmetic',
            'pilot.change.ref-release', 'pilot.change.zeroed'} <= taught


def test_call_leaves_appear_only_where_the_k_rule_has_api_hints():
    for k in k_rules.RULES:
        found = data.find_rule(k.id, k.revision)
        has_call = any(leaf.prefix == 'call' for c in found.changes for leaf in c.leaves)
        assert not has_call or k.api_hints, f'{k.id} reads call leaves but K gives it no api_hints'
    assert not k_rules.rule_for('null-deref').api_hints and not k_rules.rule_for('input').api_hints
    assert not k_rules.rule_for('deserialization').api_hints


def test_table_stays_inside_the_p07_limits():
    assert len(data.RULES) <= DEFAULT_LIMITS.p07_rules
    for r in data.RULES:
        assert len(r.changes) <= DEFAULT_LIMITS.p07_changes_per_rule
        assert all(len(c.any_of) <= DEFAULT_LIMITS.p07_leaves_per_change for c in r.changes)


# --- the plan s5 ledger rows at rule level --------------------------------------------------------------------------

def test_plan_s5_f1_reads_two_of_three_expected_changes_with_one_of_one_required():
    bnd, compare = obs('b1:BND', level='moderate'), obs('cf:comparison')
    arith = obs('call:added', subject='RtlSizeTAdd')
    result = run('memory-write', [bnd, compare, arith])
    assert states(result) == {'guard-added': 'met', 'size-recomputed': 'not-observed', 'checked-arithmetic': 'met'}
    assert result.changes[0].observation_ids == obs_ids(bnd, compare)
    assert result.changes[2].observation_ids == obs_ids(arith)
    assert [c.required for c in result.changes] == [True, False, False]


def test_plan_s5_other_ledger_rows_never_meet_the_required_change():
    for name, evidence in {
        'F4 allocation size doubled, no guard': [obs('b1:SIZE', level='moderate')],
        'F5 call added to a counter': [obs('call:added', subject='InterlockedIncrement')],
        'F2 new logging string': [obs('str:added', 'context')],
        'F7 callee swapped': [obs('cf:callee')],
        'F3 register-only churn': [obs('cf:register-only')],
    }.items():
        assert run('memory-write', evidence).changes[0].state != 'met', name
    assert run('memory-write', [obs('b1:SIZE', level='moderate')]).changes[1].state == 'met'


def test_plan_s5_f9_b1_guard_next_to_a_cosmetic_proof_stays_met_and_reports_the_conflict():
    bnd, proof = obs('b1:BND', level='moderate'), obs('cf:cosmetic', 'conflict')
    result = run('memory-write', [bnd, proof])
    assert states(result) == {'guard-added': 'met', 'size-recomputed': 'contradicted',
                              'checked-arithmetic': 'contradicted'}
    assert result.conflict_ids == (proof.obs_id,)


# --- per-family positive and negative fixtures (gate; ids = family names) -------------------------------------------

FIXTURES = {
    'memory-write': ([obs('b1:BND', level='moderate')],
                     [obs('b1:SCRUB', level='moderate'), obs('cf:callee'), obs('b1:BND', 'local', 'moderate'),
                      obs('str:added', 'context')]),
    'memory-read': ([obs('cf:condition')],
                    [obs('b1:VAL', level='weak'), obs('cf:string'), obs('cf:condition', 'context')]),
    'bounds': ([obs('cf:comparison')],
               [obs('b1:ERR', level='weak'), obs('cf:callee'), obs('cf:comparison', 'local')]),
    'lifetime': ([obs('call:removed', subject='ObDereferenceObject')],
                 [obs('call:removed', subject='memcpy'), obs('call:added', subject='RtlZeroMemory'),
                  obs('call:added', 'context', subject='ObReferenceObject')]),
    'null-deref': ([obs('cf:comparison')],
                   [obs('cf:callee'), obs('b1:SCRUB', level='moderate'), obs('cf:comparison', 'local')]),
    'pointer': ([obs('call:added', subject='ProbeForRead')],
                [obs('call:added', subject='memcpy'), obs('call:removed', subject='ProbeForRead'),
                 obs('b1:SCRUB', level='moderate')]),
    'integer': ([obs('b1:OVF', level='moderate')],
                [obs('b1:SCRUB', level='moderate'), obs('call:added', subject='memcpy'),
                 obs('b1:OVF', 'context', 'moderate')]),
    'type': ([obs('call:added', subject='ObReferenceObjectByHandle')],
             [obs('call:added', subject='ObDereferenceObject'), obs('b1:BND', level='moderate'),
              obs('cf:string')]),
    'race': ([obs('call:added', subject='InterlockedCompareExchange')],
             [obs('call:added', subject='memcpy'), obs('b1:BND', level='moderate'), obs('cf:comparison')]),
    'authentication': ([obs('cf:callee')],
                       [obs('cf:comparison'), obs('call:added', subject='SeAccessCheck'),
                        obs('b1:VAL', level='weak')]),
    'authorization': ([obs('call:added', subject='SeAccessCheck')],
                      [obs('call:added', subject='AcceptSecurityContext'), obs('cf:string'),
                       obs('cf:comparison')]),
    'path': ([obs('call:added', subject='PathCchCanonicalizeEx')],
             [obs('call:added', subject='LoadLibraryExW'), obs('cf:comparison'), obs('str:added', 'context')]),
    'info-exposure': ([obs('b1:SCRUB', level='moderate')],
                      [obs('b1:SIZE', level='moderate'), obs('cf:comparison'),
                       obs('call:removed', subject='RtlZeroMemory')]),
    'uninitialized': ([obs('call:added', subject='RtlZeroMemory')],
                      [obs('call:removed', subject='RtlZeroMemory'), obs('b1:BND', level='moderate'),
                       obs('call:added', subject='memcpy')]),
    'resource': ([obs('call:removed', subject='CloseHandle')],
                 [obs('call:added', subject='memcpy'), obs('b1:BND', level='moderate'), obs('cf:string')]),
    'input': ([obs('b1:VAL', level='weak')],
              [obs('b1:VAL'), obs('b1:SCRUB', level='moderate'), obs('cf:callee')]),
    'injection': ([obs('call:added', subject='KERNEL32.dll!CreateProcessA')],
                  [obs('call:added', subject='CreateFileW'), obs('cf:comparison'), obs('cf:string')]),
    'deserialization': ([obs('cf:constant')],
                        [obs('cf:comparison'), obs('call:added', subject='CoCreateInstance'),
                         obs('b1:BND', level='moderate')]),
    'search-path': ([obs('call:added', subject='SetDefaultDllDirectories')],
                    [obs('call:added', subject='CreateFileW'), obs('cf:comparison'),
                     obs('b1:BND', level='moderate')]),
    'crypto-verify': ([obs('call:added', subject='WinVerifyTrust')],
                      [obs('call:added', subject='memcpy'), obs('cf:comparison'), obs('b1:VAL', level='weak')]),
    'format-string': ([obs('cf:string')],
                      [obs('str:added', 'context'), obs('cf:comparison'), obs('b1:BND', level='moderate')]),
    'off-by-one': ([obs('b1:INT', level='moderate')],
                   [obs('b1:INT', level='weak'), obs('b1:SCRUB', level='moderate'), obs('cf:string')]),
}


def test_fixtures_cover_every_k_family():
    assert set(FIXTURES) == set(FAMILIES)


@pytest.mark.parametrize('family', FAMILIES, ids=FAMILIES)
def test_positive_fixture_meets_exactly_the_required_change(family):
    positive, _ = FIXTURES[family]
    required, *optional = run(family, positive).changes
    assert required.required and required.state == 'met' and required.observation_ids == obs_ids(*positive)
    assert {c.state for c in optional} <= {'not-observed'}
    assert run(family, positive).conflict_ids == ()


@pytest.mark.parametrize('family', FAMILIES, ids=FAMILIES)
def test_negative_fixture_leaves_every_change_not_observed(family):
    _, negative = FIXTURES[family]
    result = run(family, negative)
    assert set(states(result).values()) == {'not-observed'}, states(result)
    assert result.conflict_ids == ()


def evidence_for(leaf: rc.Leaf, hints: tuple[str, ...]) -> ev.Evidence:
    """The weakest evidence that must meet `leaf`."""
    if leaf.prefix == 'b1':
        return obs(leaf.kind, level=leaf.floor)
    if leaf.prefix == 'call':
        return obs(leaf.kind, subject=hints[0])
    return obs(leaf.kind)


@pytest.mark.parametrize('family', FAMILIES, ids=FAMILIES)
def test_every_leaf_of_a_row_meets_exactly_its_own_change(family):
    k = K_BY_FAMILY[family]
    row = data.find_rule(k.id, k.revision)
    for spec in row.changes:
        for leaf in spec.leaves:
            result = run(family, [evidence_for(leaf, k.api_hints)])
            expected = {c.id: 'met' if c.id == spec.id else 'not-observed' for c in row.changes}
            assert states(result) == expected, f'{k.id} {spec.id} {leaf.text}'
            if leaf.floor == 'moderate':  # one level below the floor is not enough
                assert states(run(family, [obs(leaf.kind, level='weak')]))[spec.id] == 'not-observed', leaf.text


@pytest.mark.parametrize('family', FAMILIES, ids=FAMILIES)
def test_added_string_and_build_flag_alone_never_meet_or_contradict_a_change(family):
    """SPEC-30 negative: a newly added string cannot prove remediation; DiE flags never promote."""
    for role in ('context', 'shape'):
        result = run(family, [obs('str:added', role), obs('die:toolchain-changed', role)])
        assert set(states(result).values()) == {'not-observed'} and result.conflict_ids == ()


# --- B3 duplicate truth (gate) --------------------------------------------------------------------------------------

B3_ONLY = {'CWE-680'}  # B3 maps it, the K lexicon cannot classify it, so no K hypothesis and no row can exist


def test_cwe_detector_map_consistent_with_rules():
    assert {cwe for cwe in b3.CWE_DETECTORS if lexicon.family(cwe) is None} == B3_ONLY
    for cwe, detectors in b3.CWE_DETECTORS.items():
        family = lexicon.family(cwe)
        if family is None:
            continue
        k = K_BY_FAMILY[family]
        leaves = [leaf for c in data.find_rule(k.id, k.revision).changes for leaf in c.leaves if leaf.prefix == 'b1']
        for detector in detectors:
            floors = [leaf.floor for leaf in leaves if leaf.name == detector]
            assert floors, f'{cwe}: B3 credits {detector} but {k.id} has no b1:{detector} leaf'
            top = rc.LEVELS.index(rc.B1_CEILING[detector])
            for level in rc.LEVELS[:top + 1]:
                if level in b3.ALIGNING_CONFIDENCE:  # B3 credits only these; the row must accept each of them too
                    assert any(rc.LEVELS.index(floor) <= rc.LEVELS.index(level) for floor in floors), (cwe, detector)


def _detectors_overriding_confidence() -> set[str]:
    rule_of = {d.rule.__name__: d.id for d in b1.DETECTORS}
    found = set()
    for node in ast.walk(ast.parse(inspect.getsource(b1))):
        if isinstance(node, ast.FunctionDef) and node.name in rule_of:
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and getattr(call.func, 'id', None) == '_Finding':
                    if len(call.args) > 3 or any(k.arg == 'confidence' for k in call.keywords):
                        found.add(rule_of[node.name])
    return found


def test_vocabulary_matches_b1_and_spec_31():
    assert set(rc.B1_CEILING) == {d.id for d in b1.DETECTORS}
    assert rc.LEVELS == ('weak', 'moderate', 'strong') and set(rc.LEVELS) == set(get_args(Confidence)) - {'unavailable'}
    overriding = _detectors_overriding_confidence()
    assert overriding == {'INT'}, 'a B1 detector now reports a confidence other than its default: update B1_CEILING'
    for d in b1.DETECTORS:
        assert rc.B1_CEILING[d.id] == ('moderate' if d.id in overriding else d.confidence), d.id
    assert 'strong' not in rc.B1_CEILING.values()  # no B1 detector reaches `strong`, so no floor may ask for it
    assert set(rc.CF_SHAPE) == set(unified.SEMANTIC_CLASSES) <= set(get_args(unified.ChangeClass))
    assert set(rc.CF_CONFLICT) == {'cosmetic', 'unchanged'} <= set(unified.MATERIALITIES)


def _kinds_read_by_the_table() -> list[str]:
    kinds = {leaf.kind for r in data.RULES for c in r.changes for leaf in c.leaves if leaf.kind}
    kinds |= {leaf.kind for r in data.RULES for leaf in r.conflicts}
    return sorted(kinds)


@pytest.mark.parametrize('kind', _kinds_read_by_the_table())
def test_every_leaf_kind_is_a_valid_observation_kind(kind):
    """The frozen A1 `Observation` must be able to carry what the table reads (kind pattern, channel, role)."""
    role = 'conflict' if kind in ('cf:cosmetic', 'cf:unchanged') else 'shape'
    probe = keys.make_observation(channel=KIND_CHANNEL[kind.split(':')[0]], kind=kind, role=role,
                                  verification='tool-reported', origins=('D_ghidra',), evidence_class='E-DECOMP',
                                  ref=ObsRef(kind='probe', id='x'), detail='probe')
    assert probe.kind == kind


# --- leaf grammar and validation ------------------------------------------------------------------------------------

@pytest.mark.parametrize('text, prefix, name, floor, role, kind', [
    ('b1:BND@moderate', 'b1', 'BND', 'moderate', 'shape', 'b1:BND'),
    ('b1:VAL@weak', 'b1', 'VAL', 'weak', 'shape', 'b1:VAL'),
    ('b1:INT@moderate', 'b1', 'INT', 'moderate', 'shape', 'b1:INT'),
    ('cf:comparison', 'cf', 'comparison', None, 'shape', 'cf:comparison'),
    ('cf:cosmetic', 'cf', 'cosmetic', None, 'conflict', 'cf:cosmetic'),
    ('cf:unchanged', 'cf', 'unchanged', None, 'conflict', 'cf:unchanged'),
    ('call:added@api_hints', 'call', 'added', None, 'shape', 'call:added'),
    ('call:removed@api_hints', 'call', 'removed', None, 'shape', 'call:removed'),
    ('capa:ns=host-interaction/process', 'capa', 'host-interaction/process', None, 'shape', None),
    ('str:*', 'str', '*', None, 'context', None),
], ids=['b1-bnd', 'b1-val', 'b1-int', 'cf-class', 'cf-cosmetic', 'cf-unchanged', 'call-added', 'call-removed',
        'capa', 'str'])
def test_parse_leaf_accepts_the_closed_vocabulary(text, prefix, name, floor, role, kind):
    leaf = rc.parse_leaf(text)
    assert (leaf.text, leaf.prefix, leaf.name, leaf.floor, leaf.role, leaf.kind) == (
        text, prefix, name, floor, role, kind)


def expect(reason: str, build) -> None:
    with pytest.raises(PilotError) as info:
        build()
    assert (info.value.code, info.value.reason) == ('PT-PILOT-RULES', reason), info.value
    assert info.value.exit_code == 3 and str(info.value)


def many(count: int) -> tuple[str, ...]:
    """`count` distinct, valid shape leaves (the vocabulary has 18)."""
    pool = [f'b1:{d}@{rc.B1_CEILING[d]}' for d in rc.B1_CEILING] + [f'cf:{c}' for c in rc.CF_SHAPE]
    pool += ['call:added@api_hints', 'call:removed@api_hints']
    assert len(pool) >= count
    return tuple(pool[:count])


BAD = [
    pytest.param(lambda: rc.parse_leaf('b1:BND'), 'bad-leaf', id='no-floor'),
    pytest.param(lambda: rc.parse_leaf(' b1:BND@moderate'), 'bad-leaf', id='whitespace'),
    pytest.param(lambda: rc.parse_leaf('b1:BND@high'), 'bad-leaf', id='level-name'),
    pytest.param(lambda: rc.parse_leaf('b1:WIL@weak'), 'unknown-detector', id='detector'),
    pytest.param(lambda: rc.parse_leaf('b1:VAL@moderate'), 'unreachable-level', id='floor-above-ceiling'),
    pytest.param(lambda: rc.parse_leaf('b1:BND@strong'), 'unreachable-level', id='strong-floor'),
    pytest.param(lambda: rc.parse_leaf('cf:address-only'), 'unknown-change-class', id='noise-class'),
    pytest.param(lambda: rc.parse_leaf('cf:teleport'), 'unknown-change-class', id='unknown-class'),
    pytest.param(lambda: rc.parse_leaf('call:added@imports'), 'bad-leaf', id='call-source'),
    pytest.param(lambda: rc.parse_leaf('call:changed@api_hints'), 'bad-leaf', id='call-direction'),
    pytest.param(lambda: rc.parse_leaf('capa:ns=/host'), 'bad-leaf', id='capa-slash'),
    pytest.param(lambda: rc.parse_leaf('capa:ns=Host'), 'bad-leaf', id='capa-case'),
    pytest.param(lambda: rc.parse_leaf('die:toolchain-changed'), 'bad-leaf', id='die'),
    pytest.param(lambda: rc.parse_leaf(3), 'bad-leaf', id='not-text'),
    pytest.param(lambda: change('x', 'str:*'), 'context-leaf', id='string-leaf'),
    pytest.param(lambda: change('x', 'cf:cosmetic'), 'leaf-position', id='conflict-as-shape'),
    pytest.param(lambda: rule(counters=('cf:comparison',)), 'leaf-position', id='shape-as-counter'),
    pytest.param(lambda: rule(counters=('str:*',)), 'context-leaf', id='string-counter'),
    pytest.param(lambda: rule(counters=('cf:cosmetic', 'cf:cosmetic')), 'duplicate-leaf', id='duplicate-counter'),
    pytest.param(lambda: change('x'), 'no-leaves', id='empty-leaves'),
    pytest.param(lambda: change('x', *many(17)), 'too-many-leaves', id='leaf-limit'),
    pytest.param(lambda: change('x', 'cf:comparison', 'cf:comparison'), 'duplicate-leaf', id='leaf-twice'),
    pytest.param(lambda: change('x', 'b1:INT@weak', 'b1:INT@moderate'), 'duplicate-leaf', id='detector-twice'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('b', 'cf:comparison', required=False)),
                 'duplicate-leaf', id='leaf-in-two-changes'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('a', 'cf:condition', required=False)),
                 'duplicate-change', id='change-twice'),
    pytest.param(lambda: rule(change('a', 'cf:comparison', required=False)), 'no-required-change',
                 id='no-required'),
    pytest.param(lambda: rule(change('a', 'cf:comparison', required=False), change('b', 'cf:condition')),
                 'required-after-optional', id='required-last'),
    pytest.param(lambda: rc.PilotRule('R-TEST', 1, (), ()), 'no-changes', id='no-changes'),
    pytest.param(lambda: rule(*[change(f'c{i}', leaf, required=i == 0) for i, leaf in enumerate(many(17))]),
                 'too-many-changes', id='change-limit'),
    pytest.param(lambda: rule(rule_id='memory-write'), 'bad-rule-id', id='rule-id'),
    pytest.param(lambda: rule(revision=0), 'bad-revision', id='revision-zero'),
    pytest.param(lambda: rule(revision=True), 'bad-revision', id='revision-bool'),
    pytest.param(lambda: change('Guard Added', 'cf:comparison'), 'bad-change-id', id='change-id'),
    pytest.param(lambda: change('x', 'cf:comparison', teach='pilot.state.x'), 'bad-teach-id', id='teach-prefix'),
    pytest.param(lambda: change('x', 'cf:comparison', teach='guard'), 'bad-teach-id', id='teach-shape'),
    pytest.param(lambda: rc.ChangeSpec('x', True, 'cf:comparison', 'pilot.change.x'), 'bad-shape',
                 id='leaves-as-text'),
    pytest.param(lambda: rc.ChangeSpec('x', 'yes', ('cf:comparison',), 'pilot.change.x'), 'bad-required',
                 id='required-flag'),
    pytest.param(lambda: rc.PilotRule('R-TEST', 1, ('cf:comparison',), ()), 'bad-shape', id='changes-as-text'),
    pytest.param(lambda: rc.RuleTable(['R-TEST']), 'bad-shape', id='rules-as-text'),
    pytest.param(lambda: rc.RuleTable([rule(), rule()]), 'duplicate-rule', id='rule-twice'),
    pytest.param(lambda: rc.RuleTable([rule(rule_id=f'R-T{i}') for i in range(DEFAULT_LIMITS.p07_rules + 1)]),
                 'too-many-rules', id='rule-limit'),
]


@pytest.mark.parametrize('build, reason', BAD)
def test_a_defective_table_entry_is_refused_with_its_own_reason(build, reason):
    expect(reason, build)


def test_limits_are_inclusive_and_a_second_revision_of_a_rule_is_allowed():
    change('x', *many(DEFAULT_LIMITS.p07_leaves_per_change))
    full = [change(f'c{i}', leaf, required=i == 0) for i, leaf in enumerate(many(DEFAULT_LIMITS.p07_changes_per_rule))]
    assert len(rule(*full).changes) == DEFAULT_LIMITS.p07_changes_per_rule
    table = rc.RuleTable([rule(rule_id=f'R-T{i}') for i in range(DEFAULT_LIMITS.p07_rules)])
    assert len(table.rules) == DEFAULT_LIMITS.p07_rules
    two = rc.RuleTable([rule(revision=2), rule(revision=1)])
    assert [r.revision for r in two.rules] == [1, 2] and two.find('R-TEST', 2).revision == 2
    assert two.find('R-TEST', 3) is None


def test_lists_are_normalised_to_tuples_and_models_are_immutable():
    spec = rc.ChangeSpec('x', True, ['cf:comparison'], 'pilot.change.x')
    assert spec.any_of == ('cf:comparison',) and isinstance(spec.leaves, tuple)
    with pytest.raises(AttributeError):
        spec.required = False
    assert spec.channels == ('code',) and change('y', 'call:added@api_hints').channels == ('calls',)
    assert synthetic().changes[2].channels == ('capa',)


# --- versioned digest -----------------------------------------------------------------------------------------------

def test_digest_is_hex_deterministic_and_pinned():
    digest = data.pilot_rules_digest()
    assert re.fullmatch(r'[0-9a-f]{64}', digest) and digest == data.TABLE.digest() == data.pilot_rules_digest()
    assert digest == PINNED_DIGEST, 'the rule table changed: re-baseline PINNED_DIGEST on purpose (results go stale)'


def test_digest_is_identical_across_hash_seeds():
    code = 'from patchtrace.pilot.rules import data\nprint(data.pilot_rules_digest())\n'
    outputs = set()
    for seed in ('1', '2', '3'):
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
        assert result.returncode == 0, result.stderr
        outputs.add(result.stdout.strip())
    assert outputs == {data.pilot_rules_digest()}


def test_digest_ignores_authoring_order_of_rules_and_leaves_but_not_the_order_of_changes():
    a, b = rule(change('a', 'cf:comparison', 'cf:condition')), rule(rule_id='R-OTHER')
    assert rc.RuleTable([a, b]).digest() == rc.RuleTable([b, a]).digest()
    reversed_leaves = rule(change('a', 'cf:condition', 'cf:comparison'))
    assert rc.RuleTable([a]).digest() == rc.RuleTable([reversed_leaves]).digest()
    first = rule(change('a', 'cf:comparison'), change('b', 'cf:condition', required=False))
    swapped = rule(change('a', 'cf:comparison'), change('c', 'cf:condition', required=False))
    assert rc.RuleTable([first]).digest() != rc.RuleTable([swapped]).digest()


def _base() -> rc.PilotRule:
    return rule(change('a', 'cf:comparison'), change('b', 'cf:condition', required=False))


@pytest.mark.parametrize('edit', [
    pytest.param(lambda: rule(change('a', 'cf:comparison', 'cf:constant'), change('b', 'cf:condition', required=False)),
                 id='leaf-added'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('b', 'cf:constant', required=False)),
                 id='leaf-changed'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('c', 'cf:condition', required=False)),
                 id='change-id'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'),
                              change('b', 'cf:condition', required=False, teach='pilot.change.other')),
                 id='teach-id'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('b', 'cf:condition')), id='required-flag'),
    pytest.param(lambda: rule(change('a', 'cf:comparison')), id='change-removed'),
    pytest.param(lambda: rule(change('b', 'cf:condition'), change('a', 'cf:comparison', required=False)),
                 id='change-order'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('b', 'cf:condition', required=False),
                              counters=('cf:cosmetic',)), id='counter-removed'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('b', 'cf:condition', required=False),
                              revision=2), id='revision'),
    pytest.param(lambda: rule(change('a', 'cf:comparison'), change('b', 'cf:condition', required=False),
                              rule_id='R-OTHER'), id='rule-id'),
])
def test_digest_changes_with_every_semantic_edit(edit):
    assert rc.RuleTable([edit()]).digest() != rc.RuleTable([_base()]).digest()


@pytest.mark.parametrize('name, value', [
    ('PILOT_RULES_VERSION', 'pilot-rules/2'),
    ('LEVELS', ('weak', 'moderate', 'strong', 'typed')),
    ('B1_CEILING', {**rc.B1_CEILING, 'VAL': 'moderate'}),
    ('CF_SHAPE', (*rc.CF_SHAPE, 'frame')),
    ('CF_CONFLICT', (*rc.CF_CONFLICT, 'moved')),
], ids=['version', 'levels', 'b1-ceiling', 'cf-shape', 'cf-conflict'])
def test_digest_changes_with_the_table_version_and_each_vocabulary_table(monkeypatch, name, value):
    table = rc.RuleTable([_base()])
    base = table.digest()
    monkeypatch.setattr(rc, name, value)
    assert table.digest() != base
    monkeypatch.undo()
    assert table.digest() == base


# --- evaluation semantics (synthetic rule) --------------------------------------------------------------------------

def test_met_keeps_every_matching_observation_sorted_and_in_rule_order():
    a, b = obs('b1:INT', level='weak', tag='a'), obs('cf:comparison', tag='b')
    result = ev.evaluate_rule(synthetic(), [b, a, a], AVAILABLE, ())
    assert [c.id for c in result.changes] == ['guard', 'api', 'cap']
    assert result.changes[0].state == 'met' and result.changes[0].observation_ids == obs_ids(a, b)
    assert [(c.required, c.teach_id) for c in result.changes] == [
        (True, 'pilot.change.guard'), (False, 'pilot.change.api'), (False, 'pilot.change.cap')]
    assert result.conflict_ids == ()


@pytest.mark.parametrize('role', ['local', 'counter', 'conflict', 'context', 'bogus'])
def test_only_shape_evidence_can_meet_a_change(role):
    result = ev.evaluate_rule(synthetic(), [obs('cf:comparison', role)], AVAILABLE, ())
    assert states(result)['guard'] == 'not-observed' and result.conflict_ids == ()


@pytest.mark.parametrize('floor, level, met', [
    ('weak', 'weak', True), ('weak', 'moderate', True), ('weak', 'strong', True), ('weak', None, False),
    ('moderate', 'weak', False), ('moderate', 'moderate', True), ('moderate', 'strong', True),
    ('moderate', None, False), ('moderate', 'bogus', False),
], ids=['w-w', 'w-m', 'w-s', 'w-none', 'm-w', 'm-m', 'm-s', 'm-none', 'm-bogus'])
def test_b1_leaf_needs_a_signal_at_least_at_its_floor(floor, level, met):
    lone = rule(change('guard', f'b1:INT@{floor}'))
    state = ev.evaluate_rule(lone, [obs('b1:INT', level=level)], AVAILABLE, ()).changes[0].state
    assert state == ('met' if met else 'not-observed')


def test_b1_leaf_reads_only_its_own_detector():
    lone = rule(change('guard', 'b1:INT@weak'))
    assert ev.evaluate_rule(lone, [obs('b1:BND', level='moderate')], AVAILABLE, ()).changes[0].state == 'not-observed'


@pytest.mark.parametrize('subject, hints, met', [
    ('RtlSizeTAdd', ('RtlSizeTAdd',), True),
    ('rtlsizetadd', ('RtlSizeTAdd',), True),
    ('ntoskrnl.exe!RtlSizeTAdd', ('RtlSizeTAdd',), True),
    ('CreateFileA', ('CreateFileW',), True),
    ('CreateFile', ('CreateFileW',), True),
    ('memcpy', ('RtlSizeTAdd',), False),
    ('RtlSizeTAdd', (), False),
    (None, ('RtlSizeTAdd',), False),
    ('', ('RtlSizeTAdd',), False),
], ids=['exact', 'case', 'module', 'ansi', 'macro', 'other-api', 'no-hints', 'no-subject', 'empty-subject'])
def test_call_leaf_matches_the_api_key_against_the_k_hints(subject, hints, met):
    state = ev.evaluate_rule(synthetic(), [obs('call:added', subject=subject)], AVAILABLE, hints).changes[1].state
    assert state == ('met' if met else 'not-observed')


def test_api_hints_must_be_a_collection_of_names_not_a_string():
    """A bare string would silently become its characters."""
    with pytest.raises(TypeError):
        ev.evaluate_rule(synthetic(), [], AVAILABLE, 'memcpy')


def test_call_leaf_reads_only_its_direction():
    only_added = rule(change('api', 'call:added@api_hints'))
    result = ev.evaluate_rule(only_added, [obs('call:removed', subject='memcpy')], AVAILABLE, ('memcpy',))
    assert result.changes[0].state == 'not-observed'


@pytest.mark.parametrize('subject, met', [
    ('host-interaction/process', True), ('host-interaction/process/create', True),
    ('host-interaction/processor', False), ('host-interaction', False), ('linking/runtime-linking', False),
    (None, False),
], ids=['exact', 'child', 'sibling-prefix', 'parent', 'other', 'no-subject'])
@pytest.mark.parametrize('kind', ['capa:added', 'capa:removed'])
def test_capa_leaf_matches_a_namespace_at_a_path_boundary(kind, subject, met):
    state = ev.evaluate_rule(synthetic(), [obs(kind, subject=subject)], AVAILABLE, ()).changes[2].state
    assert state == ('met' if met else 'not-observed')


@pytest.mark.parametrize('name, key', [
    ('memcpy', 'memcpy'), ('MemCpy', 'memcpy'), ('KERNEL32.dll!CreateFileW', 'createfile'),
    ('CreateFileA', 'createfile'), ('CreateFile', 'createfile'), ('RtlSizeTAdd', 'rtlsizetadd'),
    ('Abcw', 'abcw'), ('Abcdw', 'abcd'), ('ExAllocatePool2', 'exallocatepool2'), ('a!b!Name', 'name'),
], ids=['plain', 'case', 'module-wide', 'ansi', 'macro', 'helper', 'short-kept', 'folded-at-4', 'digit', 'last-bang'])
def test_api_key_is_lower_case_without_module_and_folds_a_trailing_a_or_w(name, key):
    assert ev.api_key(name) == key


@pytest.mark.parametrize('state', ['partial', 'not-run', 'unsupported', 'failed', 'stale'])
def test_a_channel_that_is_not_available_makes_only_its_changes_unknown(state):
    for channel, unknown in (('code', 'guard'), ('calls', 'api'), ('capa', 'cap')):
        expected = {'guard': 'not-observed', 'api': 'not-observed', 'cap': 'not-observed', unknown: 'unknown'}
        result = ev.evaluate_rule(synthetic(), [], {**AVAILABLE, channel: state}, ())
        assert states(result) == expected


def test_a_channel_missing_from_the_mapping_is_unknown_never_a_negative():
    assert set(states(ev.evaluate_rule(synthetic(), [], {}, ())).values()) == {'unknown'}


def test_the_strings_channel_never_matters_to_a_change():
    degraded = {**AVAILABLE, 'strings': 'failed', 'build': 'not-run'}
    assert set(states(ev.evaluate_rule(synthetic(), [], degraded, ())).values()) == {'not-observed'}


def test_a_met_change_ignores_unavailable_channels():
    result = ev.evaluate_rule(synthetic(), [obs('b1:INT', level='weak')], {'code': 'partial'}, ())
    assert states(result) == {'guard': 'met', 'api': 'unknown', 'cap': 'unknown'}


def test_conflict_evidence_contradicts_unmet_changes_and_leaves_met_ones_met():
    bnd = obs('b1:INT', level='weak')
    cosmetic, unchanged = obs('cf:cosmetic', 'conflict'), obs('cf:unchanged', 'conflict')
    result = ev.evaluate_rule(synthetic(), [bnd, unchanged, cosmetic], AVAILABLE, ())
    assert states(result) == {'guard': 'met', 'api': 'contradicted', 'cap': 'contradicted'}
    assert result.conflict_ids == obs_ids(cosmetic, unchanged)
    assert result.changes[1].observation_ids == obs_ids(cosmetic, unchanged)
    assert result.changes[0].observation_ids == (bnd.obs_id,)


def test_a_conflict_beats_unknown_but_never_a_met_change():
    proof = obs('cf:cosmetic', 'conflict')
    degraded = {'code': 'failed', 'calls': 'not-run', 'capa': 'not-run'}
    assert set(states(ev.evaluate_rule(synthetic(), [proof], degraded, ())).values()) == {'contradicted'}


@pytest.mark.parametrize('role', ['shape', 'local', 'counter', 'context'])
def test_only_conflict_role_evidence_counts_as_a_conflict(role):
    result = ev.evaluate_rule(synthetic(), [obs('cf:cosmetic', role)], AVAILABLE, ())
    assert result.conflict_ids == () and set(states(result).values()) == {'not-observed'}


def test_a_rule_without_a_matching_conflict_leaf_ignores_conflict_evidence():
    lone = rule(change('guard', 'cf:comparison'), counters=('cf:unchanged',))
    result = ev.evaluate_rule(lone, [obs('cf:cosmetic', 'conflict')], AVAILABLE, ())
    assert result.conflict_ids == () and result.changes[0].state == 'not-observed'


# --- properties -----------------------------------------------------------------------------------------------------

KINDS = ('b1:BND', 'b1:INT', 'b1:OVF', 'b1:VAL', 'b1:ERR', 'b1:SIZE', 'b1:SCRUB', 'cf:comparison', 'cf:condition',
         'cf:constant', 'cf:callee', 'cf:string', 'cf:cosmetic', 'cf:unchanged', 'call:added', 'call:removed',
         'capa:added', 'str:added', 'die:toolchain-changed')
SUBJECTS = (None, 'memcpy', 'RtlSizeTAdd', 'ObDereferenceObject', 'KERNEL32.dll!CreateFileW',
            'host-interaction/process/create')
HINTS = ('memcpy', 'RtlSizeTAdd', 'CreateFileW', 'ObDereferenceObject')
EVIDENCE = st.builds(ev.Evidence, obs_id=st.integers(0, 30).map(oid), kind=st.sampled_from(KINDS),
                     role=st.sampled_from(get_args(Role)), level=st.sampled_from((None, 'weak', 'moderate', 'strong')),
                     subject=st.sampled_from(SUBJECTS))
CHANNEL_STATES = st.fixed_dictionaries({name: st.sampled_from(get_args(ChannelState))
                                        for name in ('code', 'calls', 'capa', 'strings')})
ROWS = st.sampled_from(data.RULES)


@PROPS
@given(ROWS, st.lists(EVIDENCE, max_size=12), CHANNEL_STATES, st.randoms(use_true_random=False))
def test_evaluation_ignores_order_and_duplicates(row, evidence, channels, rnd):
    shuffled = [*evidence, *evidence]
    rnd.shuffle(shuffled)
    assert ev.evaluate_rule(row, shuffled, channels, HINTS) == ev.evaluate_rule(row, evidence, channels, HINTS)


@PROPS
@given(ROWS, st.lists(EVIDENCE, max_size=10), st.lists(EVIDENCE, max_size=10), CHANNEL_STATES)
def test_more_evidence_never_removes_a_met_change(row, first, extra, channels):
    def met(evidence):
        result = ev.evaluate_rule(row, evidence, channels, HINTS)
        return {c.id: set(c.observation_ids) for c in result.changes if c.state == 'met'}
    before, after = met(first), met([*first, *extra])
    assert before.keys() <= after.keys() and all(before[key] <= after[key] for key in before)


@PROPS
@given(ROWS, st.lists(EVIDENCE, max_size=12), CHANNEL_STATES)
def test_unknown_is_never_reported_as_not_observed_and_ids_come_from_the_input(row, evidence, channels):
    result = ev.evaluate_rule(row, evidence, channels, HINTS)
    shape = {e.obs_id for e in evidence if e.role == 'shape'}
    conflicts = {e.obs_id for e in evidence if e.role == 'conflict'}
    assert set(result.conflict_ids) <= conflicts and list(result.conflict_ids) == sorted(result.conflict_ids)
    for spec, outcome in zip(row.changes, result.changes, strict=True):
        assert (outcome.id, outcome.required, outcome.teach_id) == (spec.id, spec.required, spec.teach_id)
        complete = all(channels[name] == 'available' for name in spec.channels)
        if outcome.state == 'not-observed':
            assert complete and not result.conflict_ids and not outcome.observation_ids
        elif outcome.state == 'unknown':
            assert not complete and not result.conflict_ids and not outcome.observation_ids
        elif outcome.state == 'contradicted':
            assert outcome.observation_ids == result.conflict_ids
        else:
            assert outcome.state == 'met' and set(outcome.observation_ids) <= shape


# --- purity ---------------------------------------------------------------------------------------------------------

MODULES = ('contracts', 'data', 'evaluate')
RUNTIME_ALLOWED = {
    'contracts': {'pydantic', 'patchtrace.enrichment.identity', 'patchtrace.pilot.contracts',
                  'patchtrace.pilot.limits'},
    'data': {'patchtrace.pilot.rules.contracts'},
    'evaluate': {'patchtrace.pilot.contracts', 'patchtrace.pilot.rules.contracts'},
}
STDLIB = {'__future__', 'collections', 'collections.abc', 'dataclasses', 'functools', 'hashlib', 'json', 're', 'types',
          'typing'}


def _runtime_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding='utf-8'))
    guarded = set()
    for node in ast.walk(tree):  # imports under `if TYPE_CHECKING:` are annotations only
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING':
            guarded |= {id(n) for n in ast.walk(node)}
    found = set()
    for node in ast.walk(tree):
        if id(node) in guarded:
            continue
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            name = '.' * node.level + (node.module or '')
            found.add(importlib.util.resolve_name(name, 'patchtrace.pilot.rules') if node.level else name)
    return found


@pytest.mark.parametrize('module', MODULES, ids=MODULES)
def test_rule_modules_respect_the_import_rules(module):
    assert _runtime_imports(PACKAGE / f'{module}.py') - STDLIB <= RUNTIME_ALLOWED[module]


def test_init_is_documentation_only():
    tree = ast.parse((PACKAGE / '__init__.py').read_text(encoding='utf-8'))
    assert all(isinstance(n, ast.Expr) for n in tree.body)  # a docstring and nothing that runs


def test_rule_package_imports_no_qt_sqlite_network_process_or_other_feature():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.pilot.rules, patchtrace.pilot.rules.contracts, patchtrace.pilot.rules.data\n'
            'import patchtrace.pilot.rules.evaluate\n'
            'bad = [m for m in ("PySide6", "sqlite3", "subprocess", "ssl", "urllib.request", "http.client",\n'
            '                   "patchtrace.intelligence", "patchtrace.unified", "patchtrace.secondary",\n'
            '                   "patchtrace.enrichment.signals", "patchtrace.enrichment.cve",\n'
            '                   "patchtrace.enrichment.storage", "patchtrace.persistence") if m in sys.modules]\n'
            'print(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
