"""PIL-B2 properties of the whole engine on random scenarios (docs/specs/program-e/PIL-integration-plan.md s6, s10): the
result does not depend on the order or repetition of its inputs, removing support never raises a class, adding doubt never
raises one, unknown never becomes "not seen", ties tile the ranks, the `strong` mechanism and floats never appear, and the
result survives a canonical JSON round trip and a change of hash seed. Also: cancel, deadline, limits and the 5 s target.
Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pilot_localize_support import (
    CVE_A,
    CVE_B,
    advisory_entry,
    anchor,
    build,
    call,
    candidate,
    context,
    hypothesis,
    observation,
    run,
)

from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, service
from patchtrace.pilot.limits import DEFAULT_LIMITS, Budget, PilotError
from patchtrace.pilot.rules import data as rules

ROOT = Path(__file__).resolve().parents[1]


def fixed_clock() -> datetime:
    return datetime(2099, 1, 1, tzinfo=UTC)  # a fixed clock keeps `created_utc` out of the comparisons


PROPS = settings(deadline=None, max_examples=60, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
COMPONENT = [anchor('component', 'SYNTHETIC Example Net IPv6 Fragment Reassembly'),
             anchor('module', 'examplenet.sys'), anchor('feature', 'IPv6')]
NAMES = ('ReassembleFragment', 'ParseOptions', 'FragmentInit', 'Dispatch', 'FragmentReassembleTail')
HYPOTHESES = (hypothesis('R-MEMORY-WRITE', 'CWE-787'), hypothesis('R-INPUT', 'CWE-20', 'cwe-id-in-text'),
              hypothesis('R-LIFETIME', 'CWE-416'), hypothesis('R-POINTER', 'CWE-822'),
              hypothesis('R-INTEGER', 'CWE-190', 'curated-vocabulary'))
# What the generator may attach to a candidate. Every observation has a single origin, which is what the adapters emit.
SUPPORT = {  # shape evidence: removing it must never raise a class
    'bnd': lambda r: observation('b1:BND', ref=r, line=3), 'size': lambda r: observation('b1:SIZE', ref=r, line=4),
    'ovf': lambda r: observation('b1:OVF', ref=r, line=5), 'cmp': lambda r: observation('cf:comparison', ref=r, line=6),
    'cond': lambda r: observation('cf:condition', ref=r, line=7),
    'label': lambda r: call('RtlSizeTAdd'), 'probe': lambda r: call('ProbeForRead'),
    'import': lambda r: call('RtlSizeTAdd', verification='verified-bytes', origins=('D_pe_tables',)),
    'review': lambda r: observation('cf:comparison', ref=r, line=8, obligations=['second-channel'])}
DOUBT = {  # counter evidence and build facts: adding it must never raise a class
    'proof': lambda r: observation('cf:cosmetic', role='conflict', ref=r), 'flag': lambda r: observation(
        'die:toolchain-changed', role='context', ref=r), 'packed': lambda r: observation(
        'die:packed', role='context', ref=r),
    'noise': lambda r: observation('cf:register-only', role='context', ref=r)}
CONTEXT = {  # context that says a function changed or was seen, never shape evidence
    'callee': lambda r: observation('cf:callee', role='context', ref=r),
    'string': lambda r: observation('cf:string', role='context', ref=r),
    'floss': lambda r: observation('str:added', role='context', ref=r),
    'capa': lambda r: observation('capa:added', role='context', ref=r)}
CATALOGUE = {**SUPPORT, **DOUBT, **CONTEXT}


@dataclasses.dataclass(frozen=True)
class Case:
    names: tuple[str, ...]
    identities: tuple[str, ...]
    evidence: tuple[tuple[int, str, int], ...]  # (candidate index, catalogue key, variant)
    hypotheses: tuple[int, ...]
    gate: str
    window: str
    states: dict


@st.composite
def cases(draw):
    n = draw(st.integers(1, 5))
    evidence = draw(st.lists(st.tuples(st.integers(0, n - 1), st.sampled_from(sorted(CATALOGUE)), st.integers(0, 1)),
                             unique=True, max_size=14))
    states = {
        'code': draw(st.sampled_from(['available', 'partial', 'not-run', 'failed'])),
        'calls': draw(st.sampled_from(['available', 'partial', 'not-run', 'stale'])),
        'capa': draw(st.sampled_from(['available', 'not-run'])),
        'strings': draw(st.sampled_from(['available', 'not-run'])),
        'build_state': draw(st.sampled_from(['available', 'not-run']))}
    return Case(
        names=tuple(draw(st.lists(st.sampled_from(NAMES), min_size=n, max_size=n))),
        identities=tuple(draw(st.lists(st.sampled_from(['corroborated', 'contested', 'unassessed']), min_size=n,
                                       max_size=n))),
        evidence=tuple(evidence), hypotheses=tuple(draw(st.lists(st.integers(0, len(HYPOTHESES) - 1), unique=True,
                                                                 max_size=3))),
        gate=draw(st.sampled_from(['applies', 'asserted', 'unverified', 'conflict', 'not-applicable'])),
        window=draw(st.sampled_from(['yes', 'no', 'unknown'])), states=states)


def inputs_of(case: Case, *, evidence=None, order=None, repeat=False):
    """The case as a `LocalizeInputs`; `order` permutes the candidates, `repeat` lists every observation twice."""
    cands = [candidate(i, name, identity=identity)
             for i, (name, identity) in enumerate(zip(case.names, case.identities, strict=True))]
    pairs = [(cands[i], CATALOGUE[key](f'{i}-{key}-{variant}')) for i, key, variant in (evidence or case.evidence)]
    pairs = pairs * 2 if repeat else pairs
    universe = cands if order is None else [cands[i] for i in order]
    contexts = [context(CVE_A, gate=case.gate, window=case.window, window_cves=(CVE_A, CVE_B))]
    return build(universe, pairs, cves={CVE_A: tuple(HYPOTHESES[i] for i in case.hypotheses)}, contexts=contexts,
                 anchors=COMPONENT, entries={CVE_A: (advisory_entry(),)}, **case.states)


def go(inputs):
    return run(inputs, clock=fixed_clock)


def classes(assessment: c.PilotAssessment) -> dict:
    return {(lead.cve, lead.candidate_key): c.CLASS_RANK[lead.lead_class] for lead in assessment.leads}


# --- the result depends on what is known, not on how it arrived -------------------------------------------------------------------

@given(cases())
@PROPS
def test_localization_is_idempotent_and_ignores_the_clock(case):
    first = go(inputs_of(case))
    again = go(inputs_of(case))
    later = run(inputs_of(case), clock=lambda: datetime(2100, 6, 1, tzinfo=UTC))
    assert first == again
    assert later.model_copy(update={'created_utc': first.created_utc}) == first and later.result_id == first.result_id


@given(cases(), st.randoms(use_true_random=False))
@PROPS
def test_the_order_of_candidates_and_observations_does_not_matter(case, rng):
    order = list(range(len(case.names)))
    rng.shuffle(order)
    shuffled = list(case.evidence)
    rng.shuffle(shuffled)
    assert go(inputs_of(case)) == go(inputs_of(case, evidence=tuple(shuffled), order=order))


@given(cases())
@PROPS
def test_listing_an_observation_twice_changes_nothing(case):
    assert go(inputs_of(case)) == go(inputs_of(case, repeat=True))


# --- monotone: support raises, doubt lowers ---------------------------------------------------------------------------------------

@given(cases(), st.data())
@PROPS
def test_removing_support_never_raises_a_class(case, data):
    support = [e for e in case.evidence if e[1] in SUPPORT]
    dropped = set(data.draw(st.lists(st.sampled_from(support), unique=True))) if support else set()
    before = classes(go(inputs_of(case)))
    after = classes(go(inputs_of(case, evidence=tuple(e for e in case.evidence if e not in dropped))))
    assert before.keys() == after.keys()
    assert all(after[k] >= before[k] for k in before), {k: (before[k], after[k]) for k in before if after[k] < before[k]}


@given(cases(), st.data())
@PROPS
def test_adding_doubt_never_raises_a_class(case, data):
    index = data.draw(st.integers(0, len(case.names) - 1))
    key = data.draw(st.sampled_from(sorted(DOUBT)))
    extra = (index, key, 9)
    before = classes(go(inputs_of(case)))
    after = classes(go(inputs_of(case, evidence=(*case.evidence, extra))))
    assert all(after[k] >= before[k] for k in before)


# --- unknown stays unknown ------------------------------------------------------------------------------------------------------------

@given(cases())
@PROPS
def test_a_change_is_not_seen_only_where_every_channel_it_reads_is_complete(case):
    assessment = go(inputs_of(case))
    available = {x.channel for x in assessment.channels if x.state == 'available'}
    pairs = {lead.candidate_key: len(lead.older) == len(lead.newer) == 1 for lead in assessment.leads}
    for lead in assessment.leads:
        for fit in lead.fits:
            rule = rules.find_rule(fit.rule_id, fit.rule_revision)
            for change in fit.expected_changes:
                reads = next(spec for spec in rule.changes if spec.id == change.id).channels
                complete = pairs[lead.candidate_key] and set(reads) <= available
                if change.state == 'not-observed':
                    assert complete, (lead.cve, change.id)
                if change.state == 'unknown':
                    assert not complete, (lead.cve, change.id)


# --- what every result is --------------------------------------------------------------------------------------------------------------

def walk(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


@given(cases())
@PROPS
def test_every_result_is_certified_float_free_and_never_strong(case):
    assessment = go(inputs_of(case))
    keys.verify_assessment(assessment)
    dumped = assessment.model_dump(mode='json')
    assert not [x for x in walk(dumped) if isinstance(x, float)]
    assert 'strong' not in {lead.mechanism for lead in assessment.leads}
    assert assessment.status in ('complete', 'partial') and bool(assessment.limitations) == (assessment.status != 'complete')
    again = c.PilotAssessment.model_validate_json(keys.canonical_bytes(assessment))
    assert again == assessment and keys.canonical_bytes(again) == keys.canonical_bytes(assessment)


@given(cases())
@PROPS
def test_ranks_tile_each_context_and_ties_are_the_equal_evidence_groups(case):
    assessment = go(inputs_of(case))
    for cve in {lead.cve for lead in assessment.leads}:
        leads = sorted((x for x in assessment.leads if x.cve == cve), key=lambda x: x.rank)
        assert [x.rank for x in leads] == list(range(1, len(leads) + 1))  # nothing is cut at this size
        for _, group in itertools.groupby(leads, key=lambda x: x.tie):
            members = list(group)
            assert [x.rank for x in members] == list(range(members[0].tie.first, members[0].tie.last + 1))
            assert members[0].tie.size == len(members)
            if cve is None:
                assert len({x.lead_class for x in members}) == 1
            else:  # what the order key reads is equal inside a tie group
                assert len({(x.lead_class, x.mechanism, x.identity == 'contested', x.local_hits, x.components.count)
                            for x in members}) == 1


# --- control: cancel, deadline, limits, hash seed ----------------------------------------------------------------------------------------

def tiny():
    cand = candidate(1, 'Handler')
    return cand, build([cand], [(cand, observation('b1:BND', ref='x', line=1))], cves={CVE_A: (hypothesis(),)})


def test_a_cancel_set_before_the_run_is_honoured_at_once():
    _, inputs = tiny()
    event = threading.Event()
    event.set()
    with pytest.raises(PilotError) as raised:
        run(inputs, cancel=event)
    assert (raised.value.code, raised.value.exit_code) == ('PT-PILOT-CANCEL', 5)


class Cancelling:
    """A pairing port that cancels the run while it is being read."""

    def __init__(self, inner, event):
        self._inner, self._event = inner, event

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def candidates(self):
        for item in self._inner.candidates():
            self._event.set()
            yield item


@pytest.mark.parametrize('where', ['pairing', 'changes'], ids=['while-reading-the-universe', 'while-reading-evidence'])
def test_a_cancel_during_the_run_is_honoured(where):
    _, inputs = tiny()
    event = threading.Event()
    if where == 'pairing':
        inputs = dataclasses.replace(inputs, pairing=Cancelling(inputs.pairing, event))
    else:
        class Late(type(inputs.changes)):
            def observations(self, candidate_keys):
                event.set()
                return super().observations(candidate_keys)
        inputs = dataclasses.replace(inputs, changes=Late(inputs.changes.status(), inputs.changes._pairs))  # noqa: SLF001
    with pytest.raises(PilotError) as raised:
        run(inputs, cancel=event)
    assert raised.value.code == 'PT-PILOT-CANCEL'


def test_the_deadline_stops_a_run_with_a_limit_error(monkeypatch):
    ticks = itertools.count(0, 50)

    class Hurried(Budget):
        @classmethod
        def after(cls, seconds, cancel=None, *, check_every=4096, clock=None):
            return super().after(seconds, cancel, check_every=check_every, clock=lambda: next(ticks))

    monkeypatch.setattr(service, 'Budget', Hurried)
    _, inputs = tiny()
    with pytest.raises(PilotError) as raised:
        run(inputs)
    assert (raised.value.code, raised.value.reason) == ('PT-PILOT-LIMIT', 'deadline')


def test_the_candidate_and_cve_limits_are_enforced(monkeypatch):
    limits = dataclasses.replace(DEFAULT_LIMITS, p01_candidates=3, p03_cves=1)
    monkeypatch.setattr(service, '_LIMITS', limits)
    config = keys.default_config(limits)
    many = [candidate(i) for i in range(4)]
    with pytest.raises(PilotError) as raised:
        run(build(many), config)
    assert (raised.value.code, raised.value.reason) == ('PT-PILOT-LIMIT', 'candidates')
    two = build(many[:2], cves={CVE_A: (hypothesis(),), CVE_B: (hypothesis(cve=CVE_B),)})
    with pytest.raises(PilotError) as cves:
        run(two, config)
    assert (cves.value.code, cves.value.reason) == ('PT-PILOT-LIMIT', 'cves')
    assert run(build(many[:3], cves={CVE_A: (hypothesis(),)}), config).status == 'complete'


def test_the_result_is_stable_across_hash_seeds():
    script = (
        "import sys, threading, hashlib\n"
        "from datetime import UTC, datetime\n"
        "from pilot_synergy_support import arms, sources_for\n"
        "from patchtrace.pilot import keys, service\n"
        "digest = hashlib.sha256()\n"
        "for arm in sorted(arms()):\n"
        "    a = service.localize(sources_for(arms()[arm]), keys.default_config(), threading.Event(),\n"
        "                         clock=lambda: datetime(2099, 1, 1, tzinfo=UTC))\n"
        "    digest.update(keys.canonical_bytes(a))\n"
        "print(digest.hexdigest())\n")
    found = set()
    for seed in ('1', '2'):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=os.pathsep.join([str(ROOT / 'src'), str(ROOT / 'tests')]),
                   PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, env=env, cwd=ROOT,
                                check=False)
        assert result.returncode == 0, result.stderr
        found.add(result.stdout.strip())
    assert len(found) == 1 and len(next(iter(found))) == 64


# --- the 5 s target -----------------------------------------------------------------------------------------------------------------------------

def test_5000_pairs_by_8_cves_localize_within_the_5_second_target():
    """Plan s7 target: 5,000 pairs x 8 CVEs in 5 s. Every pair carries evidence and every CVE two hypotheses, so this is
    heavier than a real diff; CPU time is measured, which a busy machine does not stretch."""
    rule_ids = ('R-MEMORY-WRITE', 'R-MEMORY-READ', 'R-BOUNDS', 'R-INTEGER', 'R-LIFETIME', 'R-NULL-DEREF', 'R-RACE',
                'R-INPUT')
    cands = [candidate(i, name=f'Ipv6pFunc{i % 97}Handler{i % 13}') for i in range(5000)]
    evidence = []
    for i, cand in enumerate(cands):
        evidence += [(cand, observation('b1:BND' if i % 2 else 'b1:SIZE', ref=str(i), line=5)),
                     (cand, observation('cf:comparison', ref=str(i), line=5)), (cand, call(f'Api{i}')),
                     (cand, observation('cf:string', role='context', ref=str(i)))]
    cves = {f'CVE-2099-5{k:04d}': (hypothesis(rule_ids[k], 'CWE-787', cve=f'CVE-2099-5{k:04d}'),
                                   hypothesis(rule_ids[(k + 3) % 8], 'CWE-122', 'curated-vocabulary',
                                              cve=f'CVE-2099-5{k:04d}')) for k in range(8)}
    window = tuple(sorted(cves))
    inputs = build(cands, evidence, cves=cves, anchors=COMPONENT, entries={cve: (advisory_entry(cve),) for cve in cves},
                   contexts=[context(cve, window='yes', window_cves=window) for cve in cves])
    started = time.process_time()
    assessment = run(inputs)
    elapsed = time.process_time() - started
    assert elapsed <= 5.0, f'{elapsed:.2f} s of CPU'
    assert len(assessment.cves) == 8 and assessment.status == 'partial' and assessment.limits_hit
    assert hashlib.sha256(keys.canonical_bytes(assessment)).hexdigest()  # and it serializes
    assert json.loads(keys.canonical_bytes(assessment))['contract'] == 'pilot/1'
