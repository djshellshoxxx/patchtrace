"""PIL-B2 tiers, order and explanation: the tier derivation over its whole fact space, the integer order key and its tie
groups, the P-04 cut, and the plain-text "why this function" (docs/specs/program-e/PIL-integration-plan.md s6, s7, s8).

The derivation is a pure function of ten flags, a gate and an identity, so it is checked exhaustively: every combination
yields an assignable mechanism (never `strong`), and every flag is monotone (more support never lowers a tier, more doubt
never raises one). Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import ast
import dataclasses
import itertools
import re
from pathlib import Path
from typing import get_args

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pilot_localize_support import (
    CVE_A,
    build,
    candidate,
    hypothesis,
    leads_of,
    observation,
    order_of,
    run,
)
from pilot_synergy_support import arms, expected, lead_map, run_arm
from pydantic import TypeAdapter

from patchtrace.pilot import contracts as c
from patchtrace.pilot import ranking, tiers, why
from patchtrace.pilot.quality import NUISANCE_CLASSES, NUISANCE_FLAGS, QUALITY_FLAGS, UNASSESSED_CAPA
from patchtrace.pilot.rules import data as rules
from patchtrace.pilot.sources import tools, unified
from patchtrace.unified import contracts as spec31

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'src' / 'patchtrace' / 'pilot'
ENGINE = ('fusion', 'quality', 'ranking', 'service', 'tiers', 'why')
PROPS = settings(deadline=None, max_examples=60, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
GATES = ('applies', 'asserted', 'unverified', 'conflict', 'none')
IDENTITIES = ('corroborated', 'contested', 'unassessed')
GOOD = ('eligible', 'met_any', 'change', 'local', 'typed', 'material', 'lexical_moderate')  # more support
BAD = ('conflict', 'confounded', 'toolchain')  # more doubt
FLAGS = (*GOOD, *BAD)
ORDER = ranking.MECHANISM_INDEX


def all_facts():
    for gate, identity, bits in itertools.product(GATES, IDENTITIES, itertools.product((False, True), repeat=len(FLAGS))):
        yield tiers.TierFacts(gate=gate, identity=identity, **dict(zip(FLAGS, bits, strict=True)))


# --- the tier derivation, over its whole fact space ----------------------------------------------------------------------------

def test_strong_is_unreachable():
    """The mechanism `strong` needs a typed dominance or dataflow channel that PatchTrace does not have."""
    assert c.STRONG_REACHABLE is False and 'strong' not in c.ASSIGNABLE_MECHANISMS
    seen = {tiers.derive(f).mechanism for f in all_facts()}
    assert seen == set(c.ASSIGNABLE_MECHANISMS) and 'strong' not in seen
    with pytest.raises(ValueError, match='strong'):
        c.Lead.model_validate({'mechanism': 'strong'})  # the contract refuses it before anything else


def test_every_flag_is_monotone():
    for facts in all_facts():
        base = ORDER[tiers.derive(facts).mechanism]
        for flag in GOOD:
            if not getattr(facts, flag):
                better = ORDER[tiers.derive(dataclasses.replace(facts, **{flag: True})).mechanism]
                assert better <= base, (flag, facts)
        for flag in BAD:
            if not getattr(facts, flag):
                worse = ORDER[tiers.derive(dataclasses.replace(facts, **{flag: True})).mechanism]
                assert worse >= base, (flag, facts)
        if facts.gate != 'none':
            assert ORDER[tiers.derive(dataclasses.replace(facts, identity='contested')).mechanism] >= base
            for gate in ('unverified', 'conflict'):
                assert ORDER[tiers.derive(dataclasses.replace(facts, gate=gate)).mechanism] >= ORDER[
                    tiers.derive(dataclasses.replace(facts, gate='applies')).mechanism]


def test_an_analyst_assertion_acts_exactly_like_an_applicable_advisory():
    for facts in all_facts():
        if facts.gate == 'applies':
            assert tiers.derive(dataclasses.replace(facts, gate='asserted')) == tiers.derive(facts)


def test_the_derived_caps_agree_with_the_contract():
    for facts in all_facts():
        tier = tiers.derive(facts)
        cls = tiers.lead_class(tier.mechanism, facts.gate, facts.change)
        assert tier.mechanism in c.CLASS_MECHANISMS[cls], facts
        assert (cls in ('code',)) <= (facts.gate == 'none') and (facts.gate == 'none') <= (cls in ('code', 'queue'))
        assert list(tier.caps) == sorted(set(tier.caps))
        if tiers.WINDOW_CAP in tier.caps or tiers.TOOLCHAIN_CAP in tier.caps:
            assert tier.mechanism == 'tentative' and cls == 'partial'
        if tiers.UNVERIFIED_CAP in tier.caps:
            assert facts.gate == 'unverified' and cls == 'partial'
        if tiers.CONFLICT_CAP in tier.caps:
            assert facts.gate == 'conflict' and cls == 'review'
        if cls == 'fit':
            assert facts.eligible and facts.identity != 'contested' and facts.gate in ('applies', 'asserted')
            assert not (facts.conflict or facts.confounded and not facts.local or facts.toolchain and not facts.material)


def test_no_advisory_means_nothing_is_assessed():
    for facts in all_facts():
        if facts.gate == 'none':
            assert tiers.derive(facts) == tiers.Tier('not-assessed', ())
            assert tiers.lead_class('not-assessed', 'none', facts.change) == ('code' if facts.change else 'queue')


# --- no averaging, no weights, no floats -----------------------------------------------------------------------------------------

@pytest.mark.parametrize('module', ENGINE)
def test_the_engine_has_no_float_division_or_rounding(module):
    tree = ast.parse((PACKAGE / f'{module}.py').read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        assert not (isinstance(node, ast.Constant) and isinstance(node.value, float)), (module, node.lineno)
        assert not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)), (module, node.lineno)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ('float', 'round', 'mean', 'average'), (module, node.lineno)
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [a.name for a in node.names] + [getattr(node, 'module', None) or '']
            assert not {'math', 'statistics', 'numpy', 'fractions', 'decimal'} & {n.split('.')[0] for n in names}


def test_order_keys_are_tuples_of_integers():
    key = ranking.advisory_key(lead_class='partial', mechanism='tentative', contested=True, met=2, components=3,
                               basis=1, local_hits=2, anchored=False, severity=4, nuisance=1)
    code = ranking.code_key(lead_class='code', severity=3, shape_kinds=2, anchored=True, nuisance=0)
    for item in (key, code):
        assert isinstance(item, tuple) and all(type(x) is int for x in item)
    assert key == (2, 2, 1, -2, -3, 1, -2, 1, 4, 1) and code == (3, 3, -2, 0, 0)


BASE = dict(lead_class='partial', mechanism='tentative', contested=False, met=1, components=2, basis=0, local_hits=0,
            anchored=True, severity=ranking.NO_SEVERITY, nuisance=0)


@pytest.mark.parametrize(('better', 'worse'), [
    ({'lead_class': 'fit', 'mechanism': 'moderate'}, {}),
    ({'lead_class': 'review', 'mechanism': 'contested'}, {}),
    ({}, {'lead_class': 'queue', 'mechanism': 'unexplained'}),
    ({'lead_class': 'queue', 'mechanism': 'unexplained'}, {'lead_class': 'queue', 'mechanism': 'not-assessed'}),
    ({}, {'contested': True}), ({'met': 2}, {}), ({'components': 3}, {}), ({}, {'basis': 1}),
    ({'basis': 1}, {'basis': 2}), ({'local_hits': 2}, {}), ({}, {'anchored': False}), ({'severity': 0}, {}),
    ({'severity': 0}, {'severity': 1}), ({}, {'nuisance': 1})],
    ids=['fit', 'review', 'queue', 'unexplained', 'contested-last', 'met', 'components', 'basis', 'vocabulary',
         'locality', 'anchor', 'severity', 'callee-first', 'nuisance'])
def test_the_advisory_key_orders_by_the_plan(better, worse):
    assert ranking.advisory_key(**{**BASE, **better}) < ranking.advisory_key(**{**BASE, **worse})


def test_earlier_elements_outweigh_later_ones():
    """Lexicographic: no amount of a later element makes up for an earlier one (nothing is summed)."""
    many = dict(met=9, components=9, local_hits=9, severity=0)
    assert ranking.advisory_key(**{**BASE, 'lead_class': 'queue', 'mechanism': 'unexplained', **many}) > \
        ranking.advisory_key(**{**BASE, 'met': 0, 'components': 0, 'nuisance': 99})
    assert ranking.advisory_key(**{**BASE, 'contested': True, **many}) > ranking.advisory_key(**BASE)


def test_the_code_key_orders_by_severity_then_distinct_kinds():
    base = dict(lead_class='code', severity=1, shape_kinds=1, anchored=True, nuisance=0)
    assert ranking.code_key(**{**base, 'severity': 0}) < ranking.code_key(**base)
    assert ranking.code_key(**{**base, 'shape_kinds': 2}) < ranking.code_key(**base)
    assert ranking.code_key(**base) < ranking.code_key(**{**base, 'anchored': False}) < ranking.code_key(
        **{**base, 'anchored': False, 'nuisance': 1})
    assert ranking.code_key(**{**base, 'lead_class': 'queue', 'severity': 0}) > ranking.code_key(**{**base, 'severity': 9})


# --- SPEC-31 severity order and the vocabularies mirrored from the adapters ---------------------------------------------------------

def spec31_order() -> dict[str, int]:
    text = (ROOT / 'docs/specs/unified-engine/05-fusion-and-noise.md').read_text(encoding='utf-8')
    line = next(x for x in text.splitlines() if x.startswith('Severity order:'))
    classes = set(get_args(spec31.ChangeClass))
    rank: dict[str, int] = {}
    groups = line.removeprefix('Severity order:').rstrip('.').replace('block-added/removed', 'block-added block-removed')
    for index, group in enumerate(groups.split(' > ')):
        for name in re.findall(r'[a-z]+(?:-[a-z]+)*', group):
            if name in classes:
                rank.setdefault(name, index)  # `constant` appears twice: the first (compare context) position wins
    return rank


def test_the_severity_table_follows_spec_31_05_s2_6():
    doc = spec31_order()
    assert set(doc) | {'unknown', 'layout-only'} == set(get_args(spec31.ChangeClass))  # the document names the rest
    for first, second in itertools.permutations(doc, 2):
        assert (doc[first] < doc[second]) == (ranking.severity_of(first) < ranking.severity_of(second)), (first, second)
    unranked = {name for name in get_args(spec31.ChangeClass) if ranking.severity_of(name) == ranking.NO_SEVERITY}
    assert unranked == {'unknown', 'layout-only'}  # the document names neither; they rank last


def test_the_severity_of_a_candidate_is_its_most_severe_change_and_a_proof_is_not_one():
    proof = observation('cf:cosmetic', role='conflict', ref='p')
    edits = [observation('cf:string', role='context', ref='s'), observation('cf:callee', role='context', ref='c')]
    assert ranking.severity([proof]) == ranking.NO_SEVERITY
    assert ranking.severity([*edits, proof]) == ranking.severity_of('callee') == 0
    assert ranking.severity([observation('b1:BND', ref='b'), observation('call:added', ref='x')]) == ranking.NO_SEVERITY


def test_the_mirrored_vocabularies_equal_the_adapters():
    assert NUISANCE_CLASSES == set(unified.NUISANCE_CLASSES) and NUISANCE_FLAGS == set(unified.NUISANCE_FLAGS)
    assert QUALITY_FLAGS == set(unified.QUALITY_FLAGS)
    # every flag the unified adapter can turn into a `pair:` observation is either a nuisance or a quality flag
    assert set(unified.NUISANCE_FLAGS) | set(unified.QUALITY_FLAGS) == NUISANCE_FLAGS | QUALITY_FLAGS
    assert UNASSESSED_CAPA == {'limitation', 'recovery-shift', 'unlocalized-added', 'unlocalized-removed'}
    assert set(tools._CAPA_FLAGS.values()) <= UNASSESSED_CAPA  # noqa: SLF001 - pins the T adapter's flag names


# --- ties are explicit -----------------------------------------------------------------------------------------------------------

def test_equal_keys_share_a_tie_group_and_every_lead_has_its_own_position():
    rows = [((1, 0), 'd'), ((0, 5), 'z'), ((1, 0), 'a'), ((1, 0), 'c'), ((2, 0), 'b')]
    placed = ranking.place(rows)
    assert [(p.candidate_key, p.rank, p.first, p.last) for p in placed] == [
        ('z', 1, 1, 1), ('a', 2, 2, 4), ('c', 3, 2, 4), ('d', 4, 2, 4), ('b', 5, 5, 5)]  # inside a tie: candidate key


@given(st.lists(st.tuples(st.tuples(st.integers(0, 3), st.integers(0, 2)), st.text('abcdef', min_size=1, max_size=3)),
                unique_by=lambda row: row[1], max_size=25), st.randoms(use_true_random=False))
@PROPS
def test_placement_is_a_permutation_invariant_tiling(rows, rng):
    shuffled = list(rows)
    rng.shuffle(shuffled)
    placed = ranking.place(rows)
    assert placed == ranking.place(shuffled)
    assert [p.rank for p in placed] == list(range(1, len(rows) + 1))
    assert all(p.first <= p.rank <= p.last for p in placed)
    for first, last in {(p.first, p.last) for p in placed}:
        members = [p for p in placed if (p.first, p.last) == (first, last)]
        assert len({p.key for p in members}) == 1 and len(members) == last - first + 1
        assert [p.rank for p in members] == list(range(first, last + 1))


def test_leads_with_equal_evidence_tie_and_one_more_observation_splits_them():
    cands = [candidate(i, f'Func{i}') for i in range(1, 5)]
    evidence = [(cand, observation('b1:BND', ref=str(i), line=4)) for i, cand in enumerate(cands)]
    assessment = run(build(cands, evidence, cves={CVE_A: (hypothesis(),)}))
    leads = leads_of(assessment, CVE_A)
    assert {lead.tie for lead in leads.values()} == {c.Tie(size=4, first=1, last=4)}
    assert order_of(assessment, CVE_A) == sorted(order_of(assessment, CVE_A))  # the candidate key breaks the tie
    evidence.append((cands[0], observation('cf:comparison', ref='x', line=4)))
    split = leads_of(run(build(cands, evidence, cves={CVE_A: (hypothesis(),)})), CVE_A)
    assert split[cands[0].candidate_key].tie == c.Tie(size=1, first=1, last=1)
    assert {lead.tie for k, lead in split.items() if k != cands[0].candidate_key} == {c.Tie(size=3, first=2, last=4)}


def test_a_contested_pairing_sorts_after_a_corroborated_one_with_equal_evidence():
    first, second = candidate(1, 'Aa', identity='contested'), candidate(2, 'Bb', identity='corroborated')
    evidence = [(first, observation('b1:SIZE', ref='1', line=2)), (second, observation('b1:SIZE', ref='2', line=2))]
    assessment = run(build([first, second], evidence, cves={CVE_A: (hypothesis(),)}))
    assert order_of(assessment, CVE_A) == [second.candidate_key, first.candidate_key]
    assert order_of(assessment, None)[0] in (first.candidate_key, second.candidate_key)  # code only: identity is no key


def test_the_class_order_is_fit_review_partial_then_the_queue():
    assessment = run_arm('full')
    classes = [lead.lead_class for lead in sorted((x for x in assessment.leads if x.cve == 'CVE-2099-20001'),
                                                  key=lambda x: x.rank)]
    assert classes == ['fit', 'review', 'review', 'partial', 'partial', 'partial', 'queue', 'queue', 'queue']


# --- P-04: what a context keeps ----------------------------------------------------------------------------------------------------

def test_a_context_keeps_500_leads_and_200_queue_rows_and_counts_the_rest():
    changed = [candidate(i, f'Func{i}') for i in range(700)]
    quiet = [candidate(i, f'Idle{i}') for i in range(700, 1000)]
    evidence = [(cand, observation('b1:SIZE', ref=str(i), line=3)) for i, cand in enumerate(changed)]
    assessment = run(build([*changed, *quiet], evidence, cves={CVE_A: (hypothesis(),)}))
    kept = [lead for lead in assessment.leads if lead.cve == CVE_A]
    assert (sum(x.lead_class == 'partial' for x in kept), sum(x.lead_class == 'queue' for x in kept)) == (500, 200)
    (ctx,) = assessment.cves
    assert (ctx.counts.partial, ctx.counts.queue) == (700, 300)  # the context counts everything, the leads keep the top
    assert assessment.limits_hit == ('leads-cut', 'queue-cut') and assessment.status == 'partial'
    assert assessment.queue_count == 200  # 100 left out of the CVE context and 100 of the code-only one
    assert any(x.startswith('400 further leads') for x in assessment.limitations)  # 200 per context, two contexts
    assert any(x.startswith('200 changed functions with no fit') for x in assessment.limitations)
    assert [x.rank for x in kept] == sorted(x.rank for x in kept) and max(x.rank for x in kept) <= 1000
    assert kept[-1].tie.last >= kept[-1].rank  # a cut tie group keeps its true size
    c.PilotAssessment.model_validate_json(c.PilotAssessment.model_dump_json(assessment))


# --- why this function ---------------------------------------------------------------------------------------------------------------

def lines_of(arm, fid, cve='CVE-2099-20001'):
    assessment = run_arm(arm)
    return why.Explainer(assessment).explain(lead_map(assessment, cve)[fid])


def test_the_fit_is_explained_as_the_plan_shows():
    lines = lines_of('full', 'F1')
    text = '\n'.join(lines)
    assert lines[0] == 'Summary'
    assert '- fits advisory; expected changes seen 2 of 3 (required 1 of 1); 2 independent groups; evidence depth typed.' \
        in lines
    assert '- Seen: guard added (B1 BND, ChangeFacts comparison; go to newer line 14).' in lines
    assert '- Seen: checked arithmetic (RtlSizeTAdd call added, label only).' in lines
    assert '- Not seen: size recomputed.' in lines
    assert '- Ghidra-derived code: B1 BND, ChangeFacts comparison, RtlSizeTAdd call added, label only ' \
        '(same origin, counted once).' in lines
    assert '- Advisory text: CISA KEV, CSAF, MSRC, NVD (same origin, counted once).' in lines
    assert '- Partial fit for CVE-2099-20002.' in lines and '- None.' in lines
    assert 'Function name shares fragment, reassemble with the advisory component.' in text
    assert [x for x in lines if x in ('Summary', 'Expected changes', 'Independent evidence', 'Against', 'Unknown',
                                      'Alternatives', 'Pairing', 'Provenance', 'Limitations')] == [
        'Summary', 'Expected changes', 'Independent evidence', 'Against', 'Unknown', 'Alternatives', 'Pairing',
        'Provenance', 'Limitations']
    assert lines[-1] == '- ' + why.FOOTER


def test_the_explanation_states_the_facts_the_oracle_records_for_the_fit():
    """`expected.json` (PIL-T) holds the facts the plan's "why" text for F1 must state; the wording is B2's."""
    facts = expected()['why_f1']
    lines = lines_of('full', 'F1')
    summary = facts['summary']
    required = f'required {summary["required_seen"]} of {summary["required_total"]}'
    assert (f'- fits advisory; expected changes seen {summary["expected_changes_seen"]} of '
            f'{summary["expected_changes_total"]} ({required}); {summary["independent_groups"]} independent groups; '
            f'evidence depth {summary["depth"]}.') in lines
    labels = {'b1:BND': 'B1 BND', 'cf:comparison': 'ChangeFacts comparison'}
    for item in facts['expected_changes']:
        words = why.CHANGE_WORDS[item['id']]
        if item['state'] == 'met' and item['id'] == 'guard-added':
            where = f'go to {item["go_to"]["side"]} line {item["go_to"]["line"]}'
            assert f'- Seen: {words} ({", ".join(sorted(labels[k] for k in item["kinds"]))}; {where}).' in lines
        elif item['state'] == 'met':
            assert f'- Seen: {words} ({item["api"]} call added, label only).' in lines
            assert item['verification'] == 'label-only'
        else:
            assert f'- Not seen: {words}.' in lines
    sources = {'kev': 'CISA KEV', 'msrc': 'MSRC', 'nvd': 'NVD', 'stated': 'CSAF'}
    advisory = next(x for x in facts['independent_evidence'] if x['origin'] == 'D_vendor_text')
    assert f'- Advisory text: {", ".join(sorted(sources[s] for s in advisory["advisory_sources"]))} ' \
        '(same origin, counted once).' in lines
    assert any(x.startswith('- Ghidra-derived code: ') and x.endswith('(same origin, counted once).') for x in lines)
    window = facts['window']
    assert f'- The advisory lists {len(window["cves"])} CVEs fixed in this build. A change that fits the expected ' \
        'shape may belong to another CVE; only advisory-specific evidence can separate them.' in lines
    assert f'- Function name shares {", ".join(window["names_matched"])} with the advisory component.' in lines
    assert [f'- Partial fit for {x["cve"]}.' for x in facts['alternatives']] == [x for x in lines if 'Partial fit for' in x]
    assert facts['against'] == [] and '- None.' in lines


@pytest.mark.parametrize(('fid', 'cve', 'needle'), [
    ('F9', 'CVE-2099-20001', '- Needs review because a named proof argues against the change that was seen.'),
    ('F8', 'CVE-2099-20001', '- Needs review because the pairing of the two functions is contested.'),
    ('F6', 'CVE-2099-20001', '- Held at partial fit: the function name does not single this CVE out.'),
    ('F5', 'CVE-2099-20001', '- No expected change was seen; the function changed and its name matches the advisory.'),
    ('F4', 'CVE-2099-20001', '- Held at partial fit: a required change was not seen.'),
    ('F2', 'CVE-2099-20001', '- changed, no fit; expected changes seen 0 of 3 (required 0 of 1); 0 independent '
                             'groups; evidence depth none.')],
    ids=['proof', 'contested', 'window', 'locality', 'required-unmet', 'string'])
def test_every_class_says_why_it_is_not_a_fit(fid, cve, needle):
    assert needle in lines_of('full', fid, cve)


def test_ties_unknowns_and_next_steps_are_stated():
    lines = lines_of('adv', 'F1')
    assert '- Positions 1-3 are tied: equal evidence.' in lines
    assert f'- Next step: {why.NEXT_STEPS["pilot.state.tie"]}' in lines
    assert any(x.startswith('- Capa, Code, Strings') or 'not run' in x for x in lines)
    assert f'- Next step: {why.NEXT_STEPS["pilot.state.unknown-channel"]}' in lines
    code_only = lines_of('b1', 'F1', None)
    assert code_only[1].startswith('- code change; 1 independent group; evidence depth lexical.')
    assert 'Expected changes' not in code_only  # no advisory, no expected changes


def test_a_label_only_requirement_and_a_missing_second_source_are_named():
    pointer = (hypothesis('R-POINTER', 'CWE-822'),)
    cand = candidate(1, 'Handler')
    held = run(build([cand], [(cand, observation('cf:comparison', ref='c', line=3))], cves={CVE_A: pointer}))
    lead = leads_of(held, CVE_A)[cand.candidate_key]
    assert '- Held at partial fit: no second independent code source agrees, and this kind of change has no B1 detector.' \
        in why.explain(held, lead)
    integer = (hypothesis('R-INTEGER', 'CWE-190'),)
    labelled = run(build([cand], [(cand, observation('call:added', ref='RtlULongAdd', verification='label-only'))],
                         cves={CVE_A: integer}))
    lead = leads_of(labelled, CVE_A)[cand.candidate_key]
    assert '- Held at partial fit: a required change rests on call labels only.' in why.explain(labelled, lead)


def test_every_explanation_is_plain_bounded_and_free_of_the_swept_words():
    # stems match as prefixes, the rest as whole words ('provenance' is fine), as the repo's other sweeps do
    banned = re.compile(r'\b(?:probab|likelihood|confiden|percent|vulnerab|exploit|(?:proven|certain|verified|safe|secure)\b)',
                        re.I)
    sanctioned = (why.FOOTER, 'absence says nothing about exploitation', 'CISA KEV', 'analyst statement')
    total = 0
    for arm in arms():
        assessment = run_arm(arm)
        for lead in assessment.leads:
            lines = why.Explainer(assessment).explain(lead)
            assert 1 <= len(lines) <= 64
            for line in lines:
                total += 1
                assert len(line) <= 300 and c.plain_line(line) == line
                stripped = line
                for phrase in sanctioned:
                    stripped = stripped.replace(phrase, '')
                assert not banned.search(stripped), line
    assert total > 1000


def test_every_teach_hook_of_the_rule_table_and_the_states_has_a_next_step():
    taught = {change.teach_id for rule in rules.RULES for change in rule.changes}
    assert len(taught) == 13 and all(why.next_step(t) for t in taught)
    states = ('pilot.state.contested', 'pilot.state.unknown-channel', 'pilot.state.tie', 'pilot.state.confounded-window',
              'pilot.context.kev')
    assert all(why.next_step(t) for t in states) and why.next_step('pilot.change.unheard-of') is None
    assert {change.id for rule in rules.RULES for change in rule.changes} <= set(why.CHANGE_WORDS)
    assert all(TypeAdapter(c.TeachId).validate_python(t) == t for t in why.NEXT_STEPS)


def test_hostile_names_and_details_stay_plain_text():
    markup = '<img src=x onerror=alert(1)>'
    cand = candidate(1, markup)
    proof = observation('cf:cosmetic', role='conflict', ref='p', detail=f'{markup} [link](javascript:alert(1))')
    assessment = run(build([cand], [(cand, observation('b1:BND', ref='b', line=2)), (cand, proof)],
                           cves={CVE_A: (hypothesis(),)}))
    lead = leads_of(assessment, CVE_A)[cand.candidate_key]
    lines = why.explain(assessment, lead)
    assert any(markup in line for line in lines)  # shown as the text it is; escaping belongs to the renderer
    assert all(c.plain_line(line) == line and len(line) <= 300 for line in lines)
