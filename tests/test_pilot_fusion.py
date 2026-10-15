"""PIL-B2 fusion: shared-origin independence, three-valued expected changes, the CVE gate and the caps of the tier
derivation, locality and the observation lists of a lead (docs/specs/program-e/PIL-integration-plan.md s6, s7).

Each test states one rule of the plan on a one-candidate or few-candidate scenario built from real pilot/1 observations
and K hypotheses (`pilot_localize_support`); the oracle (`test_pilot_synergy.py`) covers the nine-function ledger.
Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import dataclasses

import pytest
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
    leads_of,
    observation,
    run,
    sha,
    status,
)
from pilot_synergy_support import StaticEvidence

from patchtrace.enrichment import signals as b1
from patchtrace.pilot import contracts as c
from patchtrace.pilot import fusion, keys
from patchtrace.pilot.limits import PilotError
from patchtrace.pilot.rules import data as rules
from patchtrace.pilot.service import DEFAULT_REGISTRY

COMPONENT = [anchor('component', 'SYNTHETIC Example Net IPv6 Fragment Reassembly'),
             anchor('module', 'examplenet.sys'), anchor('feature', 'IPv6')]
GUARD = ('b1:BND', 'cf:comparison')


def scenario(observations, *, hyps=None, gate='applies', window='no', window_cves=(), name='Handler',
             identity='corroborated', config=None, anchors=(), extra=(), **kw):
    """One candidate with the given observations against one CVE; returns (assessment, its lead in the CVE context).
    The tool channels ran unless a test says otherwise (an observation of a channel that did not run is not read)."""
    for tool in ('capa', 'strings', 'build_state'):
        kw.setdefault(tool, 'available')
    cand = candidate(1, name, identity=identity)
    inputs = build([cand, *extra], [(cand, o) for o in observations], cves={CVE_A: (hypothesis(),) if hyps is None else tuple(hyps)},
                   contexts=[context(CVE_A, gate=gate, window=window, window_cves=window_cves)], anchors=anchors,
                   entries={CVE_A: (advisory_entry(),)}, **kw)
    assessment = run(inputs, config)
    return assessment, leads_of(assessment, CVE_A).get(cand.candidate_key)


def shape(kind='b1:BND', **kw):
    return observation(kind, ref=kw.pop('ref', 'x'), line=kw.pop('line', 7), **kw)


def guard():
    return [shape('b1:BND'), shape('cf:comparison')]


# --- independence: shared origins count once, never summed or averaged --------------------------------------------------

def test_one_origin_is_one_witness_however_many_observations_repeat_it():
    many = [shape('b1:BND', ref='a'), shape('cf:comparison', ref='b'), shape('cf:condition', ref='c'),
            call('RtlSizeTAdd'), shape('b1:SIZE', ref='d')]
    _, lead = scenario(many)
    assert (lead.components.count, lead.components.tags) == (2, ('D_ghidra', 'D_vendor_text'))
    assert lead.lead_class == 'fit'  # two witnesses: the advisory text and Ghidra-derived code
    _, single = scenario([shape('b1:BND')])
    assert (single.components.count, single.lead_class) == (2, 'fit')


def test_an_independent_origin_adds_a_witness_and_context_adds_none():
    sized = call('RtlSizeTAdd', verification='verified-bytes', origins=('D_pe_tables',))
    _, lead = scenario([shape('cf:comparison'), sized])
    assert lead.components.tags == ('D_ghidra', 'D_pe_tables', 'D_vendor_text')  # the import table is not Ghidra output
    noisy = [shape('cf:comparison'), observation('str:added', role='context', ref='s'),
             observation('die:toolchain-changed', role='context', ref='d')]
    _, lead = scenario(noisy)
    assert lead.components.count == 2  # strings and build facts are context: they never count


def test_the_advisory_is_a_witness_only_when_code_evidence_meets_a_change():
    _, unmet = scenario([observation('cf:string', role='context', ref='s')])
    assert unmet.components.count == 0 and advisory_entry().obs_id not in unmet.support_ids
    _, met = scenario([shape('b1:BND')])
    assert advisory_entry().obs_id in met.support_ids


def test_a_label_only_call_supports_at_most_a_partial_fit():
    """Plan s4: label-only calls support at most tentative. R-INTEGER (`overflow-check`) can rest on a call alone."""
    integer = (hypothesis('R-INTEGER', 'CWE-190'),)
    label = call('RtlULongAdd')
    _, lead = scenario([label], hyps=integer)
    assert (lead.lead_class, lead.mechanism, lead.fits[0].met) == ('partial', 'tentative', 1)
    assert lead.fits[0].expected_changes[0].state == 'met' and not lead.caps  # met, but not firm enough for a fit
    proven = call('RtlULongAdd', verification='verified-bytes', origins=('D_pe_tables',))
    _, lead = scenario([label, proven], hyps=integer)
    assert (lead.lead_class, lead.components.count) == ('fit', 3)  # the import table was read from the file bytes


def test_rows_without_a_b1_detector_need_two_independent_code_origins():
    """Plan s7: they stay tentative unless two components agree (the advisory does not count for them)."""
    pointer = (hypothesis('R-POINTER', 'CWE-822'),)
    assert not rules.find_rule('R-POINTER', 1).detectors
    _, lead = scenario([shape('cf:comparison')], hyps=pointer)
    assert (lead.lead_class, lead.components.count) == ('partial', 2)  # advisory + Ghidra is not enough here
    probe = call('ProbeForRead', verification='verified-bytes', origins=('D_pe_tables',))
    _, lead = scenario([shape('cf:comparison'), probe], hyps=pointer)
    assert (lead.lead_class, lead.components.count) == ('fit', 3)
    _, backed = scenario([shape('b1:BND')], hyps=(hypothesis('R-MEMORY-WRITE'),))
    assert backed.lead_class == 'fit'  # a row with a B1 detector needs only the advisory and one code origin


def test_lexical_evidence_alone_can_fit_unless_the_configuration_forbids_it():
    _, lead = scenario([shape('b1:BND')])
    assert (lead.lead_class, lead.depth) == ('fit', 'lexical')  # plan s11 question 5: yes, with the text-only flag
    strict = keys.default_config(lexical_moderate=False)
    _, held = scenario([shape('b1:BND')], config=strict)
    assert (held.lead_class, held.depth, held.caps) == ('partial', 'lexical', ())
    _, typed = scenario([shape('cf:comparison')], config=strict)
    assert (typed.lead_class, typed.depth) == ('fit', 'typed')


def test_b1_integer_signals_are_read_at_the_weakest_confidence():
    """`INT` is weak unless a strictness flip is found; the observation does not repeat it, so it is read as weak."""
    assert dict(fusion.B1_LEVEL) == {d.id: ('weak' if d.id == 'INT' else d.confidence) for d in b1.DETECTORS}
    off_by_one = (hypothesis('R-OFF-BY-ONE', 'CWE-193'),)
    _, weak = scenario([shape('b1:INT')], hyps=off_by_one)
    assert weak.fits[0].expected_changes[0].state == 'not-observed'  # `b1:INT@moderate` needs the flip
    _, bound = scenario([shape('b1:BND')], hyps=off_by_one)
    assert bound.fits[0].expected_changes[0].state == 'met'


# --- three-valued: missing evidence is unknown, never a negative vote ------------------------------------------------------

def test_an_incomplete_channel_gives_unknown_and_a_complete_one_gives_not_seen():
    _, partial = scenario([shape('b1:BND')], code='partial')
    assert {x.id: x.state for x in partial.fits[0].expected_changes} == {
        'guard-added': 'met', 'size-recomputed': 'unknown', 'checked-arithmetic': 'unknown'}
    _, complete = scenario([shape('b1:BND')], code='available', calls='available')
    assert {x.id: x.state for x in complete.fits[0].expected_changes} == {
        'guard-added': 'met', 'size-recomputed': 'not-observed', 'checked-arithmetic': 'not-observed'}


def test_one_sided_and_group_candidates_are_not_compared_so_nothing_is_not_seen():
    one_sided = candidate(2, 'Gone', older_only=True)
    group = c.Candidate(candidate_key=sha('group'), identity='unassessed',
                        older=(c.FunctionRef(rva=0x10, name='A'), c.FunctionRef(rva=0x20, name='B')),
                        newer=(c.FunctionRef(rva=0x30, name='C'),))
    assessment, _ = scenario([], extra=[one_sided, group], code='available', calls='available')
    for cand in (one_sided, group):
        lead = leads_of(assessment, CVE_A)[cand.candidate_key]
        assert {x.state for x in lead.fits[0].expected_changes} == {'unknown'}, cand
        assert lead.lead_class == 'queue' and lead.mechanism == 'not-assessed'


@pytest.mark.parametrize('state', ['not-run', 'unsupported', 'failed', 'stale'])
def test_evidence_of_a_channel_that_did_not_run_is_not_read(state):
    _, lead = scenario([shape('cf:comparison'), call('RtlSizeTAdd')], calls=state)
    assert [x.state for x in lead.fits[0].expected_changes] == ['met', 'not-observed', 'unknown']  # the call is unread
    assert lead.lead_class == 'fit'  # the code channel alone still fits
    _, silent = scenario([shape('cf:comparison')], code=state)
    assert silent.lead_class == 'queue' and silent.fits[0].met == 0  # nothing was read: unknown, not "no"
    assert {x.state for x in silent.fits[0].expected_changes} == {'unknown'}


def test_an_unusable_channel_is_listed_and_a_failed_one_makes_the_result_partial():
    assessment, _ = scenario([shape('b1:BND')], code='failed')
    states = {x.channel: x.state for x in assessment.channels}
    assert states['code'] == 'failed' and tuple(states) == c.CHANNELS
    assert assessment.status == 'partial' and any('Code channel is failed' in x for x in assessment.limitations)
    quiet, _ = scenario([shape('b1:BND')], capa='not-run', strings='not-run')
    assert quiet.status == 'complete'  # a tool that was not run is unknown evidence, not a failure


# --- proofs against a change -----------------------------------------------------------------------------------------------

def test_a_named_proof_against_a_met_change_forces_review_and_is_kept():
    proof = observation('cf:cosmetic', role='conflict', ref='p', detail='proof COS-LAYOUT/1 holds: only moved')
    _, lead = scenario([shape('b1:BND'), proof])
    assert (lead.lead_class, lead.mechanism, lead.assessment) == ('review', 'contested', 'rule-hypothesis')
    assert lead.counter_ids == (proof.obs_id,)
    assert {x.id: x.state for x in lead.fits[0].expected_changes} == {
        'guard-added': 'met', 'size-recomputed': 'contradicted', 'checked-arithmetic': 'contradicted'}


def test_a_proof_with_no_met_change_gives_no_tier():
    proof = observation('cf:cosmetic', role='conflict', ref='p')
    _, lead = scenario([proof])
    assert (lead.lead_class, lead.mechanism, lead.fits[0].met) == ('queue', 'not-assessed', 0)
    assert lead.counter_ids == (proof.obs_id,)


def test_a_contested_pairing_forces_review_and_never_a_fit():
    _, lead = scenario(guard(), identity='contested')
    assert (lead.lead_class, lead.identity) == ('review', 'contested')
    _, plain = scenario(guard(), identity='unassessed')
    assert plain.lead_class == 'fit'  # an unassessed pairing is not a doubt


def test_a_compiler_only_rebuild_yields_no_fit():
    """Plan s6: cosmetic proofs, register and address churn and a changed toolchain explain a lexical guard away."""
    churn = [observation('cf:register-only', role='context', ref='r'),
             observation('cf:address-only', role='context', ref='a'),
             observation('die:toolchain-changed', role='context', ref='d')]
    proof = observation('cf:cosmetic', role='conflict', ref='p')
    _, lead = scenario([shape('b1:BND'), proof, *churn])
    assert lead.lead_class == 'partial' and lead.caps == ('toolchain-changed-lexical-only',)
    assert len(lead.alternative_ids) == 3 and lead.counter_ids == (proof.obs_id,)
    _, quiet = scenario(churn)
    assert (quiet.lead_class, quiet.mechanism) == ('queue', 'not-assessed')


@pytest.mark.parametrize('evidence', [
    [observation('cf:string', role='context', ref='s')],
    [observation('str:added', role='context', ref='s')],
    [observation('cf:string', role='context', ref='s'), observation('str:added', role='context', ref='t')]],
    ids=['changefacts', 'floss', 'both'])
def test_an_added_string_alone_is_never_a_fit(evidence):
    _, lead = scenario(evidence)
    assert (lead.lead_class, lead.mechanism, lead.components.count) == ('queue', 'unexplained', 0)


def test_build_facts_never_promote_and_only_cap_lexical_evidence():
    flag = observation('die:packed', role='context', ref='d')
    _, lead = scenario([flag])
    assert (lead.lead_class, lead.mechanism, lead.alternative_ids) == ('queue', 'not-assessed', (flag.obs_id,))
    _, capped = scenario([shape('b1:BND'), flag])
    assert capped.caps == ('toolchain-changed-lexical-only',) and capped.lead_class == 'partial'
    _, typed = scenario([shape('b1:BND'), flag, shape('cf:comparison')])
    assert typed.lead_class == 'fit' and not typed.caps  # a material ChangeFacts delta outweighs the build fact
    unanchored = observation('cf:comparison', ref='r', obligations=['second-channel'], line=7)
    _, review_row = scenario([shape('b1:BND'), flag, unanchored])
    assert review_row.caps == ('toolchain-changed-lexical-only',) and review_row.depth == 'typed'  # needs a material one


# --- the CVE gate ----------------------------------------------------------------------------------------------------------

def test_cve_gate_table():
    applied, applies = scenario(guard())
    assert (applies.gate, applies.lead_class, applies.caps) == ('applies', 'fit', ())
    _, unverified = scenario(guard(), gate='unverified')
    assert (unverified.gate, unverified.lead_class, unverified.caps) == ('unverified', 'partial', ('cve-unverified',))
    _, conflict = scenario(guard(), gate='conflict')
    assert (conflict.gate, conflict.lead_class, conflict.mechanism, conflict.caps) == (
        'conflict', 'review', 'contested', ('cve-conflict',))
    asserted, lead = scenario(guard(), gate='asserted')
    assert (lead.gate, lead.lead_class) == ('asserted', 'fit') and asserted.inputs.asserted_gates == (CVE_A,)
    assert applied.inputs.asserted_gates == ()
    assert keys.result_id(asserted.inputs) != keys.result_id(applied.inputs)  # an assertion is part of the identity


def test_not_applicable_cve_produces_no_leads():
    assessment, lead = scenario(guard(), gate='not-applicable')
    assert lead is None
    (ctx,) = assessment.cves
    assert ctx.gate == 'not-applicable' and not any(ctx.counts.model_dump().values())
    assert [x.cve for x in assessment.leads] == [None]  # the code evidence alone is still listed


def test_a_cve_without_a_stored_report_has_no_expected_changes_and_says_so():
    cand = candidate(1, 'Handler')
    assessment = run(build([cand], [(cand, shape('b1:BND'))], contexts=[context(CVE_A)]))
    lead = leads_of(assessment, CVE_A)[cand.candidate_key]
    assert (lead.lead_class, lead.mechanism, lead.fits) == ('queue', 'unexplained', ())
    assert assessment.status == 'partial' and any('No advisory report' in x for x in assessment.cves[0].limitations)


def test_a_hypothesis_without_a_rule_row_fails_closed_to_unexplained():
    future = hypothesis().model_copy(update={'rule_revision': 99})
    assessment, lead = scenario([shape('b1:BND')], hyps=(future,))
    assert (lead.lead_class, lead.mechanism, lead.fits) == ('queue', 'unexplained', ())
    assert assessment.status == 'partial'
    assert any('rule R-MEMORY-WRITE revision 99' in x for x in assessment.cves[0].limitations)


# --- the confounded window and locality --------------------------------------------------------------------------------------

def test_a_confounded_window_holds_a_shape_fit_without_locality():
    both = (CVE_A, CVE_B)
    _, held = scenario(guard(), window='yes', window_cves=both, name='Unrelated', anchors=COMPONENT)
    assert (held.lead_class, held.caps, held.local_hits) == ('partial', ('confounded-window-needs-locality',), 0)
    _, local = scenario(guard(), window='yes', window_cves=both, name='ReassembleFragment', anchors=COMPONENT)
    assert (local.lead_class, local.caps, local.local_hits) == ('fit', (), 2)
    _, unknown = scenario(guard(), window='unknown', name='Unrelated', anchors=COMPONENT)
    assert unknown.lead_class == 'fit'  # an unknown window is stated, not capped
    _, alone = scenario(guard(), window='no', name='Unrelated', anchors=COMPONENT)
    assert alone.lead_class == 'fit'
    nameless, lead = scenario(guard(), window='yes', window_cves=both, name='Reassemble')  # no component anchor
    assert lead.lead_class == 'partial' and any('names no component' in x for x in nameless.cves[0].limitations)


def test_the_window_threshold_is_a_configuration_knob():
    strict = keys.default_config(confounded_min_cves=3)
    _, lead = scenario(guard(), window='yes', window_cves=(CVE_A, CVE_B), name='Unrelated', anchors=COMPONENT,
                       config=strict)
    assert lead.lead_class == 'fit'  # two CVEs are below the configured threshold of three


def hits(name, anchors=COMPONENT, minimum=2):
    view = fusion.view_of(context(), (), anchors, (), keys.default_config(), DEFAULT_REGISTRY)
    return fusion.locality(fusion.hold(candidate(1, name), ()), view, minimum)[0]


@pytest.mark.parametrize(('name', 'expected'), [
    ('ReassembleFragment', 2), ('FragmentReassembly', 2), ('Ipv6pFragmentListReassemble', 2),
    ('FragmentOnly', 0), ('Reassemble', 0), ('FUN_180001234', 0), ('sub_401000', 0), ('thunk_FUN_180001234', 0)],
    ids=['both', 'synonym', 'camel', 'one-token', 'other-token', 'ghidra-fun', 'sub', 'thunk'])
def test_locality_needs_two_distinct_tokens_and_a_placeholder_name_never_counts(name, expected):
    assert hits(name) == expected


def test_module_and_feature_words_are_not_locality():
    anchors = [anchor('component', 'Examplenet IPv6 Fragment Reassembly'), anchor('module', 'examplenet.sys'),
               anchor('feature', 'IPv6')]
    assert hits('Examplenet_Ipv6_Fragment', anchors) == 0  # only `fragment` is left of the phrase
    assert hits('Examplenet_Ipv6_Fragment_Reassembly', anchors) == 2


def test_tokens_of_two_phrases_never_combine_and_the_threshold_is_configurable():
    phrases = [anchor('component', 'Alpha Bravo'), anchor('component', 'Charlie Delta')]
    assert hits('AlphaCharlie', phrases, minimum=2) == 0 and hits('AlphaCharlie', phrases, minimum=1) == 1


def test_a_locality_is_its_own_ledger_entry_and_never_a_witness():
    assessment, lead = scenario(guard(), name='ReassembleFragment', anchors=COMPONENT)
    by_id = {o.obs_id: o for o in assessment.observations}
    (local,) = [by_id[i] for i in lead.support_ids if by_id[i].kind == 'loc:names']
    assert local.role == 'local' and local.origins == ('D_symbols',) and local.nav is not None
    assert 'fragment' in local.detail and 'reassemble' in local.detail
    assert lead.components.tags == ('D_ghidra', 'D_vendor_text')  # D_symbols is not a component


def test_locality_with_a_change_is_a_partial_fit_and_without_a_change_it_is_nothing():
    _, changed = scenario([observation('cf:string', role='context', ref='s')], name='ReassembleFragment',
                          anchors=COMPONENT)
    assert (changed.lead_class, changed.mechanism, changed.assessment) == ('partial', 'tentative', 'unknown')
    _, still = scenario([], name='ReassembleFragment', anchors=COMPONENT)
    assert (still.lead_class, still.mechanism, still.local_hits) == ('queue', 'not-assessed', 2)


# --- hypotheses ----------------------------------------------------------------------------------------------------------------

def test_the_best_hypothesis_comes_first_and_all_are_listed():
    explicit = hypothesis('R-MEMORY-WRITE', 'CWE-787', 'explicit-csaf-cwe')
    vocabulary = hypothesis('R-MEMORY-WRITE', 'CWE-122', 'curated-vocabulary')
    in_text = hypothesis('R-INPUT', 'CWE-20', 'cwe-id-in-text')
    _, lead = scenario([shape('b1:BND')], hyps=(vocabulary, in_text, explicit))
    # all three fit equally, so the basis decides: stated, then named in the text, then vocabulary
    assert [f.cwe_id for f in lead.fits] == ['CWE-787', 'CWE-20', 'CWE-122']
    _, by_evidence = scenario([shape('b1:VAL', ref='v')], hyps=(explicit, in_text))
    assert by_evidence.fits[0].rule_id == 'R-INPUT'  # the hypothesis the evidence meets is the best one
    assert {f.rule_id for f in by_evidence.fits} == {'R-MEMORY-WRITE', 'R-INPUT'}


def test_without_a_usable_hypothesis_there_is_nothing_to_fit():
    _, lead = scenario([shape('b1:BND')], hyps=())
    assert (lead.lead_class, lead.mechanism, lead.fits) == ('queue', 'unexplained', ())


# --- the observation lists of a lead -------------------------------------------------------------------------------------------

def test_every_observation_of_a_candidate_lands_in_exactly_one_list():
    parts = {
        'support': [shape('b1:BND'), observation('cf:string', role='context', ref='s')],
        'counter': [observation('cf:cosmetic', role='conflict', ref='p')],
        'unknown': [observation('capa:limitation', role='context', ref='l')],
        'alternative': [observation('die:toolchain-changed', role='context', ref='d'),
                        observation('cf:register-only', role='context', ref='r')]}
    _, lead = scenario([o for group in parts.values() for o in group])
    lists = {'support': lead.support_ids, 'counter': lead.counter_ids, 'unknown': lead.unknown_ids,
             'alternative': lead.alternative_ids}
    for name, group in parts.items():
        assert {o.obs_id for o in group} <= set(lists[name]), name
    seen = [i for ids in lists.values() for i in ids]
    assert len(seen) == len(set(seen))  # nothing is in two lists


def test_a_binary_level_finding_applies_to_every_lead_and_a_capa_finding_without_a_function_is_unknown():
    flag = observation('die:toolchain-changed', role='context', ref='binary')
    lost = observation('capa:unlocalized-added', role='context', ref='rule')
    first, second = candidate(1, 'Aa'), candidate(2, 'Bb')
    inputs = build([first, second], [(first, shape('b1:BND'))], cves={CVE_A: (hypothesis(),)}, binary=[flag, lost],
                   build_state='available', capa='available')
    assessment = run(inputs)
    assert len(assessment.leads) == 4  # two candidates, the code-only context and the CVE
    for lead in assessment.leads:
        assert flag.obs_id in lead.alternative_ids and lost.obs_id in lead.unknown_ids
    capped = leads_of(assessment, CVE_A)[first.candidate_key]
    assert capped.lead_class == 'partial' and capped.caps == ('toolchain-changed-lexical-only',)


def test_a_lead_references_at_most_p02_observations_and_keeps_its_evidence():
    many = [call(f'Api{i}', verification='tool-reported') for i in range(300)]
    meets = shape('b1:BND')
    # an advisory entry whose id sorts before every other observation: the first one a careless cut would drop
    first = next(e for e in (advisory_entry(source=f'csaf-{n}') for n in range(5000))
                 if e.obs_id < min(o.obs_id for o in [meets, *many]))
    cand = candidate(1, 'Handler')
    inputs = build([cand], [(cand, o) for o in [meets, *many]], cves={CVE_A: (hypothesis(),)}, entries={CVE_A: (first,)},
                   capa='available', strings='available', build_state='available')
    assessment = run(inputs)
    lead = leads_of(assessment, CVE_A)[cand.candidate_key]
    references = {*lead.support_ids, *lead.counter_ids, *lead.unknown_ids, *lead.alternative_ids}
    assert len(references) == 256 and meets.obs_id in lead.support_ids
    assert first.obs_id in lead.support_ids  # the advisory's own entry is explanation, kept before plain context
    assert 'observations-cut' in assessment.limits_hit and assessment.status == 'partial'
    assert lead.fits[0].expected_changes[0].observation_ids == (meets.obs_id,)


def test_the_pool_holds_exactly_what_the_leads_reference():
    assessment, _ = scenario(guard())
    referenced = set()
    for lead in assessment.leads:
        referenced |= {*lead.support_ids, *lead.counter_ids, *lead.unknown_ids, *lead.alternative_ids}
        referenced |= {i for f in lead.fits for x in f.expected_changes for i in x.observation_ids}
    assert [o.obs_id for o in assessment.observations] == sorted(referenced)
    keys.verify_assessment(assessment)


# --- misuse ----------------------------------------------------------------------------------------------------------------------

class Careless(StaticEvidence):
    """A code port that ignores which candidates were asked for."""

    def observations(self, candidate_keys):
        return iter(self._pairs)


def test_a_malformed_source_is_refused_with_a_typed_error():
    cand, other = candidate(1), candidate(2)
    careless = Careless(status('code'), [(other.candidate_key, shape('b1:BND'))])
    with pytest.raises(PilotError) as stray:
        run(dataclasses.replace(build([cand]), changes=careless))
    assert (stray.value.code, stray.value.reason) == ('PT-PILOT-INPUT', 'unknown-candidate')
    with pytest.raises(PilotError) as repeated:
        run(build([cand, cand]))
    assert repeated.value.reason == 'duplicate-candidate'
    wrong = keys.default_config().model_copy(update={'limits_digest': '0' * 64})
    with pytest.raises(PilotError) as limits:
        run(build([cand]), wrong)
    assert limits.value.reason == 'limits-digest'


def test_a_candidate_universe_that_cannot_be_listed_abstains():
    cand = candidate(1)
    for inputs in (build([cand], pairing='failed'), build([])):
        assessment = run(inputs)
        assert assessment.status == 'abstained' and not assessment.leads and assessment.limitations
        keys.verify_assessment(assessment)
