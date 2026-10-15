"""SPEC-31 S3 verdict rules in isolation (05 s2.5): every proof needs target consistency and EH-EQ, semantic deltas beat
the decompiler proof, a material verdict needs an anchored second channel. The rules are fed hand-made `Evidence`, and
a property test checks that no combination of evidence can make `judge` build an invalid `ChangeFacts`."""
from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.unified.contracts import CHANNELS, Delta
from patchtrace.unified.facts import Evidence, IrEvidence, verdict

ROW = 'a' * 64
EQUAL = {'C0': 'equal', 'C1': 'equal', 'C2': 'equal', 'C3': 'equal', 'C4': 'equal', 'C5': 'equal', 'C6': 'unavailable',
         'C7': 'unavailable', 'C8': 'unavailable'}


def delta(cls, channel='C2', old='OLD', new='NEW'):
    return Delta(cls=cls, channel=channel, older_rva=0x1000, newer_rva=0x1000, old=old, new=new)


def ev(states=None, deltas=(), anchors=None, targets=(3, 0, 0), eh='equal', ir=None, limits_hit=(), signal=False,
       diff_types=()):
    return Evidence(states={**EQUAL, **(states or {})}, deltas=tuple(deltas),
                    anchors=tuple(anchors) if anchors is not None else (None,) * len(tuple(deltas)), targets=targets,
                    eh=eh, change_signal=signal, diff_types=diff_types, limits_hit=limits_hit,
                    ir=ir or IrEvidence(positional_cfg=True, layout_ok=True, mask_unlocated=False))


def judge(evidence, decision='matched'):
    return verdict.judge(ROW, decision, evidence)


def pair(evidence):
    facts = judge(evidence).facts
    return facts.verdict, facts.proof


# --- the order of the rules ------------------------------------------------------------------------------------------------

def test_equal_bytes_with_mapped_targets_and_equal_unwind_data_are_unchanged():
    assert pair(ev()) == ('unchanged', 'UNCH/1')
    assert pair(ev(eh='absent')) == ('unchanged', 'UNCH/1')


@pytest.mark.parametrize('what', [dict(targets=(3, 1, 0)), dict(targets=(3, 0, 1)), dict(eh='differs'),
                                  dict(eh='unavailable'), dict(limits_hit=('align-cap',)),
                                  dict(deltas=[delta('register-only')])],
                         ids=['unmapped', 'conflict', 'eh-differs', 'eh-unavailable', 'align-cap', 'any-delta'])
def test_unchanged_is_blocked(what):
    assert pair(ev(**what))[0] != 'unchanged'


def test_an_alignment_cap_alone_is_a_reason_for_review_never_unknown():
    """The cap hides what could not be aligned: a pair without any other signal must not read `unknown`."""
    facts = judge(ev(limits_hit=('align-cap',))).facts
    assert (facts.verdict, facts.proof) == ('review', None) and 'align-cap' in facts.limits_hit
    assert pair(ev(states={name: 'unavailable' for name in EQUAL})) == ('unknown', None)     # the baseline: no signal


def test_masked_equal_bytes_are_cosmetic_with_the_address_proof_only_when_the_cfg_is_positional():
    moved = {'C0': 'differs'}
    assert pair(ev(moved)) == ('cosmetic', 'COS-ADDR/1')
    assert pair(ev(moved, ir=IrEvidence(False, False, False)))[0] == 'review'
    assert pair(ev(moved, ir=IrEvidence(True, True, True)))[1] == 'COS-LAYOUT/1'       # an unlocated field: no COS-ADDR
    assert pair(ev({'C0': 'differs', 'C1': 'differs'}, ir=IrEvidence(False, True, False))) == ('cosmetic', 'COS-LAYOUT/1')


@pytest.mark.parametrize('what', [dict(targets=(3, 1, 0)), dict(eh='differs'), dict(states={'C4': 'differs'}),
                                  dict(states={'C5': 'differs'}), dict(states={'C5': 'unavailable'}),
                                  dict(deltas=[delta('cfg')]), dict(deltas=[delta('block-added')]),
                                  dict(deltas=[delta('unknown')]), dict(deltas=[delta('frame')]),
                                  dict(deltas=[delta('register-only')]), dict(deltas=[delta('constant')])],
                         ids=['unmapped', 'eh', 'c4', 'c5', 'c5-missing', 'cfg', 'block', 'unknown', 'frame', 'register',
                              'constant'])
def test_structural_cosmetic_is_blocked(what):
    base = {'C0': 'differs'}
    what = dict(what)
    what['states'] = {**base, **what.get('states', {})}
    assert pair(ev(**what))[0] not in ('cosmetic', 'unchanged')


def test_layout_proof_needs_the_bijection():
    assert pair(ev({'C0': 'differs', 'C1': 'differs'}, ir=IrEvidence(False, False, False)))[0] == 'review'


def test_the_decompiler_proof_is_listed_and_needs_zero_unmapped_labels():
    states = {'C0': 'differs', 'C1': 'differs', 'C6': 'equal'}
    off = IrEvidence(False, False, False)
    assert pair(ev(states, ir=off)) == ('cosmetic', 'COS-PSEUDO/1')
    assert pair(ev(states, ir=IrEvidence(False, False, False, pseudo_unmapped=1)))[0] == 'review'
    assert pair(ev(states, ir=off, eh='differs'))[0] == 'review'
    assert pair(ev(states, ir=off, targets=(1, 0, 1)))[0] != 'cosmetic'
    assert pair(ev(states, ir=off, deltas=[delta('frame')]))[0] == 'review'


def test_a_semantic_delta_beats_every_proof():
    for cls in ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
                'struct-offset', 'string'):
        assert pair(ev({'C0': 'differs', 'C6': 'equal'}, deltas=[delta(cls)]))[0] == 'review', cls


# --- material needs an anchored second channel -------------------------------------------------------------------------------

def test_material_needs_anchored_second_channel():
    states = {'C0': 'differs', 'C1': 'differs', 'C4': 'differs'}
    callee = delta('callee')
    assert judge(ev(states, deltas=[callee], anchors=['C4'])).facts.verdict == 'material'
    assert judge(ev(states, deltas=[callee], anchors=[None])).facts.verdict == 'review'
    # an anchor from the bytes group, or from a channel that does not differ, is no anchor
    assert judge(ev(states, deltas=[callee], anchors=['C2'])).facts.verdict == 'review'
    assert judge(ev({**states, 'C4': 'equal'}, deltas=[callee], anchors=['C4'])).facts.verdict == 'review'
    # a non-semantic class is never promoted, whatever anchors it
    assert judge(ev(states, deltas=[delta('frame')], anchors=['C4'])).facts.verdict == 'review'


def test_register_address_and_unwind_changes_stay_review():
    for cls in ('register-only', 'frame', 'cfg', 'unknown'):
        assert judge(ev({'C0': 'differs', 'C1': 'differs', 'C4': 'differs'}, deltas=[delta(cls)],
                        anchors=['C4'])).facts.verdict == 'review'
    result = judge(ev({'C0': 'equal'}, eh='differs'))
    assert result.facts.verdict == 'review' and 'eh' in result.classes


def test_review_ordering_puts_calls_first_and_context_constants_before_other_constants():
    result = judge(ev({'C0': 'differs'}, deltas=[delta('constant', old='MOV EAX,0x1'), delta('callee'),
                                                  delta('constant', old='CMP EAX,0x1')]))
    assert result.classes == ('callee', 'constant')
    from patchtrace.unified.facts import severity
    assert severity(delta('constant', old='CMP EAX,0x1')) < severity(delta('struct-offset'))
    assert severity(delta('struct-offset')) < severity(delta('constant', old='MOV EAX,0x1'))


def test_a_trace_argument_row_gets_its_hint():
    result = judge(ev({'C0': 'differs'}, deltas=[delta('constant')], ir=IrEvidence(False, False, False, trace_arg=True)))
    assert result.hints == ('trace-arg',) and result.facts.verdict == 'review'


def test_one_sided_rows_have_no_facts():
    assert judge(ev(), 'older-only').facts.verdict == 'not-applicable'


def test_a_pair_without_any_signal_is_unknown_never_cosmetic():
    silent = dict.fromkeys(CHANNELS, 'unavailable')
    result = judge(Evidence(states=silent, deltas=(), anchors=(), targets=(0, 0, 0), eh='unavailable',
                            change_signal=False, diff_types=(), limits_hit=(), ir=None))
    assert result.facts.verdict == 'unknown' and result.facts.proof is None


# --- no evidence can make the rules build an invalid record ----------------------------------------------------------------

STATES = st.sampled_from(['equal', 'differs', 'unavailable'])
CLASSES = st.sampled_from(['constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
                           'struct-offset', 'cfg', 'block-added', 'block-removed', 'string', 'frame', 'eh', 'unknown',
                           'register-only', 'address-only'])


@st.composite
def evidence(draw):
    deltas = draw(st.lists(st.builds(delta, CLASSES, st.sampled_from(['C2', 'C3', 'C4', 'C5', 'C6'])), max_size=6))
    states = {c: draw(STATES) for c in CHANNELS}
    anchors = [draw(st.sampled_from([None, 'C0', 'C2', 'C3', 'C4', 'C6', 'C8'])) for _ in deltas]
    ir = draw(st.one_of(st.none(), st.builds(IrEvidence, st.booleans(), st.booleans(), st.booleans(),
                                             st.integers(0, 2))))
    return Evidence(states=states, deltas=tuple(deltas), anchors=tuple(anchors),
                    targets=(draw(st.integers(0, 3)), draw(st.integers(0, 2)), draw(st.integers(0, 2))),
                    eh=draw(st.sampled_from(['equal', 'differs', 'absent', 'unavailable'])),
                    change_signal=draw(st.booleans()), diff_types=(), limits_hit=draw(st.sampled_from([(), ('align-cap',)])),
                    ir=ir)


@settings(max_examples=500, deadline=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])
@given(evidence())
def test_no_evidence_builds_an_invalid_change_facts_and_every_proof_has_its_preconditions(e):
    facts = judge(e).facts                      # the model validators raise on any contradiction
    if facts.proof is not None:
        assert facts.targets[1] == facts.targets[2] == 0
        assert not {d.cls for d in facts.deltas} & {'constant', 'comparison', 'condition', 'callee', 'call-added',
                                                    'call-removed', 'data-ref', 'struct-offset', 'string'}
    if facts.verdict == 'unchanged':
        assert dict(facts.channels)['C0'] == 'equal' and facts.eh in ('equal', 'absent') and not facts.deltas
    if facts.proof in ('UNCH/1', 'COS-ADDR/1', 'COS-LAYOUT/1'):
        assert facts.eh in ('equal', 'absent')
    if facts.verdict == 'material':
        assert facts.second_channel not in ('C0', 'C1', 'C2', 'C5') and dict(facts.channels)[facts.second_channel] == 'differs'
