"""SPEC-31 S3b: which review rows are decompiled (facts/refacts.py, 05 s2.8) and how the decompiled C text reaches C6
and MAT-ANCHOR (`FactsContext.build(decompiled=...)`). The decompiler output used here is hand-written C of the
shape Ghidra prints; the text of the REAL decompiler is pinned in tests/test_unified_refacts_recorded.py."""
from __future__ import annotations

import dataclasses
import random

import pytest
import test_unified_facts as s0
import unified_s0_fixtures as fx
from test_unified_ir_facts import image
from test_unified_verdict_ir import delta, ev, judge
from unified_facts_builder import run_facts

from patchtrace.unified.facts import IrEvidence
from patchtrace.unified.facts.channels import FactsContext
from patchtrace.unified.facts.refacts import select_for_decompile, wants_decompile
from patchtrace.unified.limits import DEFAULT_LIMITS

MOVED = {'C0': 'differs', 'C1': 'differs'}
OLD = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_a'), ('add_ri', 'EAX', 3), ('label', 'done'),
       ('ret',)]
NEW = [*OLD[:3], ('add_ri', 'EAX', 4), *OLD[4:]]
TEXT_OLD = 'int f(int a)\n{\n  if (a < 7) {\n    return a + 3;\n  }\n  return 0;\n}'
TEXT_NEW = TEXT_OLD.replace('+ 3', '+ 4')


def review(cls, old='ADD EAX,0x5', **kw):
    return judge(ev(MOVED, deltas=[delta(cls, old=old)], **kw))


# --- the selection ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('cls', ['constant', 'comparison', 'condition', 'struct-offset'])
def test_the_four_classes_a_decompiler_can_confirm_are_selected(cls):
    assert wants_decompile(review(cls)) and select_for_decompile([((1, 1), review(cls))]) == [(1, 1)]


@pytest.mark.parametrize('cls', ['callee', 'call-added', 'call-removed', 'data-ref', 'string', 'frame', 'register-only',
                                 'unknown'])
def test_other_classes_are_not(cls):
    assert not wants_decompile(review(cls))


def test_only_review_rows_without_c6_are_selected():
    material = judge(ev({**MOVED, 'C4': 'differs'}, deltas=[delta('constant')], anchors=['C4']))
    assert material.facts.verdict == 'material' and not wants_decompile(material)
    assert not wants_decompile(judge(ev({**MOVED, 'C6': 'equal'}, deltas=[delta('constant')])))
    assert not wants_decompile(judge(ev({**MOVED, 'C6': 'differs'}, deltas=[delta('constant')])))
    assert not wants_decompile(judge(ev({}, deltas=[])))                                    # unchanged
    assert not wants_decompile(judge(ev(MOVED)))                                            # cosmetic
    assert not wants_decompile(judge(ev(MOVED), decision='older-only'))                     # one-sided


def test_the_review_order_of_05_s2_6_decides_and_the_trace_arguments_come_last():
    rows = {
        'condition': review('condition'), 'comparison': review('comparison'),
        'constant-compare': review('constant', old='CMP EAX,0x5'), 'struct-offset': review('struct-offset'),
        'constant': review('constant', old='ADD EAX,0x5'),
        'trace': review('condition', ir=IrEvidence(True, True, False, trace_arg=True))}
    pairs = {name: (0x1000 + 0x10 * i, 0x1000 + 0x10 * i) for i, name in enumerate(rows)}
    shuffled = list(rows.items())
    random.Random(7).shuffle(shuffled)
    chosen = select_for_decompile((pairs[name], judged) for name, judged in shuffled)
    by_pair = {pair: name for name, pair in pairs.items()}
    assert [by_pair[pair] for pair in chosen] == ['condition', 'comparison', 'constant-compare', 'struct-offset',
                                                  'constant', 'trace']


def test_the_limit_and_the_order_of_the_input_do_not_change_the_choice():
    rows = [((0x1000 + i, 0x2000 + i), review('constant')) for i in range(70)]
    assert len(select_for_decompile(rows)) == DEFAULT_LIMITS.l41_decompile_pairs == 64
    assert select_for_decompile(rows, limit=3) == [(0x1000, 0x2000), (0x1001, 0x2001), (0x1002, 0x2002)]
    assert select_for_decompile(reversed(rows), limit=3) == select_for_decompile(rows, limit=3)


# --- the decompiled text reaches C6 and MAT-ANCHOR -----------------------------------------------------------------------------

def run(tmp_path, decompiled=None, old=OLD, new=NEW):
    return run_facts(tmp_path, image(old), image(new), decompiled=decompiled)


def test_a_constant_only_edit_is_review_until_the_decompiler_shows_it(tmp_path):
    before = run(tmp_path)
    assert before.verdict('f') == ('review', None) and dict(before.facts('f').channels)['C6'] == 'unavailable'
    assert select_for_decompile([((0x1000, 0x1000), before['f'])]) == [(0x1000, 0x1000)]
    after = run(tmp_path, {'older': {0x1000: TEXT_OLD}, 'newer': {0x1000: TEXT_NEW}})
    facts = after.facts('f')
    assert (facts.verdict, facts.second_channel) == ('material', 'C6') and dict(facts.channels)['C6'] == 'differs'
    assert [d.cls for d in facts.deltas] == [d.cls for d in before.facts('f').deltas]     # the same deltas, now anchored


def test_text_that_does_not_show_the_same_change_never_promotes(tmp_path):
    same = run(tmp_path, {'older': {0x1000: TEXT_OLD}, 'newer': {0x1000: TEXT_OLD}})
    assert same.verdict('f') == ('review', None) and dict(same.facts('f').channels)['C6'] == 'equal'
    other = run(tmp_path, {'older': {0x1000: TEXT_OLD}, 'newer': {0x1000: TEXT_OLD.replace('< 7', '< 8')}})
    assert other.verdict('f') == ('review', None) and dict(other.facts('f').channels)['C6'] == 'differs'


def test_one_side_alone_or_text_over_the_cap_gives_no_c6(tmp_path):
    half = run(tmp_path, {'older': {0x1000: TEXT_OLD}})
    assert dict(half.facts('f').channels)['C6'] == 'unavailable' and half.verdict('f')[0] == 'review'
    tight = dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_lines=3)
    capped = run_facts(tmp_path, image(OLD), image(NEW), limits=tight,
                       decompiled={'older': {0x1000: TEXT_OLD}, 'newer': {0x1000: TEXT_NEW}})
    assert dict(capped.facts('f').channels)['C6'] == 'unavailable' and 'pseudo-cap' in capped.facts('f').limits_hit


def test_one_side_of_text_alone_is_inert_even_when_it_is_over_the_cap(tmp_path):
    tight = dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_lines=3)
    r = run_facts(tmp_path, image(OLD), image(NEW), limits=tight, decompiled={'older': {0x1000: TEXT_OLD}})
    assert dict(r.facts('f').channels)['C6'] == 'unavailable' and 'pseudo-cap' not in r.facts('f').limits_hit


def s0_context(*, decompiled, records=True):
    """S0 mode (no IR) over Ghidriff's stored code, with the S3b texts alongside."""
    matches = [s0.pair_match('int f(int a) { return a + 1; }', 'int f(int a) { return a + 2; }')] if records else []
    row = s0.decided(0x1000, 0x1080)
    context = FactsContext.build(older_sha256=fx.OLD_SHA, newer_sha256=fx.NEW_SHA, addr=fx.addr_map(), matches=matches,
                                 rows=[row], bindiff_flags={}, decompiled=decompiled)
    return context.collect(row)


def test_ghidriffs_stored_code_wins_over_the_decompile():
    texts = {'older': {0x1000: 'int f(int a) { return a + 5; }'}, 'newer': {0x1080: 'int f(int a) { return a + 9; }'}}
    evidence = s0_context(decompiled=texts)
    assert {(d.old, d.new) for d in evidence.deltas if d.cls == 'constant'} == {('1', '2')}        # not 5 -> 9


def test_a_pair_without_any_ghidriff_record_gets_c6_from_the_decompile_alone():
    texts = {'older': {0x1000: 'int f(int a) { return a + 5; }'}, 'newer': {0x1080: 'int f(int a) { return a + 9; }'}}
    assert s0_context(decompiled=None, records=False).states['C6'] == 'unavailable'
    evidence = s0_context(decompiled=texts, records=False)
    assert evidence.states['C6'] == 'differs'
    assert {(d.old, d.new) for d in evidence.deltas if d.cls == 'constant'} == {('5', '9')}


def test_the_decompiled_text_never_decides_alone(tmp_path):
    """No bytes difference, a text difference: the text cannot make a row `material` (it is the second channel)."""
    r = run(tmp_path, {'older': {0x1000: TEXT_OLD}, 'newer': {0x1000: TEXT_NEW}}, old=OLD, new=OLD)
    assert r.verdict('f')[0] != 'material' and r.facts('f').second_channel is None


def test_a_row_the_decompile_does_not_mention_is_untouched(tmp_path):
    plain = run(tmp_path)
    other = run(tmp_path, {'older': {0x1200: TEXT_OLD}, 'newer': {0x1200: TEXT_NEW}})
    assert plain.facts('f') == other.facts('f')
