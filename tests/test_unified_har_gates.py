"""SPEC-31 harness audit (card har): evaluator hardening for G-U4 (U7-08), G-U7 (U7-17) and the rule that no gate passes on
empty or missing data. Pure and hermetic: label documents from the SPEC-32 contract, outcome rows written by hand."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS), str(ROOT / 'src')]
from unified_s6_helpers import label_doc  # noqa: E402

from tools.unified import evaluators, outcomes  # noqa: E402
from tools.unified.corpus import manifest as corpus_manifest  # noqa: E402

R = outcomes.OutcomeRow
FLIP = {'older-only': 'newer-only', 'newer-only': 'older-only'}
KINDS = ('matched', 'tentative', 'candidate', 'contested', 'ambiguous', 'unknown')


def pair(doc, rs, orientation='forward'):
    return outcomes.collect_rows(rs, doc, orientation=orientation)


def run(name, *pairs):
    return outcomes.build(name, 'Linux-6', pairs)


def mirror(rs, *, change=None):
    """The swapped orientation of rows; `change` maps an index to a replacement decision."""
    out = []
    for i, r in enumerate(rs):
        decision = (change or {}).get(i, FLIP.get(r.decision, r.decision))
        out.append(R(older=r.newer, newer=r.older, decision=decision, materiality=r.materiality))
    return out


def one_of_each():
    rows = [R(older=(0x1000 + 0x10 * i,), newer=(0x2000 + 0x10 * i,), decision=k, materiality='review')
            for i, k in enumerate(KINDS)]
    return [*rows, R(older=(0x5000,), newer=(), decision='older-only', materiality='not-applicable'),
            R(older=(), newer=(0x6000,), decision='newer-only', materiality='not-applicable')]


def g4(rows, back):
    doc = label_doc('rel', 'release')
    sets = [run('linux', pair(doc, rows), pair(doc, back, orientation='swapped'))]
    return evaluators.g_u4(sets, corpus_manifest.build([doc], {}))


def test_g_u4_mirror_check_covers_every_decision_kind():
    rows = one_of_each()
    status, reasons, observed = g4(rows, mirror(rows))
    assert observed['mirrored'] == {'rel': 'mirrored'} and not any('mirror' in r for r in reasons)
    for index, kind in enumerate(KINDS):
        other = next(k for k in KINDS if k != kind)
        status, reasons, observed = g4(rows, mirror(rows, change={index: other}))
        assert status == 'fail' and observed['mirrored'] == {'rel': 'not-mirrored'}, kind
        assert any('mirror image' in r for r in reasons), kind


@pytest.mark.parametrize('kind', KINDS[1:])
def test_g_u4_a_row_that_pairs_other_functions_on_swap_is_not_mirrored(kind):
    rows = [R(older=(0x1000,), newer=(0x2000,), decision=kind, materiality='review')]
    back = [R(older=(0x2010,), newer=(0x1000,), decision=kind, materiality='review')]
    assert g4(rows, back)[0] == 'fail'


def test_g_u4_one_sided_rows_must_trade_places():
    rows = [R(older=(0x5000,), newer=(), decision='older-only', materiality='not-applicable')]
    same_side = [R(older=(), newer=(0x5000,), decision='older-only', materiality='not-applicable')]
    assert g4(rows, same_side)[0] == 'fail'
    assert g4(rows, mirror(rows))[2]['mirrored'] == {'rel': 'mirrored'}


def test_trace_arg_mutant_class_is_pending_with_its_exact_need_so_g_u2_cannot_pass_silently():
    from tools.unified.mutations import classes
    pending = {p.id: p for p in classes.PENDING}
    assert 'trace-arg' in pending and 'import' in pending['trace-arg'].needs and 'review' in pending['trace-arg'].needs
    assert pending['trace-arg'].spec_phrase == 'trace-arg' and pending['trace-arg'].review_finding == 'R-29'
    assert 'trace-arg' not in {c.id for c in classes.CLASSES}          # not claimed as planted while it cannot be
