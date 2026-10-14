"""SPEC-32 s7 mutation labelling rule as a pure function."""
from __future__ import annotations

import pytest

from tools.calibration.mutations import labels as L

F = L.FunctionFact


def by_name(decisions):
    return {d.name: d for d in decisions}


@pytest.mark.parametrize('op, label', [('cmp-flip', 'changed'), ('int-width', 'changed'), ('ws-comment', 'cosmetic'),
                                       ('reorder-defs', 'cosmetic'), ('inline-toggle', 'cosmetic')])
def test_target_label_and_kind(op, label):
    assert L.target_label(op) == (label, op)


def test_unknown_operator_rejected():
    with pytest.raises(ValueError):
        L.target_label('bogus')


def test_semantic_rule_table():
    facts = [F('t', True, True, False), F('other', True, True, True), F('induced', True, True, False),
             F('gone', True, False, None), F('ka_mut_h', False, True, None)]
    d = by_name(L.label_mutation('cmp-flip', 't', facts, helpers=('ka_mut_h',)))
    assert (d['t'].label, d['t'].change_kind, d['t'].check) == ('changed', 'cmp-flip', 'ok')
    assert d['other'].label == 'unchanged' and d['other'].change_kind is None
    assert d['induced'].label == 'ambiguous' and 'induced by t' in d['induced'].note
    assert d['gone'].label == 'no-counterpart'
    assert d['ka_mut_h'].label == 'no-counterpart' and d['ka_mut_h'].note == 'planted helper'


def test_semantic_target_with_equal_masked_body_disagrees():
    d = by_name(L.label_mutation('const-change', 't', [F('t', True, True, True)]))
    assert d['t'].label == 'changed' and d['t'].check == 'disagree'
    assert not L.semantic_accepted(True) and L.semantic_accepted(False) and not L.semantic_accepted(None)


def test_cosmetic_never_induces_ambiguity():
    facts = [F('t', True, True, False), F('o', True, True, False), F('p', True, True, True)]
    d = by_name(L.label_mutation('local-rename', 't', facts))
    assert d['t'].label == 'cosmetic' and d['t'].change_kind == 'local-rename' and d['t'].check == 'ok'
    assert d['o'].label == 'unchanged' and d['p'].label == 'unchanged'


def test_missing_target_is_a_disagreement_not_a_crash():
    d = by_name(L.label_mutation('cmp-flip', 't', [F('t', True, False, None)]))
    assert d['t'].label == 'no-counterpart' and d['t'].check == 'disagree'


def test_output_is_sorted_by_name():
    facts = [F('b', True, True, True), F('a', True, True, True), F('t', True, True, False)]
    assert [d.name for d in L.label_mutation('cmp-flip', 't', facts)] == ['a', 'b', 't']
