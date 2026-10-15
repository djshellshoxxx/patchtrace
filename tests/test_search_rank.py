"""WB1 S4: the lexicographic ordering key and its explanations (pure, no index)."""
from __future__ import annotations

import pytest

from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.search.rank import Candidate, Lead, order, origin_of, rank_reasons, sort_key


def cand(name='Foo', *, tier=1, group='fn', table='fts_name', bm25=0.0, kind='function', doc_id=1, side='newer',
         rva=None, extra='') -> Candidate:
    return Candidate(group, 'a' * 16, table, doc_id, kind, side, 's', name, extra, doc_id, rva, 0, None, tier,
                     'name-words', 'name', bm25=bm25)


def match(category='modified') -> FunctionMatch:
    record = FunctionRecord(artifact_id='a', run_id='r', name='Foo')
    old, new = ([record], [record]) if category in ('modified', 'unchanged') else (
        ([], [record]) if category == 'added' else ([record], []))
    return FunctionMatch(id=f'm-{category}', run_id='r', category=category, older=old, newer=new)


def lead(*cands, m=None, rank=None, known=False, key='k') -> Lead:
    return Lead(key, list(cands), m, rank, 3, known)


def keys(leads, sort='relevance'):
    return [lead_.key for lead_ in order(leads, sort)]


def test_tier_precedes_change_class_and_sort_change_swaps_them():
    code_changed = lead(cand(tier=4, kind='code'), m=match(), key='code-changed')
    name_unchanged = lead(cand(tier=1), m=match('unchanged'), key='name-unchanged')
    assert keys([code_changed, name_unchanged]) == ['name-unchanged', 'code-changed']
    assert keys([name_unchanged, code_changed], 'change') == ['code-changed', 'name-unchanged']


def test_more_independent_origins_win_inside_a_tier_and_class():
    one = lead(cand(), m=match(), key='one')
    two = lead(cand(), cand(group='tool:floss:newer', kind='string', tier=3, doc_id=2), m=match(), key='two')
    assert two.origins == ('floss', 'ghidra') and keys([one, two]) == ['two', 'one']


def test_same_origin_counts_once():
    both = lead(cand(), cand(kind='code', tier=4, doc_id=2), m=match())
    assert both.origins == ('ghidra',) and both.tier == 1


def test_attention_ordinal_breaks_ties_and_missing_rank_is_last():
    first = lead(cand(), m=match(), rank=1, known=True, key='first')
    third = lead(cand(), m=match(), rank=3, known=True, key='third')
    unranked = lead(cand(), m=match(), known=True, key='unranked')
    assert keys([unranked, third, first]) == ['first', 'third', 'unranked']
    assert unranked.change_class == 1 and first.change_class == 0


def test_bm25_is_only_compared_inside_one_table():
    a = lead(cand(table='fts_name', bm25=-1.0, doc_id=1), key='a')
    b = lead(cand('Bar', table='fts_text', bm25=-9.0, doc_id=2), key='b')
    assert sort_key(a, 'relevance')[4:6] == ('fn:fts_name', -1.0)
    assert keys([b, a]) == ['a', 'b']  # table id decides before any bm25
    tied = [lead(cand('Zed', bm25=-2.0, doc_id=3), key='z'), lead(cand('Yak', bm25=-3.0, doc_id=4), key='y')]
    assert keys(tied) == ['y', 'z']


def test_name_and_address_sorts():
    low, high = lead(cand('Beta', rva=0x10), key='beta'), lead(cand('Alpha', rva=0x20), key='alpha')
    assert keys([low, high], 'name') == ['alpha', 'beta'] and keys([high, low], 'address') == ['beta', 'alpha']


@pytest.mark.parametrize('kind, delta, expected', [('advisory', False, 3), ('note', False, 3), ('string', False, 2),
                                                   ('string', True, 0)], ids=['adv', 'note', 'string', 'delta'])
def test_unpaired_change_class(kind, delta, expected):
    lone = lead(cand(kind=kind, tier=3))
    lone.delta = delta
    assert lone.change_class == (3 if kind in ('advisory', 'note') else expected)


@pytest.mark.parametrize('group, extra, origin', [
    ('fn', '', 'ghidra'), ('raw', '', 'ghidra'), ('pe:older', '', 'pe-parse'), ('ann', '', 'analyst'),
    ('fnd', 'model stale', 'model'), ('fnd', 'analyst', 'analyst'), ('tool:floss:newer', '', 'floss'),
    ('tool:capa:older', '', 'capa'), ('tool:diec:newer', '', 'diec'), ('adv', '', 'advisory'), ('cve', '', 'advisory'),
    ('rule', '', 'yara-x')], ids=lambda v: v or 'x')
def test_origin_of_groups(group, extra, origin):
    assert origin_of(group, extra) == origin


def test_reasons_state_unknown_attention_instead_of_zero():
    shown = rank_reasons(lead(cand(), m=match()), '')
    assert shown[-1] == 'attention/1 rank unavailable: run Rank changes'
    assert rank_reasons(lead(cand(), m=match('unchanged')), '')[-1].endswith('1 independent source: ghidra')
    assert all(len(reason) <= 120 for reason in shown)
