"""LBL-11a evalcore scoring: protocols, identity outcomes, per-label change counts, descriptors (hand-computed)."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tools.calibration.evalcore import change, descriptors, identity, protocols
from tools.calibration.evalcore.protocols import EnginePair, EnginePairs


@dataclass(frozen=True)
class Rec:
    """Minimal TruthLabelLike."""
    old_rva: int | None
    new_rva: int | None
    label: str
    identity: str = 'same'
    name: str = 'f'
    old_size: int | None = None
    new_size: int | None = None
    taxonomy: tuple[str, ...] = ()


def P(old, new, flag=False, *, native=None, key=None, ident='paired'):
    return EnginePair(old, new, flag, native, key if key is not None else ((native or 0.0,) if flag else None), ident)


def pairs(*rows, implicit=False, engine='rz-diff'):
    return EnginePairs(engine, 'v', 'hidden', tuple(rows), implicit)


# ---- protocols -------------------------------------------------------------------------------------------

@pytest.mark.parametrize('args', [
    (1, None, None, None, None, 'paired'),
    (1, 1, True, None, None, 'paired'),
    (1, None, True, None, (0.5,), 'unpaired'),
    (1, 2, None, None, None, 'unpaired'),
    (None, None, None, None, None, 'abstained'),
    (1, 1, None, None, None, 'bogus'),
    (1, 1, False, None, ([],), 'paired'),
], ids=['paired-one-side', 'flag-no-key', 'unpaired-flag', 'unpaired-two-sides', 'abstained-empty', 'bogus',
        'bad-key-type'])
def test_engine_pair_invariants(args):
    with pytest.raises(ValueError):
        EnginePair(*args)


def test_engine_pairs_rejects_unknown_engine_and_symbols():
    with pytest.raises(ValueError):
        EnginePairs('ida', 'v', 'hidden', ())
    with pytest.raises(ValueError):
        EnginePairs('rz-diff', 'v', 'both', ())


def test_engine_pairs_from_doc_round_trip():
    doc = {'engine': 'unified', 'version': 'x', 'symbols': 'hidden', 'implicit_unchanged': False,
           'pairs': [{'old_rva': 1, 'new_rva': 1, 'identity': 'paired', 'flag': True, 'native': None,
                      'order_key': [0, -1, 1]},
                     {'old_rva': None, 'new_rva': 9, 'identity': 'unpaired', 'flag': None, 'native': None,
                      'order_key': None}]}
    got = protocols.pairs_from_doc(doc)
    assert got.pairs[0] == P(1, 1, True, key=(0, -1, 1))
    assert got.pairs[1] == P(None, 9, None, ident='unpaired')


# ---- identity outcomes -----------------------------------------------------------------------------------

def _outcome(record, *rows, implicit=False):
    (got,) = identity.classify([record], pairs(*rows, implicit=implicit))
    return got.outcome, got.flagged


@pytest.mark.parametrize('rows, implicit, expected', [
    ([P(10, 20, True, native=0.5)], False, ('paired-correct', True)),
    ([P(10, 20, False, native=1.0)], False, ('paired-correct', False)),
    ([P(10, 30, True, native=0.5)], False, ('paired-wrong', None)),
    ([P(11, 20, True, native=0.5)], False, ('paired-wrong', None)),
    ([P(10, 20, None, ident='paired')], False, ('abstained', None)),
    ([P(10, 20, None, ident='abstained')], False, ('abstained', None)),
    ([P(10, None, None, ident='unpaired')], False, ('unpaired', None)),
    ([], False, ('unpaired', None)),
    ([], True, ('paired-correct', False)),
    ([P(10, None, None, ident='unpaired')], True, ('unpaired', None)),
    ([P(10, 30, True, native=0.5), P(10, 20, True, native=0.4)], False, ('paired-correct', True)),
], ids=['correct-flag', 'correct-noflag', 'wrong-new', 'wrong-old', 'flag-abstain', 'id-abstain', 'unpaired',
        'unmentioned', 'implicit', 'implicit-but-unpaired', 'correct-wins'])
def test_same_record_outcomes(rows, implicit, expected):
    assert _outcome(Rec(10, 20, 'changed'), *rows, implicit=implicit) == expected


@pytest.mark.parametrize('rows, expected', [
    ([], 'unpaired'),
    ([P(None, 20, None, ident='unpaired')], 'unpaired'),
    ([P(5, 20, True, native=0.5)], 'paired-wrong'),
    ([P(None, 20, None, ident='abstained')], 'abstained'),
], ids=['unmentioned', 'unpaired-row', 'paired-wrong', 'abstained'])
def test_no_counterpart_outcomes(rows, expected):
    assert _outcome(Rec(None, 20, 'no-counterpart', 'no-counterpart'), *rows)[0] == expected


def test_old_only_no_counterpart_matches_old_side():
    assert _outcome(Rec(10, None, 'no-counterpart', 'no-counterpart'), P(10, 30, True, native=0.1))[0] == 'paired-wrong'


def test_ambiguous_truth_is_never_scored():
    for rec in (Rec(10, 20, 'ambiguous', 'ambiguous'), Rec(10, 20, 'ambiguous', 'same')):
        assert _outcome(rec, P(10, 20, True, native=0.5)) == ('abstained', None)


def test_classify_keeps_input_order():
    recs = [Rec(1, 1, 'unchanged'), Rec(2, 2, 'changed'), Rec(None, 3, 'no-counterpart', 'no-counterpart')]
    got = identity.classify(recs, pairs(P(2, 2, True, native=0.1)))
    assert [g.record for g in got] == recs
    assert [g.outcome for g in got] == ['unpaired', 'paired-correct', 'unpaired']


# ---- per-label counts ------------------------------------------------------------------------------------

def test_count_by_label_golden():
    recs = [Rec(1, 1, 'unchanged'), Rec(2, 2, 'unchanged'), Rec(3, 3, 'unchanged'), Rec(4, 4, 'unchanged'),
            Rec(5, 5, 'changed'), Rec(6, 6, 'changed'), Rec(7, 7, 'cosmetic'),
            Rec(None, 8, 'no-counterpart', 'no-counterpart'), Rec(9, 9, 'ambiguous', 'ambiguous')]
    rows = [P(1, 1, True, native=0.9), P(2, 2, False, native=1.0), P(3, 99, True, native=0.2),
            P(5, 5, True, native=0.3), P(6, 6, None), P(7, 7, True, native=0.97)]
    counts = change.count_by_label(identity.classify(recs, pairs(*rows)))
    assert set(counts) == set(change.LABELS)
    u = counts['unchanged']
    assert (u.paired_correct, u.paired_wrong, u.unpaired, u.abstained, u.flagged) == (2, 1, 1, 0, 1)
    c = counts['changed']
    assert (c.paired_correct, c.abstained, c.flagged) == (1, 1, 1)
    assert counts['cosmetic'].flagged == 1 and counts['no-counterpart'].unpaired == 1
    assert counts['ambiguous'].abstained == 1
    assert change.flag_rate(u) == 0.5 and change.flag_rate(c) == 1.0
    assert change.flag_rate(counts['no-counterpart']) is None and change.flag_rate(counts['ambiguous']) is None


def test_flag_rate_undefined_without_paired_correct():
    assert change.flag_rate(change.LabelCount(0, 3, 0, 0, 0)) is None


def test_merge_counts_adds_per_label():
    a = change.count_by_label(identity.classify([Rec(1, 1, 'unchanged')], pairs(P(1, 1, True, native=0.5))))
    b = change.count_by_label(identity.classify([Rec(1, 1, 'unchanged')], pairs(P(1, 1, False, native=1.0))))
    got = change.merge_counts([a, b])['unchanged']
    assert (got.paired_correct, got.flagged) == (2, 1) and change.flag_rate(got) == 0.5


# ---- flagged order ---------------------------------------------------------------------------------------

def test_flagged_ranks_ties_get_midrank_and_unflagged_excluded():
    rows = [P(1, 1, True, key=(0.5,)), P(2, 2, True, key=(0.5,)), P(3, 3, True, key=(0.1,)), P(4, 4, False),
            P(5, None, None, ident='unpaired')]
    ranks = change.flagged_ranks(pairs(*rows))
    assert ranks == {(3, 3): 1.0, (1, 1): 2.5, (2, 2): 2.5}
    assert change.pool_size(pairs(*rows)) == 3


def test_flagged_ranks_independent_of_row_order():
    rows = [P(i, i, True, key=(i % 2, i)) for i in range(1, 7)]
    assert change.flagged_ranks(pairs(*rows)) == change.flagged_ranks(pairs(*reversed(rows)))


# ---- descriptors -----------------------------------------------------------------------------------------

def test_quantiles_hand_computed():
    q = descriptors.quantiles([5, 1, 3, 2, 4])
    assert (q.n, q.q05, q.q25, q.q50, q.q75, q.q95) == (5, pytest.approx(1.2), 2, 3, 4, pytest.approx(4.8))
    assert descriptors.quantiles([7]).q50 == 7 and descriptors.quantiles([]).q50 is None


def test_percentile_even_count_interpolates():
    assert descriptors.percentile([1, 2, 3, 4], 50) == 2.5


def test_descriptor_flags():
    lo_hi = (16.0, 100.0)
    assert descriptors.descriptor_flags(Rec(1, 1, 'unchanged', old_size=50, new_size=60), lo_hi) == ()
    assert descriptors.descriptor_flags(Rec(1, 1, 'unchanged', old_size=50, new_size=101), lo_hi) == ('size-outside',)
    assert descriptors.descriptor_flags(Rec(1, 1, 'unchanged', old_size=8, new_size=8, taxonomy=('N2', 'N9')),
                                        lo_hi) == ('size-outside', 'thunk', 'n9')
    assert descriptors.descriptor_flags(Rec(None, 1, 'no-counterpart', new_size=50), lo_hi) == ()


# ---- invariants ------------------------------------------------------------------------------------------

_rows = st.lists(st.tuples(st.integers(0, 5), st.integers(0, 5), st.sampled_from([True, False, None])),
                 max_size=12, unique_by=lambda t: (t[0], t[1]))


@given(_rows, st.booleans(), st.randoms(use_true_random=False))
def test_label_counts_partition_the_records_whatever_the_row_order(rows, implicit, rnd):
    recs = [Rec(i, i, 'unchanged') for i in range(6)] + [Rec(None, 9, 'no-counterpart', 'no-counterpart')]
    built = [P(o, n, f, native=0.5) for o, n, f in rows]
    shuffled = list(built)
    rnd.shuffle(shuffled)
    a = identity.classify(recs, pairs(*built, implicit=implicit))
    assert a == identity.classify(recs, pairs(*shuffled, implicit=implicit))
    counts = change.count_by_label(a)
    assert sum(c.paired_correct + c.paired_wrong + c.unpaired + c.abstained for c in counts.values()) == len(recs)
    assert all(c.flagged <= c.paired_correct for c in counts.values())
