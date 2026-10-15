"""SPEC-32 s10 scoring on hand-computed match sets. Every engine output here is SYNTHETIC (hand-made predictions over
hand-made labels): it checks the arithmetic and the decision rules, and is never live engine evidence."""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402
from tools.calibration.tier_r import schemas as S  # noqa: E402

STRATA = {'authored': ('suite', 'authored-truth'), 'release': ('release-pair', 'source-diff'),
          'aa': ('aa-rebuild', 'same-source')}


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def make_labels(records, *, pair_id='syn-pair', stratum='authored', tag=None) -> C.KnownAnswerLabels:
    """records: (name, old, new, label[, identity]) tuples; sizes are 16 bytes."""
    method, source = STRATA[stratum]
    doc = copy.deepcopy(S.example_labels())
    tag = tag or pair_id
    for side, key in (('older', 'o'), ('newer', 'n')):
        doc[side]['sha256'], doc[side]['debug_sha256'] = sha(f'{tag}-{key}'), sha(f'{tag}-{key}-dbg')
    funcs = []
    for rec in records:
        name, old, new, label = rec[:4]
        identity = rec[4] if len(rec) > 4 else ('no-counterpart' if label == 'no-counterpart' else 'same')
        kind = {'changed': 'bounds-check-added', 'cosmetic': 'cosmetic'}.get(label)
        body = {'unchanged': 'identical', 'changed': 'different', 'cosmetic': 'address-only'}.get(label, 'n/a')
        if label == 'ambiguous':
            body = 'different'
        func = S._record(name, old, new, label, identity, kind, body)
        func['label_source'] = source
        funcs.append(func)
    doc.update(pair_id=pair_id, stratum=stratum, method=method, label_source=source, functions=funcs,
               case={'intent': 'synthetic scoring fixture'})
    return C.load_labels(C.dump_json(C.finalize_labels(doc)))


FUNCS = [('A', 0x1000, 0x1000, 'unchanged'), ('B', 0x1010, 0x1010, 'unchanged'), ('C', 0x1020, 0x1020, 'changed'),
         ('D', 0x1030, 0x1030, 'changed'), ('E', 0x1040, 0x1040, 'cosmetic'), ('F', 0x1050, 0x1050, 'cosmetic'),
         ('G', 0x1060, None, 'no-counterpart'), ('H', None, 0x1070, 'no-counterpart'),
         ('I', 0x1080, 0x1080, 'ambiguous', 'same')]


def pred(o, n, changed, milli=None):
    return E.Prediction(o, n, changed, milli)


def out(*preds, **kw):
    return E.EngineOutput('rz-diff', 'ok', predictions=tuple(preds), **kw)


def test_hand_computed_counts_and_ratios():
    labels = make_labels(FUNCS)
    preds = [pred(0x1000, 0x1000, False), pred(0x1010, 0x1010, True), pred(0x1020, 0x1020, True),
             pred(0x1030, 0x1030, False), pred(0x1040, 0x1040, True), pred(0x1050, 0x1050, False),
             pred(0x1060, 0x1070, True),      # G and H have no counterpart: wrong
             pred(0x1020, 0x1030, True),      # C's old with D's new: wrong
             pred(0x1080, 0x1080, False),     # ambiguous only: ignored
             pred(0x9000, 0x9000, False)]     # unlabelled: ignored
    counts, wrong = E.score_pair(labels, out(*preds))
    assert counts == {'pairs': 1, 'truth_same': 6, 'identity_tp': 6, 'identity_fp': 2, 'identity_fn': 0,
                      'changed_truth': 2, 'changed_tp': 1, 'changed_fp': 2, 'changed_fn': 1, 'matched_negatives': 4,
                      'cosmetic_matched': 2, 'cosmetic_flagged': 1, 'ignored_predictions': 2, 'ambiguous_records': 1}
    m = E.metrics_from_counts(counts)
    assert (m['identity_precision'], m['identity_recall']) == (0.75, 1.0)
    assert (m['changed_precision'], m['changed_recall'], m['fp_rate']) == (round(1 / 3, 12), 0.5, 0.5)
    assert sorted((w['kind'], w['old_rva'], w['new_rva']) for w in wrong) == [
        ('paired-no-counterpart', 0x1060, 0x1070), ('wrong-counterpart', 0x1020, 0x1030)]
    wc = next(w for w in wrong if w['kind'] == 'wrong-counterpart')
    assert (wc['expected_new_rva'], wc['expected_old_rva'], wc['old_name'], wc['new_name']) == (0x1020, 0x1030, 'C', 'D')


def test_missing_matches_lower_recall_not_precision():
    labels = make_labels(FUNCS)
    counts, wrong = E.score_pair(labels, out(pred(0x1000, 0x1000, False)))
    m = E.metrics_from_counts(counts)
    assert (counts['identity_tp'], counts['identity_fn'], wrong) == (1, 5, [])
    assert (m['identity_precision'], m['identity_recall']) == (1.0, round(1 / 6, 12))
    assert m['changed_recall'] is None and m['changed_precision'] is None   # no changed pair was matched


def test_empty_prediction_set_has_undefined_precision_and_zero_recall():
    m = E.metrics_from_counts(E.score_pair(make_labels(FUNCS), out())[0])
    assert (m['identity_precision'], m['identity_recall'], m['fp_rate']) == (None, 0.0, None)


def test_duplicate_predictions_count_once():
    counts, _ = E.score_pair(make_labels(FUNCS), out(pred(0x1000, 0x1000, False), pred(0x1000, 0x1000, True)))
    assert counts['identity_tp'] == 1 and counts['matched_negatives'] == 1 and counts['changed_fp'] == 0


def test_implicit_unchanged_for_listing_only_engines():
    """Ghidriff-style: only modified/added/deleted are listed; unmentioned truth pairs are matched and unchanged."""
    labels = make_labels(FUNCS)
    ghid = out(pred(0x1020, 0x1020, True), old_only=frozenset({0x1060}), new_only=frozenset({0x1070}),
               implicit_unchanged=True)
    counts, wrong = E.score_pair(labels, ghid)
    assert wrong == []
    assert (counts['identity_tp'], counts['identity_fp'], counts['identity_fn']) == (6, 0, 0)
    assert (counts['changed_tp'], counts['changed_fn'], counts['changed_fp'], counts['matched_negatives']) == (1, 1, 0, 4)
    # without the flag the same output only credits the one listed pair
    assert E.score_pair(labels, out(pred(0x1020, 0x1020, True)))[0]['identity_tp'] == 1


def test_micro_aggregation_differs_from_mean_of_ratios():
    p1 = make_labels([('A', 0x1000, 0x1000, 'unchanged')], pair_id='syn-one')
    p2 = make_labels([('A', 0x1000, 0x1000, 'unchanged'), ('B', 0x1010, 0x1010, 'unchanged')], pair_id='syn-two')
    r1 = out(pred(0x1000, 0x1000, False))                                     # 1 of 1 correct
    r2 = out(pred(0x1000, 0x1000, False), pred(0x1010, 0x2000, False), pred(0x2000, 0x1010, False))   # 1 of 3 correct
    provider = E.StaticProvider('rz-diff', {'syn-one': r1, 'syn-two': r2})
    report = E.evaluate([p1, p2], [provider])
    m = report['strata']['authored']['rz-diff']
    assert (m['identity_tp'], m['identity_fp'], m['truth_same']) == (2, 2, 3)
    assert m['identity_precision'] == 0.5          # micro 2/4, not mean(1.0, 1/3)
    per_pair = {p['pair_id']: p['metrics']['identity_precision'] for p in report['pairs']}
    assert per_pair == {'syn-one': 1.0, 'syn-two': round(1 / 3, 12)}


def test_strata_are_kept_apart():
    a = make_labels([('A', 0x1000, 0x1000, 'unchanged')], pair_id='syn-a', stratum='authored')
    r = make_labels([('A', 0x1000, 0x1000, 'unchanged')], pair_id='syn-r', stratum='release')
    provider = E.StaticProvider('rz-diff', {'syn-a': out(pred(0x1000, 0x1000, False)), 'syn-r': out()})
    report = E.evaluate([a, r], [provider])
    assert report['strata']['authored']['rz-diff']['identity_recall'] == 1.0
    assert report['strata']['release']['rz-diff']['identity_recall'] == 0.0


def _rz_json(entries):
    import json
    return json.dumps([{'similarity': sim, 'type': typ,
                        'original': None if o is None else {'addr': o, 'name': 'f', 'size': 16},
                        'modified': None if n is None else {'addr': n, 'name': 'f', 'size': 16}}
                       for sim, typ, o, n in entries])


@pytest.mark.parametrize('engine,sim,rz_type,flag', [
    ('rz-diff', 1.0, 'COMPLETE', False), ('rz-diff', 1.0, 'PARTIAL', True), ('rz-diff', 0.999, 'COMPLETE', True),
    ('bindiff', 1.0, None, False), ('bindiff', 0.9, None, True)],
    ids=['rz-same', 'rz-partial', 'rz-lt1', 'bd-1', 'bd-lt1'])
def test_changed_rule_per_engine(tmp_path, engine, sim, rz_type, flag):
    """Match sets come from the production rz-diff parser / BinDiff importer fed hand-made (synthetic) input."""
    from bindiff_builder import build

    from patchtrace.secondary import rzdiff
    from patchtrace.secondary.bindiff import import_bindiff
    if engine == 'rz-diff':
        ms = rzdiff.parse_output(_rz_json([(sim, rz_type, 0x180001000, 0x180001000)]), '0.9.1', 'a' * 64, 'b' * 64)
    else:
        path = build(tmp_path / 'x.BinDiff', functions=[(1, 0x180001000, 'f', 0x180001000, 'f', sim, 1.0, 0, 7)])
        ms = import_bindiff(path, 'a' * 64, 'b' * 64)
    result = E.from_match_set(engine, ms, 0x180000000)
    assert [(p.old_rva, p.new_rva, p.changed) for p in result.predictions] == [(0x1000, 0x1000, flag)]


@pytest.mark.parametrize('address,base,expected', [(0x180001000, 0x180000000, 0x1000), (0x1000, 0x180000000, 0x1000),
                                                   (0x180000000, 0x180000000, 0)], ids=['va', 'rva', 'base'])
def test_address_basis(address, base, expected):
    assert E.to_rva(address, base) == expected


def test_one_sided_rzdiff_entries_become_unmatched_sets():
    from patchtrace.secondary import rzdiff
    ms = rzdiff.parse_output(_rz_json([(0.0, 'UNLIKE', 0x180001060, None), (0.0, 'UNLIKE', None, 0x180001070)]),
                             '0.9.1', 'a' * 64, 'b' * 64)
    result = E.from_match_set('rz-diff', ms, 0x180000000)
    assert (result.predictions, result.old_only, result.new_only) == ((), frozenset({0x1060}), frozenset({0x1070}))
