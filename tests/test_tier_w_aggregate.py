"""LBL-24: Tier-W evaluator and aggregate (SPEC-33 s10, LBL s8.2). Hand-computed goldens; synthetic labels only."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace as NS

import pytest
from tier_w_builders import ROOT

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import aggregate as G  # noqa: E402
from tools.calibration.tier_w import evaluate as E  # noqa: E402
from tools.calibration.tier_w.audit import AuditReport, StratumResult  # noqa: E402
from tools.calibration.tier_w.contracts import PairBinary, PairEntry, PairsDoc  # noqa: E402
from tools.calibration.tier_w.guard import tier_w_problems  # noqa: E402


def lab(pair, o, n, answer='same', tags=(), source='symbol-derived'):
    return E.TruthLabel(pair, o, n, answer, source, tags)


def m(pair, o, n, engine='e1', condition='symbols-hidden'):
    return NS(pair=pair, engine=engine, condition=condition, older_rva=o, newer_rva=n)


def test_wilson_golden():
    lo, hi = E.wilson(5, 10)
    assert (round(lo, 3), round(hi, 3)) == (0.237, 0.763)
    assert E.wilson(0, 0) is None and E.wilson(0, 10)[0] == 0.0 and E.wilson(10, 10)[1] == pytest.approx(1.0)


def test_scoring_golden():
    labels = [lab('p1', 1, 10, tags=('exported',)), lab('p1', 2, 20, tags=('N2',)), lab('p1', 3, 30),
              lab('p1', 4, 40, 'different')]
    matches = [m('p1', 1, 10), m('p1', 2, 21), m('p1', 4, 40), m('p1', 5, 50), m('p1', 3, 30)]
    cell = E.evaluate(labels, matches, {'p1': 'L1'})['cells']['e1']['symbols-hidden']
    o = cell['overall']
    # correct (1,10) and (3,30); wrong (2,21) (older endpoint has another counterpart) and (4,40) (labelled different)
    assert (o['correct'], o['wrong'], o['unscored'], o['truth'], o['found']) == (2, 2, 1, 3, 2)
    assert o['precision'] == 0.5 and o['recall'] == pytest.approx(2 / 3) and o['f1'] == pytest.approx(4 / 7)
    assert cell['tags']['exported']['precision'] == 1.0 and cell['tags']['exported']['truth'] == 1
    ne = cell['tags']['non-exported']
    assert (ne['correct'], ne['wrong'], ne['truth'], ne['found']) == (1, 2, 2, 1)
    assert cell['tags']['N2']['wrong'] == 1 and cell['lineages']['L1']['correct'] == 2
    assert cell['tag_lineages']['exported']['L1']['truth'] == 1


def test_no_matches_and_no_wrong_give_none_not_zero():
    cell = E.evaluate([lab('p', 1, 2)], [m('p', 9, 9)])['cells']['e1']['symbols-hidden']['overall']
    assert cell['precision'] is None and cell['recall'] == 0.0 and cell['f1'] is None


def test_symbol_labels_never_score_a_visible_run():
    labels = [lab('p', 1, 2)]
    doc = E.evaluate(labels, [m('p', 1, 2, condition='symbols-visible'), m('p', 1, 2, condition='n/a')])
    assert doc['cells']['e1']['symbols-visible'] == {'status': 'insufficient-labels', 'reason': 'circular'}
    assert doc['cells']['e1']['n/a']['status'] == 'scored'
    manual = [lab('p', 1, 2, source='manual')]
    assert E.evaluate(manual, [m('p', 1, 2, condition='symbols-visible')])['cells']['e1']['symbols-visible'][
        'status'] == 'scored'


def test_engines_never_pooled():
    labels = [lab('p', 1, 2), lab('p', 3, 4)]
    doc = E.evaluate(labels, [m('p', 1, 2, 'a'), m('p', 3, 4, 'a'), m('p', 1, 2, 'b'), m('p', 7, 7, 'b')])
    assert set(doc['cells']) == {'a', 'b'} and doc['method']['pooled'] is False
    assert doc['cells']['a']['symbols-hidden']['overall']['recall'] == 1.0
    assert doc['cells']['b']['symbols-hidden']['overall']['recall'] == 0.5


# ---- aggregate ------------------------------------------------------------------------------------------------------

def big_world(lineages=3):
    labels, matches, lineage_of = [], [], {}
    for i in range(lineages):
        pair = f'tw.secret{i}'
        lineage_of[pair] = f'L{i}'
        for j in range(40):
            labels.append(lab(pair, j, j + 1000, tags=('exported',) if j < 10 else ()))
            if j % 10:
                matches.append(m(pair, j, j + 1000))
            if j < 4:
                matches.append(m(pair, j, j + 2000))  # wrong: older endpoint belongs to another counterpart
    small = 'tw.small'
    lineage_of[small] = 'L0'
    for j in range(5):
        labels.append(lab(small, 5000 + j, 6000 + j, tags=('N2',)))
        matches.append(m(small, 5000 + j, 6000 + j))
    return labels, matches, lineage_of


def classes():
    return {k: G.ClassCount(families=1, pairs=2, lineages=1, candidates=3) for k in G.CLASSES}


def build(**kw):
    labels, matches, lineage_of = big_world()
    evaluation = E.evaluate(labels, matches, lineage_of)
    return G.aggregate(evaluation, classes=classes(), b_count=50, **kw), evaluation


def test_aggregate_golden_and_suppression():
    doc, _ = build()
    cells = doc.metrics['e1']['symbols-hidden']
    overall = cells['all']
    # per lineage: 40 truth, 36 correct, 4 wrong; the 5 small-pair matches are all correct
    assert (overall.truth, overall.scored, overall.found) == (125, 125, 113)
    assert overall.precision == pytest.approx(113 / 125) and overall.recall == pytest.approx(113 / 125)
    assert overall.precision_lineage.n_lineages == 3 and overall.precision_lineage.anti_conservative is True
    assert 'N2' not in cells and doc.suppressed_cells == 1  # 5 truth pairs < 30
    assert cells['exported'].truth == 30 and cells['exported'].scored == 39
    assert cells['non-exported'].truth == 95
    assert doc.min_cell == 30


def test_every_published_cell_has_n_at_least_30():
    doc, _ = build()
    for conditions in doc.metrics.values():
        for cells in conditions.values():
            assert all(c.scored >= 30 and c.truth >= 30 for c in cells.values() if isinstance(c, G.MetricCell))


def test_deterministic_and_hash_covers_content():
    a, evaluation = build()
    b, _ = build()
    assert a.report_sha256 == b.report_sha256 and G.to_json(a) == G.to_json(b)
    c = G.aggregate(evaluation, classes=classes(), b_count=50, tools={'ghidra': '12.0.4'})
    assert c.report_sha256 != a.report_sha256


def test_no_pooling_in_aggregate():
    labels, matches, lineage_of = big_world()
    half = [x for x in matches if x.older_rva % 2 == 0]
    both = matches + [NS(**{**vars(x), 'engine': 'e2'}) for x in half]
    doc = G.aggregate(E.evaluate(labels, both, lineage_of), classes=classes(), b_count=20)
    assert set(doc.metrics) == {'e1', 'e2'}
    assert doc.metrics['e1']['symbols-hidden']['all'].found != doc.metrics['e2']['symbols-hidden']['all'].found
    assert not any('all-engines' in k or 'pooled' in k for k in doc.metrics)


def test_circular_cell_passes_through():
    labels, _, _ = big_world()
    doc = G.aggregate(E.evaluate(labels, [m('p', 1, 2, condition='symbols-visible')]), classes=classes(), b_count=10)
    assert doc.metrics['e1']['symbols-visible']['all'].status == 'insufficient-labels'


def test_output_has_no_names_pairs_or_rvas():
    doc, _ = build()
    text = G.to_json(doc).decode() + G.render_markdown(doc)
    assert 'secret' not in text and 'tw.' not in text and '"older_rva"' not in text
    assert G.BANNER in text and 'Local only (O1)' in text and '(headline)' in text


def test_audit_and_shift_blocks():
    report = AuditReport(
        contract='tier-w-audit-report/1', tier='W', corpus_id='tw-c', population='candidates',
        strata={'census': StratumResult(population=2, reviewed=2, indeterminate=0, errors=0, error=0.0, upper=0.7),
                'random': StratumResult(population=98, reviewed=40, indeterminate=0, errors=0, error=0.0, upper=0.07)},
        unknown_items=0, symbol_audit_error=0.0, symbol_audit_error_upper=0.08, reviewed=42, indeterminate=0,
        status='ok')
    doc, evaluation = build(audit=report, shift={'q50': 0.1, 'q90': 0.4})
    assert (doc.audit.status, doc.audit.n, doc.audit.upper) == ('ok', 42, 0.08) and doc.shift == {'q50': 0.1, 'q90': 0.4}
    assert G.aggregate(evaluation, classes=classes(), b_count=10).audit.status == 'missing'
    with pytest.raises(ValueError):
        G.aggregate({'contract': 'x'}, classes=classes())


def test_free_text_cannot_enter_tools():
    _, evaluation = build()
    with pytest.raises(ValueError):
        G.aggregate(evaluation, classes=classes(), tools={'x': 'C:\\Windows\\System32\\ntdll.dll'}, b_count=10)


def test_class_counts_from_pairs_doc():
    def binary(i, name, family):
        return PairBinary(id=f'b{i}', file_name=name, sha256=f'{i:064x}', record_sha256=f'{i:064x}', family=family)

    def pair(i, older, newer, name):
        return PairEntry(id=f'tw.{i}', older=older, newer=newer, kind='adjacent-patch', file_name=name, lines=('l',),
                         older_kbs=(), newer_kbs=(), older_date=None, newer_date=None, tags=())
    pairs = PairsDoc(
        contract='tier-w-pairs/1', tier='W', corpus_id='tier-w-c', created='', params={},
        binaries=(binary(1, 'a.sys', 'driver'), binary(2, 'a.sys', 'driver'), binary(3, 'b.dll', 'usermode-dll'),
                  binary(4, 'b.dll', 'usermode-dll')),
        pairs=(pair(1, 'b1', 'b2', 'a.sys'), pair(2, 'b3', 'b4', 'b.dll'), pair(3, 'b3', 'b4', 'b.dll')),
        exclusions={}, coverage={'classes': ('driver',), 'files_with_pairs': (), 'complete': False,
                                 'allow_incomplete': True})
    out = G.class_counts(pairs, {'tw.1': 7, 'tw.3': 2})
    assert out['driver'] == G.ClassCount(families=1, pairs=1, lineages=1, candidates=7)
    assert out['usermode-dll'] == G.ClassCount(families=1, pairs=2, lineages=1, candidates=2)
    assert out['kernel'] == G.ClassCount(families=0, pairs=0, lineages=0, candidates=0)


def test_aggregate_json_is_caught_by_the_guard(tmp_path):
    doc, _ = build()
    path = tmp_path / 'aggregate.json'
    path.write_bytes(G.to_json(doc))
    assert json.loads(path.read_text())['contract'] == 'tier-w-aggregate/1'
    assert any('tier-w-aggregate/1' in p for p in tier_w_problems(tmp_path, ['aggregate.json']))
