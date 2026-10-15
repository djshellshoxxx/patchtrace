"""SPEC-31 S6c: the evaluators of G-U3 (L1 precision), G-U6 (noise against legacy) and G-U7 (independence) over
`unified-outcomes/1`. Pure and hermetic: label documents come from the SPEC-32 contract, rows are written by hand with the
truth already joined (the join itself is tested at the end with stand-ins for stored rows)."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS), str(ROOT / 'src')]
from unified_s6_helpers import label_doc, mutation_doc  # noqa: E402

from tools.unified import cluster, gates_u, outcomes, rowgates  # noqa: E402
from tools.unified.corpus import manifest as corpus_manifest  # noqa: E402

Basis, R = outcomes.Basis, outcomes.OutcomeRow


def basis(tier='A', step='P04-exact-bytes', cls='E-BODY', component='K02', source='pt-ladder'):
    return Basis(component=component, tier=tier, cls=cls, source=source, step=step)


def row(i=0, *, truth='right', tier='A', materiality='unchanged', decision='matched', edited='not-edited', legacy=(),
        step='P04-exact-bytes', supports=None, ghidriff_exact=False):
    rva = 0x1000 + 16 * i
    return R(older=(rva,), newer=(rva,), decision=decision, materiality=materiality, truth=truth, edited=edited,
             legacy=tuple(legacy), basis=tuple(supports) if supports is not None else (basis(tier, step),),
             ghidriff_exact=ghidriff_exact)


def pair(doc, rows, legacy_tools=()):
    return outcomes.collect_rows(rows, doc, legacy_tools=legacy_tools)


def run(*pairs, name='linux'):
    return outcomes.build(name, 'Linux-6', pairs)


def gate(manifest, built, gid):
    report = gates_u.build_report(gates_u.Inputs(manifest=manifest, outcomes=[built]))
    return {g.id: g for g in report.gates}[gid]


def releases(n, kind='release'):
    return [label_doc(f'rel-{i}', kind, project=f'p{i}') for i in range(n)]


# ---- the interval -----------------------------------------------------------------------------------------------------------

def test_cluster_interval_resamples_whole_lineages_and_is_deterministic():
    groups = {f'L{i}': (20.0, 20.0) for i in range(30)}
    groups['L0'] = (10.0, 20.0)
    stat = lambda s: s[0] / s[1]                                         # noqa: E731
    one, two = cluster.ci(groups, stat, seed='t', b_count=200), cluster.ci(groups, stat, seed='t', b_count=200)
    assert one == two and one['groups'] == 30 and one['anti_conservative'] is False
    assert one['lo'] < one['point'] <= one['hi'] <= 1.0
    assert cluster.ci({'a': (1.0, 1.0)}, stat, seed='t', b_count=50)['anti_conservative'] is True
    assert cluster.ci({}, stat, seed='t')['point'] is None


# ---- G-U3 -------------------------------------------------------------------------------------------------------------------

def g3_inputs(n_lineages=31, wrong_in=(), rows_per=20, wrong_n=5, **row_args):
    docs = releases(n_lineages)
    pairs = [pair(d, [row(i, truth='wrong' if (k in wrong_in and i < wrong_n) else 'right', **row_args) for i in range(rows_per)])
             for k, d in enumerate(docs)]
    return corpus_manifest.build(docs, {}), pairs


def test_g_u3_clean_precision_over_enough_lineages_leaves_only_the_bindiff_oracle_blocked():
    manifest, pairs = g3_inputs()
    g = gate(manifest, run(*pairs), 'G-U3')
    assert g.status == 'blocked' and 'bindiff' in g.reasons[0].lower()
    assert g.observed['rows'] == 620 and g.observed['precision']['point'] == 1.0
    assert g.observed['precision']['groups'] == 31 and g.observed['per_pass']['pt-ladder:P04-exact-bytes']['rows'] == 620


def test_g_u3_precision_below_the_point_threshold_fails_and_names_the_numbers():
    manifest, pairs = g3_inputs(wrong_in=range(31), rows_per=20)             # 5 of 20 wrong everywhere
    g = gate(manifest, run(*pairs), 'G-U3')
    assert g.status == 'fail' and any('precision 0.7500' in r for r in g.reasons)


def test_g_u3_a_point_estimate_above_the_bar_with_a_low_interval_still_fails():
    manifest, pairs = g3_inputs(wrong_in=(0,), rows_per=200, wrong_n=30)      # 30 wrong of 6200: 0.9952, all in one lineage
    g = gate(manifest, run(*pairs), 'G-U3')
    assert g.observed['precision']['point'] >= rowgates.PRECISION_MIN
    assert g.status == 'fail' and any('lower bound' in r for r in g.reasons)


def test_g_u3_fewer_than_thirty_lineages_cannot_decide():
    manifest, pairs = g3_inputs(n_lineages=5)
    g = gate(manifest, run(*pairs), 'G-U3')
    assert g.status == 'insufficient-data' and any('anti-conservative' in r for r in g.reasons)


def test_g_u3_a_pair_without_an_outcome_or_without_known_rows_is_insufficient_never_a_pass():
    manifest, pairs = g3_inputs()
    assert gate(manifest, run(*pairs[:-1]), 'G-U3').status == 'insufficient-data'
    unknown = [pair(d, [row(0, truth='unknown')]) for d in releases(31)]
    assert gate(manifest, run(*unknown), 'G-U3').status == 'insufficient-data'


def test_g_u3_a_ladder_pass_whose_interval_starts_below_98_percent_is_listed_for_demotion():
    docs = releases(31)
    pairs = []
    for k, d in enumerate(docs):
        rows = [row(i) for i in range(30)]
        if k < 4:
            rows += [row(30 + i, truth='wrong' if i < 2 else 'right', step='P10-md-flowgraph', tier='B') for i in range(10)]
        pairs.append(pair(d, rows))
    g = gate(corpus_manifest.build(docs, {}), run(*pairs), 'G-U3')
    assert 'pt-ladder:P10-md-flowgraph' in g.observed['demote'] and 'pt-ladder:P04-exact-bytes' not in g.observed['demote']


def aa_docs():
    return [label_doc('aa-p0', 'aa'), label_doc('aa-p1', 'aa', method='aa-layout', project='q')]


def test_g_u3_a_tier_a_pair_the_truth_contradicts_on_an_aa_pair_fails():
    manifest, pairs = g3_inputs()
    docs = aa_docs()
    manifest = corpus_manifest.build([*releases(31), *docs], {})
    bad = pair(docs[0], [row(0, truth='wrong', tier='A'), row(1)])
    ok = pair(docs[1], [row(0)])
    g = gate(manifest, run(*pairs, bad, ok), 'G-U3')
    assert g.status == 'fail' and len(g.observed['tier_a_contradicted']) == 1
    soft = pair(docs[0], [row(0, truth='wrong', tier='B'), row(1)])             # a tier-B error is G-U7's business
    assert gate(manifest, run(*pairs, soft, ok), 'G-U3').status == 'blocked'


def test_g_u3_a_ghidriff_exact_pair_must_be_matched_or_contested_on_an_aa_pair():
    manifest, pairs = g3_inputs()
    docs = aa_docs()
    manifest = corpus_manifest.build([*releases(31), *docs], {})
    ok = pair(docs[1], [row(0)])
    for decision, expected in (('matched', 'blocked'), ('contested', 'blocked'), ('tentative', 'fail'),
                               ('older-only', 'fail')):
        shaky = pair(docs[0], [row(0, decision=decision, ghidriff_exact=True)])
        assert gate(manifest, run(*pairs, shaky, ok), 'G-U3').status == expected, decision


# ---- G-U6 -------------------------------------------------------------------------------------------------------------------

def g6_corpus(lineages=2):
    return [mutation_doc(f'mut-constant-{i:02d}', target='ka_constant_00') for i in range(lineages)]


def g6_pair(doc, *, unified_false=0, legacy_false=5, planted_unified='material', planted_legacy=True, tool='ghidriff'):
    rows = [row(i, materiality='material' if i < unified_false else 'unchanged',
                legacy=(tool,) if i < legacy_false else ()) for i in range(10)]
    rows.append(R(older=(0x1200,), newer=(0x1200,), decision='matched', materiality=planted_unified, truth='right',
                  edited='edited', legacy=(tool,) if planted_legacy else ()))
    return pair(doc, rows, legacy_tools=(tool,))


def g6(**args):
    docs = g6_corpus()
    return gate(corpus_manifest.build(docs, {}), run(*(g6_pair(d, **args) for d in docs)), 'G-U6')


def test_g_u6_fewer_material_false_leads_at_equal_recall_passes_with_the_numbers():
    g = g6(unified_false=2, legacy_false=5)                                  # 4 against 10: a 60 % reduction
    assert g.status == 'pass'
    tool = g.observed['per_tool']['ghidriff']
    assert (tool['false_leads_unified'], tool['false_leads_legacy'], tool['planted']) == (4, 10, 2)
    assert tool['reduction']['point'] == 0.6 and tool['recall_unified'] == tool['recall_legacy'] == 1.0
    assert g.observed['not_supplied'] == ['bindiff', 'rz-diff']


def test_g_u6_a_reduction_below_20_percent_fails_and_exactly_20_percent_passes():
    assert g6(unified_false=5, legacy_false=5).status == 'fail'
    assert g6(unified_false=4, legacy_false=5).status == 'pass'               # 8 against 10
    low = g6(unified_false=5, legacy_false=5)
    assert any('below 20%' in r for r in low.reasons)


def test_g_u6_lower_planted_recall_than_the_legacy_output_fails_even_with_fewer_false_leads():
    g = g6(unified_false=0, legacy_false=5, planted_unified='cosmetic')
    assert g.status == 'fail' and any('recall fell' in r for r in g.reasons)
    assert g6(unified_false=0, legacy_false=5, planted_unified='review').status == 'pass'


def test_g_u6_a_legacy_output_without_false_leads_cannot_be_beaten_by_20_percent():
    assert g6(unified_false=0, legacy_false=0).status == 'insufficient-data'
    assert g6(unified_false=1, legacy_false=0).status == 'fail'


def test_g_u6_no_legacy_output_or_a_missing_pair_is_insufficient_and_absence_is_no_vote():
    docs = g6_corpus()
    manifest = corpus_manifest.build(docs, {})
    plain = [pair(d, [row(0)]) for d in docs]                                # no legacy tool ran
    assert gate(manifest, run(*plain), 'G-U6').status == 'insufficient-data'
    assert gate(manifest, run(g6_pair(docs[0])), 'G-U6').status == 'insufficient-data'


# ---- G-U7 -------------------------------------------------------------------------------------------------------------------

def bb(k1='K02', k2='K05', c1='E-BODY', c2='E-CFG'):
    return (basis('B', 'P08', c1, k1), basis('B', 'P10', c2, k2))


def g7_pair(doc, tier_a=(100, 1), pairs=None):
    rows = [row(i, truth='wrong' if i < tier_a[1] else 'right') for i in range(tier_a[0])]
    offset = tier_a[0]
    for (k1, k2), (n, wrong) in (pairs or {}).items():
        rows += [row(offset + i, truth='wrong' if i < wrong else 'right', supports=bb(k1, k2)) for i in range(n)]
        offset += n
    return pair(doc, rows)


def g7(**args):
    doc = label_doc('rel', 'release')
    return gate(corpus_manifest.build([doc], {}), run(g7_pair(doc, **args)), 'G-U7')


def test_g_u7_a_class_pair_no_worse_than_twice_the_tier_a_error_rate_passes():
    g = g7(pairs={('K02', 'K05'): (40, 0), ('K03', 'K05'): (50, 1)})        # tier A: 1 %, bound 2 %
    assert g.status == 'pass'
    assert g.observed['tier_a'] == {'rows': 100, 'error_rate': 0.01}
    assert g.observed['class_pairs']['K02+K05|E-BODY+E-CFG']['status'] == 'pass'
    assert g.observed['class_pairs']['K03+K05|E-BODY+E-CFG']['bound'] == 0.02


def test_g_u7_a_class_pair_over_twice_the_tier_a_rate_fails_and_asks_for_a_join_by_configuration():
    g = g7(pairs={('K02', 'K05'): (40, 0), ('K03', 'K05'): (40, 3)})
    assert g.status == 'fail' and any('K03+K05' in r and 'join' in r and 'configuration' in r for r in g.reasons)
    assert g.observed['class_pairs']['K02+K05|E-BODY+E-CFG']['status'] == 'pass'


def test_g_u7_a_class_pair_with_fewer_than_30_rows_is_insufficient_data_never_safe():
    g = g7(pairs={('K02', 'K05'): (40, 0), ('K03', 'K05'): (29, 0)})
    assert g.status == 'insufficient-data'
    assert g.observed['class_pairs']['K03+K05|E-BODY+E-CFG'] == {'rows': 29, 'status': 'insufficient-data'}
    assert g7(pairs={('K03', 'K05'): (30, 0)}).status == 'pass'


def test_g_u7_without_tier_a_rows_or_b_plus_b_rows_there_is_nothing_to_compare():
    assert g7(tier_a=(0, 0), pairs={('K02', 'K05'): (40, 0)}).status == 'insufficient-data'
    assert g7(pairs={}).status == 'insufficient-data'


def test_g_u7_only_rows_supported_by_exactly_two_tier_b_atoms_form_a_class():
    assert rowgates.class_key(row(supports=bb())) == 'K02+K05|E-BODY+E-CFG'
    assert rowgates.class_key(row(supports=bb('K05', 'K02', 'E-CFG', 'E-BODY'))) == 'K02+K05|E-BODY+E-CFG'
    assert rowgates.class_key(row(supports=(*bb(), basis('B', cls='E-DATA')))) is None
    assert rowgates.class_key(row(supports=(basis('A'), basis('B')))) is None


# ---- the join of stored rows to the labels ------------------------------------------------------------------------------------

def stored(older, newer, *, decision='matched', materiality='unchanged', atoms=(), support=(), match_id=None):
    return SimpleNamespace(row_id='r' * 64, older=[SimpleNamespace(rva=r) for r in older],
                           newer=[SimpleNamespace(rva=r) for r in newer], decision=decision, materiality=materiality,
                           atoms=list(atoms), support=list(support), ghidriff_match_id=match_id)


def test_truth_judges_one_to_one_rows_against_the_label_document():
    truth = outcomes.Truth(label_doc('rel', 'release', target='ka_t'))        # f0 0x1000, f1 0x1100, ka_t 0x1200 (changed)
    assert truth.judge((0x1000,), (0x1000,)) == ('right', 'not-edited')
    assert truth.judge((0x1000,), (0x1100,)) == ('wrong', 'not-edited')
    assert truth.judge((0x1200,), (0x1200,)) == ('right', 'edited')
    assert truth.judge((0x9000,), (0x1100,)) == ('wrong', '')
    assert truth.judge((0x9000,), (0x9000,)) == ('unknown', '')
    assert truth.judge((0x1000, 0x1100), (0x1000,)) == ('', '')


def test_collect_joins_supports_atoms_truth_and_legacy_flags_without_recomputing_a_verdict():
    atoms = [SimpleNamespace(source='pt-ladder', step='P04-exact-bytes', tier='A', cls='E-BODY'),
             SimpleNamespace(source='ghidriff', step='SymbolsHash', tier='A', cls='E-NAME')]
    support = [SimpleNamespace(component='K02', tier='A', atom_index=0)]
    match = stored((0x1000,), (0x1000,), atoms=atoms, support=support, match_id='m1')
    got = outcomes.collect([match], label_doc('rel', 'release'), flagged={'ghidriff': frozenset({'m1'}), 'bindiff': frozenset()})
    only = got.rows[0]
    assert (only.truth, only.edited, only.ghidriff_exact, only.legacy) == ('right', 'not-edited', True, ('ghidriff',))
    assert [(b.component, b.tier, b.cls, b.source, b.step) for b in only.basis] == [
        ('K02', 'A', 'E-BODY', 'pt-ladder', 'P04-exact-bytes')]
    assert got.legacy_tools == ('bindiff', 'ghidriff')
    assert outcomes.load(outcomes.dump(run(got))).pairs[0].rows == got.rows
