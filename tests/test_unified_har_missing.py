"""SPEC-31 harness audit (card har): no gate passes on missing, stale, duplicated or verdict-less data (08 s1 rules)."""
from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS), str(ROOT / 'src')]
from unified_s6_helpers import label_doc  # noqa: E402

from tools.unified import evaluators, outcomes, rowgates  # noqa: E402
from tools.unified.corpus import manifest as corpus_manifest  # noqa: E402

R = outcomes.OutcomeRow


def ge():
    import test_unified_gate_eval as module  # helpers only
    return module


def late(pair_id: str) -> bool:
    return int(pair_id.rsplit('-', 1)[1]) >= 20


def test_g_u2_mutants_of_the_manifest_without_an_outcome_make_the_gate_insufficient_never_a_pass():
    g = ge()
    manifest = g.mut_manifest(25)                                    # 25 mutants per class in the manifest
    skip = {d.pair_id for d in g.mutants(25) if late(d.pair_id)}
    status, reasons, observed = evaluators.g_u2(manifest, [g.mut_run(25, skip=skip)])    # outcomes for 20 per class only
    assert status == 'insufficient-data' and any('without an outcome' in r for r in reasons)
    assert all(v['manifest'] == 25 and v['mutants'] == 20 for v in observed['classes'].values())
    assert evaluators.g_u2(manifest, [g.mut_run(25)])[0] == 'pending'     # complete data: only the pending classes wait


def test_g_u2_recall_is_compared_exactly_not_after_rounding():
    assert evaluators.recall_ok(19, 20) and not evaluators.recall_ok(18, 20)
    assert not evaluators.recall_ok(94_999, 100_000) and evaluators.recall_ok(95_000, 100_000)
    assert not evaluators.recall_ok(0, 0)


def test_g_u2_an_outcome_built_from_other_labels_than_the_manifest_is_not_evidence():
    g = ge()
    manifest = g.mut_manifest(20)
    good = g.mut_run(20)
    forged = [p.model_copy(update={'labels_sha256': 'e' * 64}) if p.pair_id.startswith('mut-constant-') else p
              for p in good.pairs]
    status, reasons, _ = evaluators.g_u2(manifest, [good.model_copy(update={'pairs': tuple(forged)})])
    assert status == 'insufficient-data' and any('label digest' in r for r in reasons)


def test_g_u4_the_same_run_supplied_twice_is_not_a_second_run():
    g = ge()
    doc = label_doc('rel', 'release')
    same = g.run('linux', g.pair(doc, g.rows(4)))
    status, reasons, observed = evaluators.g_u4([same, same], corpus_manifest.build([doc], {}))
    assert status == 'insufficient-data' and observed['compared'] == {}
    assert any('same run name' in r for r in reasons)


def test_g_u1_p0_rows_without_any_verdict_cannot_pass_the_null():
    g = ge()
    doc = label_doc('aa-p0', 'aa')
    manifest = corpus_manifest.build([doc], {})
    blind = [R(older=r.older, newer=r.newer, decision='matched', materiality='unknown') for r in g.rows(40)]
    status, reasons, _ = evaluators.g_u1(manifest, [g.run('linux', g.pair(doc, blind))])
    assert status == 'insufficient-data' and any('no verdict' in r for r in reasons)
    sound = evaluators.g_u1(manifest, [g.run('linux', g.pair(doc, g.rows(40)))])
    assert not any('no verdict' in r for r in sound[1])


# ---- the row gates ---------------------------------------------------------------------------------------------------------------------

def rg():
    import test_unified_row_gates as module  # helpers only
    return module


def forged(pairs, first=1):
    return [p.model_copy(update={'labels_sha256': 'e' * 64}) if i < first else p for i, p in enumerate(pairs)]


def test_g_u3_an_outcome_built_from_other_labels_is_a_missing_outcome():
    r = rg()
    manifest, pairs = r.g3_inputs()
    assert r.gate(manifest, r.run(*pairs), 'G-U3').status == 'blocked'
    g = r.gate(manifest, r.run(*forged(pairs)), 'G-U3')
    assert g.status == 'insufficient-data' and any('label digest' in x for x in g.reasons)


def test_g_u6_and_g_u7_an_outcome_built_from_other_labels_is_a_missing_outcome():
    r = rg()
    docs = r.g6_corpus()
    built = [r.g6_pair(d) for d in docs]
    assert r.gate(corpus_manifest.build(docs, {}), r.run(*built), 'G-U6').status == 'pass'
    assert r.gate(corpus_manifest.build(docs, {}), r.run(*forged(built)), 'G-U6').status == 'insufficient-data'


def test_the_thresholds_of_g_u3_and_g_u7_are_compared_exactly_not_after_rounding():
    assert rowgates.precision_ok(995, 1000) and not rowgates.precision_ok(994, 1000)
    assert not rowgates.precision_ok(9_949_999, 10_000_000)             # 0.9949999 rounds to 0.995 at six places
    assert not rowgates.precision_ok(0, 0)
    assert not rowgates.error_ratio_exceeded(2, 100, 1, 100)           # exactly 2x
    assert rowgates.error_ratio_exceeded(3, 100, 1, 100)
    assert rowgates.error_ratio_exceeded(1, 3_000_000, 0, 100)         # a rate of 3e-7 rounds to 0.0 at six places
    assert not rowgates.error_ratio_exceeded(0, 100, 0, 100)
