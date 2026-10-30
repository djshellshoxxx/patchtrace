"""G-U7 (08-evaluation s1): per component/class pair, B+B error rate<=2*A error
rate, lineage-bootstrap CI reported; <30 B+B rows or <30 lineages is insufficient.

UNVERIFIED: evaluator tests not run. The current evaluator compares point rates and reports unpaired
class-rate intervals; the stricter paired difference below is diagnostic, not a replacement policy.
"""
from __future__ import annotations

from unified_support.gate_inputs import GOOD, pair, releases, run
from unified_support.statistics import paired_difference

from tools.unified import outcomes, rowgates
from tools.unified.corpus import manifest as cm


def inputs(n: int = 30, *, wrong_bb: bool = False, bb_rows: int = 30) -> tuple:
    docs = releases(n)
    supports = (outcomes.Basis(component="K1", tier="B", cls="E-CFG", source="ghidriff",
                              step="StructuralGraphHash"),
                outcomes.Basis(component="K2", tier="B", cls="E-BODY", source="pt-bytes",
                              step="P08-mnemonic-seq"))
    pairs = []
    for i, doc in enumerate(docs):
        rows = list(GOOD.rows(1))
        if i < bb_rows:
            rows.append(outcomes.OutcomeRow(older=(0x2000,), newer=(0x2000,), decision="matched",
                                           materiality="unknown", truth="wrong" if wrong_bb else "right",
                                           basis=supports))
        pairs.append(pair(doc, rows))
    return cm.build(docs, {}), run(pairs)


def test_g_u7_good_and_broken_class_pairs() -> None:
    manifest, good = inputs()
    assert rowgates.g_u7(manifest, [good])[0] == "pass"
    manifest, bad = inputs(wrong_bb=True)
    status, reasons, observed = rowgates.g_u7(manifest, [bad])
    assert status == "fail" and any("join" in reason for reason in reasons)
    assert observed["tier_a"]["error_rate"] == 0.0
    # Paired excess-error statistic e_BB - 2*e_A. Counts are paired by lineage.
    groups = {f"L{i}": (1.0, 1.0, 0.0, 1.0) for i in range(30)}
    ci = paired_difference(groups, seed="G-U7-script")
    assert ci["point"] == ci["lo"] == 1.0


def test_g_u7_exact_thirty_row_floor_and_missing_reference() -> None:
    for kwargs in ({"bb_rows": 29}, {"n": 29}):
        manifest, data = inputs(**kwargs)
        assert rowgates.g_u7(manifest, [data])[0] == "insufficient-data"
    manifest, data = inputs()
    no_reference = run(p.model_copy(update={"rows": p.rows[1:]}) for p in data.pairs)
    assert rowgates.g_u7(manifest, [no_reference])[0] == "insufficient-data"
