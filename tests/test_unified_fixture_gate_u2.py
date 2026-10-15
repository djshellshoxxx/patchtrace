"""G-U2 (08-evaluation s1): zero leaks into unchanged/cosmetic; recall>=0.95 per
class with >=20 distinct mutants; frame-only must be review. Bootstrap is descriptive.

UNVERIFIED: tests not run. Pending physical moved-call/scope factories remain pending; no synthetic
status removes those blockers. These inputs test evaluator behavior, not class-specific code extraction.
"""
from __future__ import annotations

from unified_support.gate_inputs import GOOD, HIDES_CHANGES, mutants, pair, paired_recall, planted_rows, run

from tools.unified import evaluators
from tools.unified.corpus import manifest as cm
from tools.unified.mutations import classes


def test_g_u2_good_script_detects_all_but_keeps_physical_factory_gaps_pending() -> None:
    docs = mutants()
    manifest = cm.build(docs, {})
    status, reasons, observed = evaluators.g_u2(manifest, [run(pair(d, planted_rows(d)) for d in docs)])
    assert status == "pending"
    assert any("moved-rva-call" in reason for reason in reasons)
    assert all(v["mutants"] == 20 and v["recall"] == 1.0 for v in observed["classes"].values())
    ci = paired_recall([1] * 30, [0] * 30)
    assert ci["lo"] == ci["point"] == ci["hi"] == 1.0


def test_g_u2_hiding_engine_fails_and_missing_distinct_mutants_are_insufficient() -> None:
    docs = mutants()
    manifest = cm.build(docs, {})
    bad = run(pair(d, planted_rows(d, HIDES_CHANGES)) for d in docs)
    assert evaluators.g_u2(manifest, [bad])[0] == "fail"
    short = run(pair(d, planted_rows(d)) for d in docs[1:])
    assert evaluators.g_u2(manifest, [short])[0] == "insufficient-data"


def test_g_u2_one_leak_fails_even_amid_many_correct_rows() -> None:
    docs = mutants()
    pairs = []
    for i, doc in enumerate(docs):
        engine = HIDES_CHANGES if i == 0 else GOOD
        pairs.append(pair(doc, planted_rows(doc, engine)))
    status, reasons, _ = evaluators.g_u2(cm.build(docs, {}), [run(pairs)])
    assert status == "fail" and any("leak" in reason for reason in reasons)


def test_g_u2_frame_only_material_is_never_counted_as_a_hit() -> None:
    docs = mutants()
    frame = next(c.id for c in classes.CLASSES if c.verdicts == ("review",))
    pairs = []
    for doc in docs:
        rows = planted_rows(doc)
        if doc.case["unified_class"] == frame:
            rows = tuple(r.model_copy(update={"materiality": "material"}) for r in rows)
        pairs.append(pair(doc, rows))
    status, _, observed = evaluators.g_u2(cm.build(docs, {}), [run(pairs)])
    assert status == "fail" and observed["classes"][frame]["detected"] == 0
