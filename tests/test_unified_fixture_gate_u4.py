"""G-U4 (08-evaluation s1): identical deterministic output under repetition/permutation;
swapped sides mirror rows; cosmetic(A,B)&cosmetic(B,C) forbids material(A,C);
cheap semantic delta forbids COS-PSEUDO.

A paired-bootstrap agreement diagnostic cannot relax these exact invariants.
UNVERIFIED: no actual Windows/Linux or manifest-byte comparison has run here.
"""
from __future__ import annotations

from unified_s6_helpers import label_doc
from unified_support.gate_inputs import GOOD, pair, paired_recall, run

from tools.unified import evaluators
from tools.unified.corpus import manifest as cm


def chain() -> tuple:
    # Explicit synthetic digest sentinels, not purported observed image hashes.
    digest = {name: name * 64 for name in ("a", "b", "c")}
    docs = [label_doc(f"synthetic-{leg}", "aa", method="aa-layout",
                      older=digest[leg[0]], newer=digest[leg[1]]) for leg in ("ab", "bc", "ac")]
    rows = GOOD.rows(4)
    return cm.build(docs, {}), docs, rows


def test_g_u4_repeat_permutation_mirror_and_chain_pass() -> None:
    manifest, docs, rows = chain()
    forward = [pair(d, rows) for d in docs]
    swapped = [pair(d, rows, orientation="swapped") for d in docs]
    a = run([*forward, *swapped])
    b = run([pair(d, reversed(rows)) for d in reversed(docs)], name="scripted-b")
    assert evaluators.g_u4([a, b], manifest)[0] == "pass"
    ci = paired_recall([1] * 30, [0] * 30)
    assert ci["point"] == ci["lo"] == 1.0


def test_g_u4_broken_chain_and_broken_repeat_fail() -> None:
    manifest, docs, rows = chain()
    good = run(pair(d, rows) for d in docs)
    bad_rows = tuple(r.model_copy(update={"materiality": "material"}) for r in rows)
    bad = run(pair(d, bad_rows if d.pair_id.endswith("ac") else rows) for d in docs)
    assert evaluators.g_u4([bad], manifest)[0] == "fail"
    assert evaluators.g_u4([good, run(bad.pairs, name="scripted-b")], manifest)[0] == "fail"


def test_g_u4_one_run_without_swap_is_insufficient_and_cross_tier_contradiction_fails() -> None:
    doc = label_doc("synthetic-one", "release")
    rows = GOOD.rows()
    manifest = cm.build([doc], {})
    assert evaluators.g_u4([run([pair(doc, rows)])], manifest)[0] == "insufficient-data"
    bad = tuple(r.model_copy(update={"materiality": "cosmetic", "proof": "COS-PSEUDO/1",
                                     "cheap_semantic": True}) for r in rows)
    assert evaluators.g_u4([run([pair(doc, bad)])], manifest)[0] == "fail"
