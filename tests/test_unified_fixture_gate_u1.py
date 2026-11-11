"""G-U1 (08-evaluation s1): X/X=100% unchanged, zero contests/one-sided;
P0 material=0 and review/rows<=0.001; every P1 material=0.

Paired bootstrap compares scripted row-error rates descriptively; the zero-error gate is exact.
UNVERIFIED: tests not run. Scripted status is never live evidence.
"""
from __future__ import annotations

from unified_s6_helpers import label_doc
from unified_support.gate_inputs import FALSE_CHANGES, GOOD, pair, run
from unified_support.pairs import pair_for
from unified_support.statistics import paired_difference

from tools.unified import evaluators
from tools.unified.corpus import aa
from tools.unified.corpus import manifest as cm


def documents() -> list:
    image = pair_for("unchanged")
    old, new = image.digests
    return [label_doc("scripted-x", "aa", older=old, newer=new), label_doc("scripted-p0", "aa"),
            *[label_doc(f"scripted-p1-{kind}", "aa", method="aa-layout",
                        case={"kind": "link-order" if kind == "link-order" else "nuisance", "nuisance": kind})
              for kind in aa.P1_KINDS]]


def test_g_u1_good_and_broken_scripted_engines_and_missing_data() -> None:
    docs = documents()
    manifest = cm.build(docs, {})
    good = run(pair(d, GOOD.rows()) for d in docs)
    bad = run(pair(d, FALSE_CHANGES.rows()) for d in docs)
    assert evaluators.g_u1(manifest, [good])[0] == "pass"
    assert evaluators.g_u1(manifest, [bad])[0] == "fail"
    assert evaluators.g_u1(manifest, [run(good.pairs[:-1])])[0] == "insufficient-data"
    assert evaluators.g_u1(manifest, [good, run(bad.pairs, "scripted-b")])[0] == "fail"
    ci = paired_difference({f"L{i}": (0.0, 20.0, 20.0, 20.0) for i in range(30)}, seed="G-U1-script")
    assert ci["point"] == ci["lo"] == ci["hi"] == -1.0
    assert ci["anti_conservative"] is False


def test_g_u1_inclusive_p0_review_boundary() -> None:
    doc = label_doc("scripted-boundary", "aa")
    baseline = GOOD.rows(1000)
    one = tuple(r.model_copy(update={"materiality": "review"}) if i == 0 else r
                for i, r in enumerate(baseline))
    two = tuple(r.model_copy(update={"materiality": "review"}) if i < 2 else r
                for i, r in enumerate(baseline))
    manifest = cm.build([doc], {})
    assert evaluators.g_u1(manifest, [run([pair(doc, one)])])[0] == "pending"
    assert evaluators.g_u1(manifest, [run([pair(doc, two)])])[0] == "fail"
