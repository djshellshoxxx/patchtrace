"""G-U6 (08-evaluation s1): material false leads at least 20% below the best
supplied legacy tool, with non-decreasing planted recall. Paired lineage CI accompanies reduction.

UNVERIFIED: scripted measurements only; no legacy engine executed.
"""
from __future__ import annotations

from unified_s6_helpers import mutation_doc
from unified_support.gate_inputs import GOOD, pair, run
from unified_support.statistics import paired_difference

from tools.unified import outcomes, rowgates
from tools.unified.corpus import manifest as cm


def inputs(n: int = 30, false_leads: int = 4, *, hide: bool = False, supplied: bool = True) -> tuple:
    docs = [mutation_doc(f"scripted-constant-{i}", target="fixture_constant") for i in range(n)]
    pairs = []
    for doc in docs:
        clean = GOOD.rows(10)
        rows = [r.model_copy(update={"materiality": "material" if i < false_leads else "unchanged",
                                     "legacy": ("ghidriff",) if i < 5 else ()}) for i, r in enumerate(clean)]
        planted = outcomes.planted_of(doc)
        assert planted is not None
        rows.append(outcomes.OutcomeRow(
            older=(planted.older_rva,), newer=(planted.newer_rva,), decision="matched",
            materiality="cosmetic" if hide else "review", truth="right", edited="edited", legacy=("ghidriff",)))
        pairs.append(pair(doc, rows, legacy_tools=("ghidriff",) if supplied else ()))
    return cm.build(docs, {}), run(pairs)


def test_g_u6_exact_twenty_percent_and_broken_engines() -> None:
    manifest, good = inputs()
    status, _, observed = rowgates.g_u6(manifest, [good])
    assert status == "pass"
    assert observed["per_tool"]["ghidriff"]["reduction"]["point"] == 0.2
    for kwargs in ({"false_leads": 5}, {"false_leads": 0, "hide": True}):
        manifest, bad = inputs(**kwargs)
        assert rowgates.g_u6(manifest, [bad])[0] == "fail"
    ci = paired_difference({f"L{i}": (4.0, 10.0, 5.0, 10.0) for i in range(30)}, seed="G-U6-script")
    assert ci["lo"] == ci["point"] == ci["hi"] == -0.1


def test_g_u6_missing_legacy_and_thin_lineages_are_insufficient() -> None:
    for kwargs in ({"supplied": False}, {"n": 29}):
        manifest, data = inputs(**kwargs)
        assert rowgates.g_u6(manifest, [data])[0] == "insufficient-data"
