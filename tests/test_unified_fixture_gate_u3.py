"""G-U3 (08-evaluation s1): matched precision>=0.995 and lineage-bootstrap
lower bound>=0.990; zero contradicted tier-A A/A pairs; demote a pass with lower<0.98.

The good script is BLOCKED by the real evaluator's BinDiff oracle requirement, never falsely passed.
UNVERIFIED: not run; simulated lineages do not establish empirical power.
"""
from __future__ import annotations

from unified_support.gate_inputs import GOOD, WRONG_MATCHES, pair, precision_inputs, releases, run
from unified_support.statistics import paired_difference

from tools.unified import rowgates
from tools.unified.corpus import manifest as cm


def test_g_u3_perfect_script_keeps_oracle_block_and_broken_script_fails() -> None:
    manifest, good = precision_inputs()
    status, reasons, observed = rowgates.g_u3(manifest, [good])
    assert status == "blocked" and any("BinDiff" in reason for reason in reasons)
    assert observed["precision"]["point"] == 1.0
    assert observed["precision"]["lo"] == 1.0
    _, bad = precision_inputs(engine=WRONG_MATCHES)
    assert rowgates.g_u3(manifest, [bad])[0] == "fail"
    ci = paired_difference({f"L{i}": (20.0, 20.0, 10.0, 20.0) for i in range(30)}, seed="G-U3-script")
    assert ci["point"] == ci["lo"] == ci["hi"] == 0.5


def test_g_u3_many_rows_in_one_lineage_do_not_create_independent_samples() -> None:
    docs = releases(1)
    large = run([pair(docs[0], GOOD.rows(1000))])
    status, reasons, observed = rowgates.g_u3(cm.build(docs, {}), [large])
    assert status == "insufficient-data" and observed["rows"] == 1000
    assert any("lineages" in reason for reason in reasons)


def test_g_u3_absent_and_unknown_truth_never_manufacture_precision() -> None:
    manifest, good = precision_inputs()
    assert rowgates.g_u3(manifest, [run(good.pairs[:-1])])[0] == "insufficient-data"
    unknown = run(p.model_copy(update={"rows": tuple(r.model_copy(update={"truth": "unknown"}) for r in p.rows)})
                  for p in good.pairs)
    assert rowgates.g_u3(manifest, [unknown])[0] == "insufficient-data"
