"""G-U5 (08-evaluation s6): L-35 time limits with 5x CI slack, no RSS slack;
ladder at 10k/60k; ingest at 60k; ticks<=12*n and 60k/10k growth<7.

Scripted measurements test the evaluator only. UNVERIFIED: no laptop, fresh-process RSS,
250k workload, external extraction or Windows frozen performance was measured.
"""
from __future__ import annotations

from unified_s6_helpers import row
from unified_support.statistics import paired_difference

from patchtrace.unified.limits import DEFAULT_LIMITS
from tools.unified import bench


def report(*rows: dict) -> bench.BenchReport:
    return bench.report(bench.evaluate(rows), {"platform": "scripted-not-measured"})


def test_g_u5_scripted_good_bad_and_insufficient_measurements() -> None:
    good = report(row(n=10_000), row(n=60_000), row(stage="ingest", n=60_000))
    assert good.verdict == "pass"
    bad = report(row(n=60_000, ladder=float(DEFAULT_LIMITS.l35_ladder_60k_s * 5 + 1)))
    assert bad.verdict == "fail"
    assert report().verdict == "insufficient-data"
    ci = paired_difference({f"L{i}": (1.0, 1.0, 0.0, 1.0) for i in range(30)}, seed="G-U5-budget")
    assert ci["lo"] == ci["point"] == 1.0


def test_g_u5_rss_has_no_time_slack_and_unknown_rss_is_not_a_pass() -> None:
    limit = DEFAULT_LIMITS.l35_worker_rss_bytes
    assert report(row(n=60_000, rss=limit)).verdict == "pass"
    assert report(row(n=60_000, rss=limit + 1)).verdict == "fail"
    assert report(row(n=60_000, rss=None)).verdict == "insufficient-data"


def test_g_u5_quadratic_work_and_wrong_results_fail_even_with_fast_scripted_time() -> None:
    assert report(row(n=10_000, ticks=10_000), row(n=60_000, ticks=360_000)).verdict == "fail"
    assert report(row(n=60_000, wrong=1)).verdict == "fail"
    assert report(row(n=60_000, ticks=12 * 60_000 + 1)).verdict == "fail"
