"""R5 deterministic illustration of risk inflation from treating correlated functions as iid.

This is NOT a PatchTrace calibration experiment. It compares a knowingly
incorrect unadjusted function-level binomial test against an independent
lineage-unit binomial test. Actual PatchTrace threshold.py applies a distinct
ICC/effective-sample correction and is NOT evaluated by this example.

Run: python docs/research/calibration-r5/independence_toy.py
Requires: Python 3.12+, standard library only.
"""
from __future__ import annotations

import json
import math


def binom_cdf(k: int, n: int, p: float) -> float:
    """Use PMF recurrence instead of enormous integer binomial terms."""
    if k < 0:
        return 0.0
    prob = (1 - p) ** n
    cumulative = prob
    for j in range(1, min(n, k) + 1):
        prob *= (n - j + 1) / j * p / (1 - p)
        cumulative += prob
    return min(1.0, cumulative)


def run() -> dict:
    lineages = 50
    functions_per_lineage = 100
    true_wrong_accept_risk = 0.10
    null_risk = 0.05
    delta = 0.05

    naive_pass = []
    lineage_pass = []
    for wrong_lineages in range(lineages + 1):
        p_naive = binom_cdf(
            wrong_lineages * functions_per_lineage,
            lineages * functions_per_lineage,
            null_risk,
        )
        p_group = binom_cdf(wrong_lineages, lineages, null_risk)
        if p_naive <= delta:
            naive_pass.append(wrong_lineages)
        if p_group <= delta:
            lineage_pass.append(wrong_lineages)

    def probability(accepted: list[int]) -> float:
        return math.fsum(
            math.comb(lineages, k)
            * true_wrong_accept_risk**k
            * (1 - true_wrong_accept_risk) ** (lineages - k)
            for k in accepted
        )

    assert naive_pass == [0, 1, 2]
    assert lineage_pass == []
    assert abs(probability(naive_pass) - 0.11172875634634728) < 1e-12

    return {
        "experiment": "independent lineages, perfectly correlated functions within lineage",
        "note": "illustration only: not PatchTrace ICC-adjusted LTT or actual binary accuracy",
        "lineages": lineages,
        "functions_per_lineage": functions_per_lineage,
        "true_wrong_accept_risk": true_wrong_accept_risk,
        "null_risk": null_risk,
        "nominal_delta": delta,
        "naive_accepted_wrong_lineages": naive_pass,
        "lineage_unit_accepted_wrong_lineages": lineage_pass,
        "naive_false_certification_probability": round(probability(naive_pass), 12),
        "lineage_unit_false_certification_probability": round(probability(lineage_pass), 12),
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
