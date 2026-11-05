# R5 / 06 — Reproducible dependence toy experiment

**Execution evidence:** A standard-library Python 3 calculation was executed successfully in the research working environment on 2026-10-30, before this file was committed. The source-equivalent implementation is [independence_toy.py](independence_toy.py). This is a deliberately small **mathematical illustration**, not an experiment on PatchTrace functions, and **not an audit of the real ICC-adjusted R5 threshold.py implementation**.

## 1. Question

What happens if an analyst incorrectly treats every matched function as statistically independent when errors are in fact perfectly correlated within independent binary/source lineages?

Assume:
- 50 independent source project lineages, each producing 100 function candidates, 5,000 candidate observations total.
- Every function inside a given lineage is either correctly paired or wrongly paired together (perfect within-lineage correlation).
- Each lineage has a true probability 0.10 of the bad outcome, so the true function-level false auto-accept risk is 10%.
- A proposed acceptor claims risk <=0.05, and applies a one-sided exact binomial cumulative test at delta=0.05.
- Both methods see the **same data**; only their experimental unit differs.

The null case is **true wrong-accept risk 0.10 > 0.05**. A test claiming acceptable risk is a false certification.

## 2. Two tests

**Incorrect iid function test:** If k lineages are wrong, treat 100k wrong functions as independent errors in 5,000 function observations. Its p-value is BinomialCDF(100k, n=5000, p=0.05).

**Correct independent lineage-unit illustration:** If k lineages are wrong, treat k wrong lineages among 50 independent lineages. Its p-value is BinomialCDF(k, n=50, p=0.05).

The toy uses an exact finite binomial PMF recurrence (instead of directly converting enormous binomial coefficients to float) and sums the true Binomial(50, 0.10) sampling probability over outcomes that each procedure would falsely certify.

## 3. Executed results

| Quantity | Naive function-iid test | Independent lineage-unit test |
|---|---:|---:|
| Nominal false-certification delta | 5% | 5% |
| Null target wrong-accept risk | 5% | 5% |
| Actual wrong-accept risk | 10% | 10% |
| Erroneous certification when number of wrong lineages is | 0, 1, 2 | None |
| **True false-certification probability in this toy world** | **11.1728756346%** | **0%** |

The naive function test has p-value about 0.000463610430 when **two lineages** have wrong matches (200 wrong functions among 5,000), so it incorrectly certifies a true-risk-10% population in that outcome. Across repeated random samples from this toy world, the total probability of that kind of false certification is 0.111728756346. With 50 independent lineage units, even the *zero-error* case gives an exact binomial p-value (0.95)^50 = 0.0769449753, so the lineage-unit test does not certify the risk at delta .05.

These are analytically computed probabilities for a fully specified extreme dependence example; no empirical binary similarity accuracy, Brier score, ECE or calibration quality can be inferred.

## 4. Reproduce

~~~bash
python docs/research/calibration-r5/independence_toy.py
~~~

Expected fields: lineages=50, functions_per_lineage=100, naive_accepted_wrong_lineages=[0,1,2], lineage_unit_accepted_wrong_lineages=[], naive_false_certification_probability=0.111728756346, lineage_unit_false_certification_probability=0.0. Python standard library only, deterministic, no random seed or external data.

**Execution limit:** The repository version of this script was not executed on a cloned PatchTrace checkout; a source-equivalent calculation was executed and checked in the research environment. Current PatchTrace tests were not run.

## 5. What the experiment does and does not show

It shows why treating correlated functions as iid is untenable for risk-control claims. **It does not show PatchTrace has the illustrated 11.17% risk.** The actual current tools/calibration/threshold.py attempts to address correlation using lineage ICC and effective n; its false-certification behavior must be evaluated separately with a proper statistical argument and stress testing. In some data regimes its correction may be conservative. The toy has no model-selection, calibration, weights, threshold grid or OOD flags.

A rigorous next step (packet R5-P0-B in [05-engineering-handoff.md](05-engineering-handoff.md)) is to import the actual current threshold selector into a reproducible dev-only stress harness and measure its empirical false-certification rates under prespecified null generators with different ICC, group count, group size, weights and score distributions. Add a second independent calibration partition method as comparator. It would be incorrect to market this toy as evidence that a production threshold is wrong, or that a tested risk-control guarantee has already been validated.
