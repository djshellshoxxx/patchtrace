# Synthetic gate-fixture statistical plan

Status: UNVERIFIED. No tests, bootstrap calculations, timing measurements, independent decoders, Windows
checks or external tools have run during authoring. Scripted results never qualify as release evidence.

## Units and paired intervals

A real sampling unit is a project lineage, not a function, a build, a randomly chosen constant or a repeated
run of one image. Twenty parameter changes to one template remain one template lineage. The simulated
lineage names in gate_inputs.py exercise sufficiency branches only. They do not establish independence.

Use the existing tools.unified.cluster.ci implementation with B=2000, two-sided 95% percentile intervals,
deterministic text seeds and whole-lineage draws. Compare two engines by resampling both systems' count
columns together, retaining their covariance. Do not bootstrap each engine independently and subtract
unpaired bounds. A zero denominator is undefined; a missing outcome is insufficient data. Degenerate
all-correct synthetic intervals demonstrate arithmetic only and are not an upper confidence bound on
unseen error. Thirty groups is the implementation's minimum, not a general guarantee of adequate power.

## Per-gate case counts and limits

| Gate | Minimum branch-exercising synthetic design | Real evidence planning |
|---|---|---|
| G-U1 | One X/X, one P0 and all five registered P1 variants; 1000 P0 rows distinguish one review from two | Exact-zero material leakage is an invariant, not a statistical tolerance. With independent Bernoulli trials and zero events, 2995 observations are needed for a one-sided 95% upper bound below 0.1%. Clustered function observations do not satisfy that independence assumption. |
| G-U2 | Twenty distinct scripted mutants per each of 12 implemented registry classes; one miss is 95%, two misses 90%; every leak fails | Twenty detects the threshold boundary, not a precise 95% recall estimate. With 20 successes, a one-sided exact 95% lower bound is about 86.1%. Fifty-nine independent successes are needed to put that lower bound above 95%. Plan at least 60 independent mutation cases per class spread across at least 30 actual lineages, then simulate clustered power using development-only rates. Count moved-RVA-call and try-scope separately until physically implemented. |
| G-U3 | Thirty simulated lineages times 20 rows, then one lineage with many rows to test rejection of pseudoreplication | Zero errors in 299 independent matches gives a one-sided upper error bound below 1%, but does not meet a clustered precision-power requirement. Use at least 30 real lineages and substantially more matches; estimate intralineage error correlation on development lineages before preregistering the locked sample size. The 99.5% point threshold and 99% lower-bound threshold are separate. |
| G-U4 | Three images, all AB/BC/AC legs, two runs and explicit mirrored orientation; one deliberately contradictory leg | These are exact equality and consistency properties. Cover every transformation and platform; repetition does not turn equality into a probabilistic claim. The existing evaluator compares row digests; manifest-byte parity still needs a separate live check. |
| G-U5 | Scripted 10k/60k ladder measurements and 60k ingest; explicit time, RSS, and work-count violations | A 250k run is informative. Actual fresh-process memory and performance must be measured at the stated sizes on Linux, Windows and a Windows frozen build. There is no valid sample count for extrapolating Windows behavior from Linux. Repeated paired stage measurements need separate fresh processes and environment records. |
| G-U6 | Thirty simulated lineages; ten unchanged rows and one mutant per pair; five legacy false leads vs four unified gives the exact 20% boundary | At least 30 real lineages with comparable tool coverage, nonzero legacy false leads and planted positives. Required sample size depends on paired discordance and the planted-recall difference; determine it on development lineages. Test every supplied tool rather than selecting a noisy tool to improve the reported reduction. |
| G-U7 | Thirty B+B rows spanning thirty simulated lineages plus tier-A reference rows; 29 tests the insufficiency floor | Thirty rows cannot establish a rare-error independence claim. Plan at least 30 real lineages per component/class stratum and retain class-level abstention. When tier-A errors are zero the ratio is unstable; do not smooth in invented errors. A paired excess-error interval e_BB minus 2*e_A is a useful proposed diagnostic, but changing gate acceptance needs an owner-approved policy amendment. |

The independent zero-event calculations use n = ceil(log(0.05)/log(1-p)). They are analytical planning
examples, not claims that these images supply independent evidence. No numeric CVE, licence or upstream
version fact is needed for these authored byte fixtures.

## Locked evaluation

Choose transformations, lineage splits, thresholds, component joins and per-pass demotions on development
data only. Freeze the design before the locked run. Keep every build and nuisance variant of a lineage in
one split. Publish missing classes and failed pairs alongside successes. Never count a scripted engine,
golden output, repeated seed or mocked timing row as a real engine run.
