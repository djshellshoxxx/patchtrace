# R5 / 02 — Statistical calibration methods and evaluation protocol

**Status:** research and experimental design; no new PatchTrace real-world measurements. This is not an amendment to the C9 preregistration. Reference main: a04f5a299a8d4afef023261e52e08d14678cf1e7.

## 1. Precisely define outcomes

Do not combine seven distinct notions: (a) engine-native similarity, (b) engine-native confidence, (c) PatchTrace ordinal evidence tier, (d) probability of a valid function correspondence, (e) semantic-change verdict, (f) OOD uncertainty, and (g) analyst review status.

- **Target A — one-to-one correspondence:** A=1 only if a Ghidriff proposed old/new function pair is the same logical source-level function. Valid labels: same, different, no-counterpart, indeterminate. The first maps to 1; the next two map to 0; indeterminate is counted and excluded from fitting, not silently forced to 0 or 1. Ambiguous and N:M relationships abstain in the existing model.
- **Relationship topology:** split, merge, inline/outlining, clone/ICF, ambiguous, missing counterpart must be labelled as component/group relationships. Current A model must not pretend a 1:1 truth target covers them.
- **Semantic-change target:** distinguish unchanged, cosmetic, material, review, unknown and not-applicable under SPEC-31 L2. Requires its own truth and preregistration; an L1 match can be right while the L2 verdict is wrong.
- **Evidence sufficiency:** whether available independent evidence clears a declared policy. This is a decision-policy state, not an empirical posterior probability.
- **Analyst decision:** user corrections and manual acceptance are provenance facts and must not be used as features for a pre-review predictor.
- **CVE/KB/product causation:** R4 provenance chain is external evidence; neither an A match nor an L2 materiality class independently establishes vulnerability causation or exploitability.

The displayed number, if eventually allowed, must state: "Estimated correctness of the one-to-one function pairing in the calibrated population." It must not be described as a vulnerability, patch validity, or semantic-equivalence probability.

## 2. Methods — sample size, assumptions, operational choice

| Candidate | Statistical behavior / data needs | Overfitting and imbalance | Offline/runtime suitability | R5 recommendation |
|---|---|---|---|---|
| Rule-based ordinal tier | Deterministic, no probability parameters | No fitted calibration risk, but thresholds still require empirical validation | Excellent; current safe fallback | Retain L0 |
| Native-ratio threshold M0 and raw-byte M0b | Baselines, not calibrated probabilities | Can fail on relocation/noise; class imbalance changes predictive value | Excellent | Must beat at equal coverage |
| L2 logistic + Platt | Low-complexity parametric correction; assumes useful monotone score | Underfit asymmetric tails, train/serve drift; stable relative to flexible models at small effective n | Existing pure-Python implementation | Primary C9 reference |
| Isotonic/PAV | Monotone nonparametric score correction | High variance and plateaus near 0/1 with few effective negatives; can worsen log loss | Existing optional fitter | Use C9 >=1,000 effective per class and one-SE benefit rule; cutoff is a project heuristic |
| Temperature scaling | One-parameter logit rescaling, effective on some neural classifiers | Cannot correct arbitrary nonlinear ratio distortions | Trivial offline inference | Exploratory only; no claim it helps binary diff ratios |
| Beta calibration | Richer parametric map for probability-like base scores | Extra coefficients, requires independent calibration and clipping of 0/1 | Small offline model, but new contract work | Candidate for future prereg v2, not frozen v1 |
| Histogram/adaptive bins | Local empirical frequency estimates | Tail sparsity and brittle bins under extreme class imbalance | Feasible, but unsuitable without many lineages | Diagnostic only initially |
| Bayesian bins / posterior model averaging | Reflects model/parameter uncertainty | Depends on priors and representative group model | More complexity than current need | Research only |
| Small tree / boosted ranker | Nonlinear interactions and missingness | Overfit risk and poorer auditability for few independent lineages | Adds packaging and provenance costs | Unnecessary until simple model fails; M5 excluded from C9 v1 |
| Conformal/risk-control/selective decision | Set prediction or threshold with risk/coverage under specific sampling assumptions | Guarantees generally require exchangeability/held-out calibration units; cluster dependence breaks naive iid interpretation | Offline feasible for a decision gate | Separate study, not a direct replacement for probability calibration |

Primary background: [Platt 1999](https://home.cs.colorado.edu/~mozer/Teaching/syllabi/6622/papers/Platt1999.pdf), [Niculescu-Mizil and Caruana, ICML 2005](https://icml.cc/Conferences/2005/proceedings/papers/079_GoodProbabilities_NiculescuMizilCaruana.pdf), [Guo et al., ICML 2017](https://proceedings.mlr.press/v70/guo17a.html), [Kull et al., AISTATS 2017](https://proceedings.mlr.press/v54/kull17a.html), [Naeini et al., AAAI 2015](https://ojs.aaai.org/index.php/AAAI/article/view/9602), [Geifman and El-Yaniv, NeurIPS 2017](https://papers.neurips.cc/paper_files/paper/2017/hash/4a8423d5e91fda00bb7e46540e2b0cf1-Abstract.html), [Angelopoulos et al., Learn then Test, AoAS 2025](https://doi.org/10.1214/24-AOAS1998), and [Barber et al., Beyond Exchangeability, Annals of Statistics 2023](https://doi.org/10.1214/23-AOS2276). These are **methodological precedents**, not PatchTrace validation.

## 3. Label population, sampling and contamination prevention

Define the population before sampling: engine candidate pairs from image pairs identified by exact SHA, architecture, compiler, product/build lineage and symbols-hidden rule. Compare engine versions only within their recorded domains. Preserve one-sided and ambiguous cases as counted exclusions and report their share.

**Natural stratum:** a reproducible, probability-sampled candidate set; record every stage's inclusion probability, source identity, and nonresponse/adjudication. Headline performance uses inverse inclusion weights. Report both weighted and raw counts, negative prevalence and effective sample size. Unavailable p-inclusion means a case is not eligible for the population-level headline.

**Adversarial stratum:** difficult wrong pairs, duplicates, shared library code, split/merge, inlining, constant-only changes, relocation/callee changes, obfuscation and deliberately ambiguous examples. Report separately; never pool with natural data to inflate or depress the headline error rate.

**Independent labels:** source-level mappings and PDB/DWARF-derived identity when legitimate, but engine scoring must be symbols hidden. PDB names may be nonunique, changed by inlining/ICF, and can leak into Ghidriff heuristics; verify actual source spans and unique function identity. Human reviewers work blind to confidence and must record disagreement, confidence of the annotation **as an annotation**, and adjudication without altering truth merely to improve model metrics. No LLM-produced ground-truth label and no post-review decision feature.

**Lineage grouping:** connected source project, adjacent versions, duplicate binary, copied dependency/source, repeated function body or PDB identity are one split unit. Across-project copied CRTs must be merged into groups or labelled seen-body and excluded from the headline. Keep each Ghidriff run in exactly one role and all compiler builds of the same source function in the same identity unit unless a preregistered domain-shift design justifies a separate evaluation with no information leakage.

The prior binary-similarity benchmark [REFuSe-Bench, Saul et al., NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/file/2663c994c84a79b338bca613fe1ae223-Paper-Datasets_and_Benchmarks_Track.pdf) is relevant to duplication and benchmarking; its real-world labels and licensing do **not** automatically constitute a lawful or directly comparable PatchTrace Windows corpus.

### Leakage checks to automate

1. Same project, binary SHA, PDB identity, normalized body, copied source or repeated mutation template crosses dev/locked/shift roles: reject manifest and name the witness IDs.
2. A fold's held-out functions alter training normalization, median imputation, OOD covariance, calibrator, C choice, or feature selection: fail.
3. Symbol-derived labels were evaluated with symbol-loaded engines: reject.
4. Calibration-feature missingness or engine profile differs between training and production schema: reject unsupported inference.
5. Analyst corrections, CVE findings or downstream semantic class enter a pre-review pairing model: reject.
6. Duplicate candidate/normalised function appears in train and test: reject or report in the predeclared seen-body stratum.
7. Negative label from unmatched absence alone or a later binary rename: reject unless independently proven.
8. Locked-test predictions were inspected while changing thresholds or choosing a model: stop, preserve v1 evidence and create new prereg.
9. Random-row CV appears stronger than grouped CV on deliberately dependent synthetic functions: retain as a **leakage illustration only**; only grouped CV is eligible for product claims.

## 4. Reproducible model study

C9 has M0 (Ghidriff-ratio threshold), M0b (rz-diff raw similarity), M1 (G-only L2 logistic), M2 (SPEC-27 index as uncalibrated score), M3 (multi-family L2 logistic) and M4 leave-family-out/dependency ablations. M5 boosted model is not eligible in v1. Profiles: G, G+R, G+B and G+B+R, with a missing secondary engine explicitly unavailable rather than a negative vote.

Procedure:
1. Verify source corpus, legal provenance, binary SHA and immutable sample selection; name toolchain and exact engine versions.
2. Audit labels with a blinded human and source/PDB evidence. Freeze ID groups and held-out roles before model choice.
3. Train each profile with nested grouped cross-validation, inner-only standardization, per-fold imputation and OOD fitting. Tune C/calibrator on dev only; Platt default, isotonic by C9 effective-n and one-standard-error rule.
4. Compare models with a **paired lineage bootstrap** at equal coverage or equal analyst review budget, not arbitrary unmatched thresholds. Report Brier/log loss, wrong-accept rate, precision, recall, FPR, FNR, rank AUC, PR-AUC (class orientation stated), calibration slope/intercept, ECE and risk–coverage.
5. Ablate each family, shared Ghidra origin, byte/CFG/callgraph/data, string references, candidate margin, competing matches, compiler and missingness groups. Record feature coefficients and stability across folds, **not** just a global feature-importance score.
6. Only a frozen dev-selected candidate proceeds to locked-test. The locked data are read only once through the prescribed gate, and results are never used to rescue a failing threshold.
7. Repeat on shift-test lineages and report each unsupported compiler/toolchain and binary class separately, keeping missing results and abstentions visible.

**Hypothesis to test:** independent byte/CFG/callgraph evidence and unique anchors may improve wrong-match rejection; correlated Ghidriff/BinDiff evidence and weak size similarity may not. Do not assume higher source count means independent evidence. An ablation must show a reproducible decrease in loss **outside the training lineage** to justify adding features.

## 5. Metrics — exact definitions and confidence intervals

Let y_i be the independent binary correspondence label, p_i the model score and w_i the known inclusion weight.

- Brier = sum(w_i (p_i-y_i)^2) / sum(w_i); Brier skill compares to the weighted base-rate predictor.
- Log loss = weighted mean of negative y log p + (1-y) log(1-p), using explicit numerical clipping for boundary values.
- ECE15 = sum over equal-width bins of weight share times absolute difference of bin mean predicted probability and bin observed positive rate; plug-in ECE is biased nonzero even under perfect calibration, so C9 compares it to a null simulation with matching predictions, weights and clustering. Also report equal-mass ECE, effective n per bin and calibration slope/intercept CI.
- Wrong auto-accept risk = (weighted wrong accepted)/(weighted accepted), the complement of precision. Coverage = weighted accepted / weighted **eligible natural** candidate population; hard OOD/review decisions count as non-accepted, not silently removed.
- False positive rate = weighted wrong accepted / weighted all wrong eligible candidates. Recall for correct matches is separate from accepted coverage.
- Risk–coverage curve = observed wrong-accept risk at every accept threshold versus fraction accepted. Abstention rate = fraction reviewed/unavailable/OOD as explicitly defined.
- ROC-AUC and PR-AUC must state whether the positive class is correct correspondence or incorrect correspondence; PR-AUC baseline is class prevalence.
- CIs: lineage-level bootstrap B=2,000, paired for comparisons; report raw and effective candidate count, independent group count, interval method, undefined replicate rate and width. Small strata are **insufficient-data**, not zero-error.

Report by compiler family and version, optimization, architecture, PE type, function size, transformation class, engine availability/profile, ordinal evidence tier, candidate margin, in-domain/OOD, source family and bin size. Do not use aggregate accuracy alone.

## 6. Risk control: mathematical qualification

The frozen C9 code chooses tau across 0.999 down to 0.500 to target precision >=0.95 with delta 0.05 using a fixed-sequence Learn-then-Test-like procedure. It converts weighted clustered errors into an ICC-adjusted effective sample n, rounds its error count and applies a binomial cumulative probability test.

This is an **unproven transfer of an iid test to correlated and weighted data** until conditions or a separate theorem validate the effective-n replacement. A function-level binomial bound cannot be described as finite-sample distribution-free certification merely because the estimator includes an ICC. The dev OOF threshold and reported dev precision are also selection-coupled; tools/calibration/train.py explicitly calls this dev-selected.

Required sensitivity study:
- Known null true wrong-accept rates above 5%, clusters {12,20,30,40,80}, ICC {0,.05,.2,.5,1}, group-size imbalance, class imbalance, inclusion-weight ratios {1,5,20}, and varying candidate thresholds.
- >=10,000 Monte Carlo trials per critical cell, deterministic seeds and binomial uncertainty around observed false-certification rate. The simulated guarantee is **conditional on simulation settings**, not a proof for arbitrary distributions.
- Compare original effective-n method against a completely disjoint lineage-level calibration cohort and conservative cluster-unit or distribution-free alternatives under their precise assumptions. Do not use locked-test to decide among them.
- If certification or coverage fails, set tau=None, abstain/route to manual and retain ordinal display. A post-lock statistical-method change requires prereg v2 with old results preserved.

## 7. Shift, OOD and model expiry

Study unsupported/unknown compiler revisions, different optimization and link settings, packed/obfuscated inputs, abnormal CFGs, extreme function sizes, missing symbols, unusual calling conventions, PE drivers vs user DLLs, wrong architecture, binary-format mismatch, new Ghidriff/BinDiff/rz-diff version, changed BinExport producer, and shared static libraries.

Test on lineages excluded from fitting by declaration. For each group report: N, group count, prevalence, percent hard-flagged, percent soft-flagged, risk and precision at frozen tau, false-flag rate and calibration diagnostics. If Mahalanobis flags do not predict error on dev-lineage validation, C9 already requires reduced range/unseen-category checks. Unknown engine-major version is a **support boundary**: ordinal/abstain unless exact version compatibility is demonstrated and the policy supports it. An OOD detector cannot justify extrapolating calibration to a binary family unseen in training.

## 8. Acceptance is an evidence chain

Necessary immutable objects: corpus manifest, independent labels, sampling list and inclusion probabilities, identity/partition mapping, prereg byte digest, engine output digests, feature schema, model fit and calibration hyperparameters, threshold and OOD policy, grouped CV predictions, locked evaluation receipt, aggregate tables and intervals, failure fixtures, current-head Linux/Windows CI, frozen EXE smoke, reviewer sign-offs, and artifact digest. Each report must separately state synthetic/Tier R/Tier W support. Report **insufficient-data** when this chain is incomplete.

**Result:** Current C9 Platt/L2 + ordinal fallback is the best defensible engineering starting point. Research alternatives are not automatically accepted or eligible for v1 promotion.
