# Label training glossary (plain language)

For readers of `docs/handoff/label-training.md`. Each entry says what the term means here, where it lives in the code or plan, and what mistake it prevents. Numbers are the frozen values of `docs/plans/c9-preregistration-v1.md` (PREREG) as of 2026-10-15; the preregistration is still a draft until the lock.

## The big picture
PatchTrace compares an older and a newer build of a program and says which functions probably correspond and which changed. "Label training" builds known-answer test data (we know the true answer because we have the source code), runs the comparison engines on it, and fits and checks a small calibration model that turns engine evidence into an ordering of how much to trust a pairing. Tier R is that work on test builds of open-source C code. Tier W is the same on real Windows files and can only be run on the owner's machine. A good Tier R result shows the pipeline works. It says nothing about Windows files.

## Terms

**Target A.** The only thing we model: "the older and newer functions in this candidate pair are the same source-level function, one to one". Not "is vulnerable", not "was fixed". B, C, D (blocks, patch mechanism, root cause) are reserved and unused.

**Tier R / Tier W.** R = Reproducible: test builds we compile ourselves from pinned open-source commits on CI. W = Windows: Microsoft binaries and symbol data, handled only on the owner's machine, never committed or uploaded. Tier R can reach gate G1 at most. Anything about Windows needs Tier W.

**Recipe.** A committed description of how to build one open-source project: pinned commit ids, the licence file hash at each pin, the explicit list of source files and compiler options. Never a script from the project itself; we never run upstream configure scripts. File: `tools/calibration/tier_r/catalogue/recipes.json` (and the split copy in `recipes.d/`).

**Card (case card).** One pair of versions of a project, old and new, with the functions the upstream change touched ("declared changed") and a few unchanged controls. Kinds: release (adjacent tags), cve (a real security fix commit), control. Files: `releases.json`, `cves.json`, `corpus/catalog/*.json`.

**Suite.** A small hand-written C project in `corpus/ours/<group>/<name>/` with versions and a truth file. We use them for mutation, noise and identity-negative tests (look-alike functions that must not be paired).

**Pin.** A 40-character git commit id (not a tag name, which can move) plus the SHA-256 of the licence file at that commit. Verified with `git ls-remote`; annotated tags must be "peeled" to the commit they point at.

**Lineage.** One family of related builds that must never be split across train and test: a project's releases, plus the mutants, A/A rebuilds and noise builds made from it. For recipes the lineage is the project. Two projects that share copied code (zstd and brotli bundle zlib-like code; Lua and Mbed TLS bundles) are merged into one lineage when their masked function bodies overlap by 15% or more (steps 15, 30, 50%). A lineage is also the unit for intervals: 500 mutants of one project are one lineage, not 500 independent samples. The count of lineages is the real sample size. Today: 41 (16 recipes plus 25 suite directories including the template), 24 of them dev.

**Stratum.** A kind of pair, used to keep different questions apart. Tier R strata: `release`, `cve`, `control` (the natural ones), `mutation`, `aa`, `noise` (controls, never accuracy evidence) and `authored` (hand-written suites). In training, "natural" rows are the engine candidates of release, CVE and control pairs; "adversarial" rows are everything built to stress an engine. They are reported in separate tables and never pooled. (Whether `authored` is natural or adversarial is open decision D-A in the handoff.)

**Candidate / row.** One proposed pairing (old function, new function) from an engine. The model scores candidates. The answer is `same`, `different`, `no-counterpart` (the function exists on one side only), `ambiguous` or `indeterminate` (the evidence cannot decide). Ambiguous and indeterminate rows are excluded from fitting but counted; if more than 5% of a stratum is indeterminate the stratum is flagged and the headline also gets a worst-case number that treats them as wrong.

**Two-source rule.** A label is trusted only if two independent sources agree: the source-code diff and the fact about the compiled function body (its relocation-masked hash). A disagreement is counted (`check=disagree`); declared functions must have none unexplained.

**Masked body.** A function's machine code with addresses and relocations blanked out, so a pure shift in memory layout does not look like a change. "Address-only" means the masked bytes are identical.

**A/A (A versus A).** Compare a build with itself, or with a rebuild from identical source. The right answer is "nothing changed", so every flagged change is a false alarm. A/A measures the noise floor of an engine. Byte-identical X-versus-X must give zero flagged material changes; otherwise stop.

**Noise pair.** Same source built two ways (for example gcc versus clang, or different link layouts) so the code differs but the meaning does not. The engine should still say "same function, no real change". It measures how much a toolchain change alone fools the engine.

**Mutation / operator.** A small planted source change (flip a comparison, remove a bounds check, change a constant) applied to a suite, compiled, and labelled with the function that changed. There are 25 source operators (16 original plus 9 added), an IR layer (the same edits made on LLVM IR, as an independent cross-check) and an `opt` layer (compiler passes that must not change meaning). Mutants are easier than real fixes, so they are reported apart from real CVE fixes ("planted" versus "real-fix").

**Engine.** A comparison tool whose output we score: rz-diff (rizin), Ghidriff, BinDiff (only from supplied BinExport files), `attention` (PatchTrace's own lead list), `unified` (the unified engine, not available yet). Engine scores are never averaged with each other; each stays in its own table.

**Shard / R1..R7.** The CI work is split into shards that run in parallel and are merged. R1 is the first diagnostic run (does everything build on a runner?), R2 the mutation farm, R3 the Ghidriff leg, R4 the MSVC leg, R5 the dev training run, R6 the single locked look, R7 a determinism re-run. Names come from `docs/plans/lbl-remaining-plan.md`.

**Roles: dev, locked-test, shift-test.** Each lineage is assigned a role by hashing its id with the salt `c9-v1`: about 60% dev (used for fitting, model choice, threshold choice, ablations), 25% locked-test (looked at once), 15% shift-test (a deliberately different slice used to see what breaks). The hash makes assignment fixed and impossible to tweak after seeing results. Roles are per lineage, never per row.

**Locked.** Locked-test data and the preregistration are looked at exactly once per preregistration SHA. The runner writes a receipt file before it evaluates, so a crash still counts as the one look. A second run for the same SHA is refused.

**Shift (shift-test, shift ladder).** Shift means the test data differs from the training data in a known way: another compiler (MSVC versus gcc/clang), another project family, or later Windows files. The shift ladder trains on one part and tests on another: (1) inside one toolchain, (2) leave one toolchain out, (3) leave one family out, (4) Tier W (owner only). A shift failure is reported as a blind spot. It is never a reason to retune.

**Preregistration (PREREG, C9).** `docs/plans/c9-preregistration-v1.md`: the analysis written down before the look: target, models, every constant, gates, shift lists, what a synthetic result may claim. Locked by committing it, hashing its bytes with SHA-256 (P-1: `python -m tools.calibration.prereg`) and recording the hash in `docs/qa.md` row `C9-PREREG-v1`. After the lock any change is a new version v2.

**Calibration.** Making a model's score mean something: of the pairs scored 0.8, about 80% should truly be the same function. Platt scaling (a fitted S-curve) is the default; isotonic (a free staircase) only with enough data.

**tau.** The score threshold above which a pairing is auto-accepted. "Frozen tau" is the value chosen on dev data and then never changed. tau-low is the lower cut below which a pairing is auto-rejected. Between them the analyst decides.

**Precision, coverage.** Precision at tau: of the pairs auto-accepted, the share that are truly the same. Coverage: the share of all candidates that got auto-accepted. High precision with tiny coverage is useless; the targets are both.

**LTT (Learn-then-Test).** The method that picks tau with a guarantee. Instead of "choose the tau that looks best", it tests thresholds from strict to loose and stops at the first one it cannot certify, so with high confidence (delta 0.05) the true error is at most 5% at the chosen tau. The test uses an effective sample size that shrinks when rows cluster in a few lineages.

**Effective n.** How many independent observations the data is worth. 10,000 rows from 12 lineages are worth far fewer than 10,000. Kish effective n with the lineage correlation (ICC) is used; if the correlation cannot be estimated the cautious value 1.0 is used for LTT.

**ECE (expected calibration error) and ECE excess.** ECE averages the gap between what the model says (score) and what happens (observed rate), over 15 equal-width bins. Even a perfectly calibrated model shows a positive ECE by chance on finite data, so the gate uses ECE excess = measured ECE minus the ECE of a simulated perfectly calibrated model (1,000 simulations). Targets: excess at most 0.03 (interval upper bound at most 0.05).

**Brier score / skill.** Mean squared error of the probabilities. Skill compares it to always guessing the overall base rate; skill above 0 (interval lower bound) means the model beats that guess.

**Calibration slope and intercept.** Fit a line from the model's score (on the log-odds scale) to outcomes. Slope 1 and intercept 0 mean perfect calibration. Gate: the interval for the slope contains 1 and for the intercept contains 0.

**Lineage bootstrap and intervals.** Resample whole lineages (not rows) with replacement, 2,000 times, recompute the statistic, take the middle 95%. `anti_conservative` is the flag put on an interval built from fewer than 30 lineages: it is probably too narrow and the headline cannot pass. Paired comparisons use identical resamples.

**Nested CV.** Cross-validation inside cross-validation: the outer 5 folds estimate performance on unseen lineages; the inner 5 folds choose settings (the regularisation C from {0.01, 0.1, 1, 10}). Every fitted piece (scaling, calibrator, out-of-distribution statistics) is fitted on training folds only. Groups (identity groups) are never split across folds.

**Identity group / hub / seen-body.** Candidates that share a function body across lineages are put in one group so a body seen in training cannot reappear in testing. A body that appears in more than 3 lineages is a hub (shared C runtime or static code); hubs are not used to join lineages, and their candidates are reported in a separate `seen-body` stratum.

**OOD (out-of-distribution).** A pair that looks unlike anything in training (unseen toolchain, unusual size, thunk). The model abstains on hard OOD cases instead of guessing. The OOD flag is kept only if flagged pairs really do err more often than unflagged ones.

**Models M0..M4.** M0: Ghidriff similarity above a cutoff. M0b: rz-diff raw byte similarity cutoff. M1: logistic regression on Ghidriff features alone. M2: the current hand-set order index. M3: the multi-family logistic regression (the thing being trained). M4: ablations of M3 (drop one evidence family at a time). A family that does not help is removed. M5 (boosted trees) is excluded from v1.

**G0, G1, G2, G3 (gates).** G0: do we have enough data (at least 12,000 natural candidates, 40 lineages from 10 families, six Windows families covering kernel, user-mode DLL and driver, two toolchain profiles, a shift lineage, annotator agreement, symbol-audit error at most 0.02, indeterminate at most 5%). G1: does the pipeline recover known answers on synthetic Tier R data (computed with the strict L2 numbers); a pipeline-health result only. G2: precision at least 0.95 with interval lower bound at least 0.90 and width at most 0.10, coverage at least 0.40, certified by LTT, on real Windows locked-test data (allows band display). G3: stricter numbers (lower bound 0.93, width 0.06, coverage 0.50, ECE excess limits), a second independent annotator, a reproducibility check, owner sign-off and a frozen-EXE smoke test (allows numeric display). Each gate returns `pass`, `fail` or `insufficient-data`. Insufficient data is never a pass. On Tier R alone G0, G2 and G3 are always `insufficient-data`.

**Display level.** What the product may show for scores: `ordinal` ("order only", today), bands (after G2), numbers (after G3). A Tier R result never changes it.

**Honest scope / `TIER_R_CLAIM`.** The sentence every Tier R report starts with: "Measured on test builds of open-source code; says nothing about Windows system files." The product shows "Order only" and an Evidence limits text; no percent from synthetic data appears anywhere.

**Validation ledger.** A packaged list of what has been tested on what, with states such as untested and `synthetic-validated` (Tier R report SHA cited) or `windows-validated` (Tier W, owner only). None ships yet, so the status reads "untested".

**Stop-and-ask.** A fixed list of conditions (handoff Appendix B) under which a worker stops, posts the report unchanged and asks the owner, instead of retuning or retrying.

**Determinism.** The same inputs must give a byte-identical report, checked by comparing `report_sha256` of two runs. No clocks, sorted ids, canonical JSON.

**Leakage.** Anything that lets the test peek at the training answers: the same lineage, source project, image hash, PDB name or function body on both sides of a split; symbols visible to an engine; swapped older/newer order. The guards `audit_manifest` and `audit_identity_roles` check these; any finding stops the run.

**Clopper-Pearson bound.** An exact upper limit for a rate when you saw zero (or few) events. "0 false alarms in 100" still allows a true rate up to 3%; about 2,995 clean items are needed before the 0.1% limit is demonstrated.
