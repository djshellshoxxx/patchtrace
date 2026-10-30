# R5 / 03 — Dataset creation, experiments, reproducibility and test runbook

**Scope:** implementation-ready sequence for a responsible R5 owner with an actual checkout and permitted local tools/data. Commands below were checked against main source CLI parsers on 2026-10-30 but **not executed in this research session**. The repository requires Python >=3.12, PySide6 6.12.0, pydantic 2.13.5, protobuf 7.36.2; dev requirements are in pyproject.toml.

## 0. Preflight and immutable checkpoint

First record exact live main commit, active worktrees, branch/PR owners, model bundles, current CI statuses and the 2026-10-30 R1 #128, R3 #129, R4 #130 and integration #126 handoffs. Run git status; preserve dirty/untracked data; never overwrite a contributor's branch. R1 owns corpus source, Tier R label admission and first native-engine pilot. Use R1-produced verified data; this R5 dossier does not create a second Tier R factory.

Read AGENTS.md, CLAUDE.md, SECURITY.md, docs/modules.md, docs/qa.md, tasks/todo.md, docs/specs/calibration-corpus-and-model.md, docs/specs/multi-engine-evidence-calibration.md, docs/specs/unified-engine/05-fusion-and-noise.md, docs/specs/unified-engine/08-evaluation.md, docs/plans/c9-preregistration-v1.md and existing current code. Validate whether the C9 prereg SHA has since been locked before changing its values.

Suggested reproducible environment:
~~~bash
python --version
python -m pip install --only-binary=:all: -e ".[dev,calibration-dev]"
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_calibration_math.py tests/test_calibration_metrics.py tests/test_calibration_cv.py tests/test_calibration_tools.py tests/test_calibration_runtime.py tests/test_calibration_scope.py tests/test_calibration_hardening.py
python -m ruff check src tests tools
python -m tools.calibration.prereg --file docs/plans/c9-preregistration-v1.md
python -m tools.calibration.tier_r toolchain
~~~
The last prereg command computes a digest but **does not lock the test or prove approval**; use --qa docs/qa.md only after the authoritative C9-PREREG-v1 row exists. The exact test invocation must be run on the real checkout; simulated command text does not constitute a pass. Windows acceptance must use an actual Windows runner.

All generated images, PDBs, native engine outputs and local Tier W materials go under an **external, excluded** PATCHTRACE_CALIB_ROOT, never inside the repository. Keep private Microsoft data and any legally restricted inputs out of git and PR attachments.

## 1. Corpus manifest and independent truth

Reuse:
- tools/calibration/tier_r/factory.py, build.py, manifest.py, labeler.py, debuginfo.py and annotate.py;
- tools/calibration/tier_r/catalogue/recipes.json, releases.json, cves.json and split release/recipe directories;
- tools/calibration/tier_w paths, fetch, PDB/symbol source, labels, audit and aggregation tools for **owner machine only**;
- tools/calibration/{corpus,lineage,guards,sample,label,contracts,prereg}.py;
- docs/schemas/calibration/{CorpusManifest,LabelRecord,PairRows,CalibrationReport,CalibrationArtifact,ValidationLedger}.json;
- corpus/ours, approved permissive source pins and source fixtures.

Contract rules:
- Each image: exact SHA-256, size, architecture, compiler and recipe/toolchain identity, source commit and license, redistribution permission and symbols-hidden analysis condition.
- Each pair: ordered older/newer identities, source family, connected lineage, role and stratum, candidate set hash and engine output digests.
- Each function endpoint: old/new RVA, body/identity hash, uniqueness, source/PDB identity (when legitimately derived), displacement masking provenance, actual source diff/commit, ambiguous/ICF/inline flags.
- Each label: same/different/no-counterpart/indeterminate, N subtype, independent annotators and adjudication, reason/evidence hash, audit state, inclusion probability; never include private Microsoft disassembly in a public report.
- For every report: feature schema, label-set and manifest SHA, partition/identity graph SHA, prereg SHA, model config, seeds, exact engine versions, exclusions and coverage denominators, accepted model scope.
- Controls A/A, compiler-noise and planted-mutation sets **do not belong in natural-sample headline accuracy**. Keep them as regression and stress suites. The held-out shift domain is selected before truth inspection.

### Source of truth and independent labels

For source-built Tier R, use exact source identity plus debug-symbol mapping, and verify the relevant source span and pairing after compilation. Link-time ICF, inlining, outlining, static-name collisions, compiler thunks and duplicate source names prevent naive same-name identity claims. Address-masked body equality is supporting evidence, not truth by itself: a replacement callee or global may produce identical masked instructions but changed semantics.

For Tier W, use only owner-permitted local Winbindex/PE and Microsoft Symbol Server PDB data; require authoritative size/SHA and PDB GUID-age, matched source symbol names with uniqueness checks, and independent human audit. Always run candidate engines with symbols hidden if labels came from PDB/symbol identities. Report ambiguity and unresolved provenance instead of converting missing matches to false negative labels by assumption.

If source files, compiler or engine cannot be obtained, mark **BLOCKED** with the exact failure; do not substitute synthetic success.

## 2. Tier R acquisition/build/evaluation commands

The command names/flags shown below exist in tools/calibration/tier_r/cli.py on the inspected revision. Use a non-repository output root and a documented card/suite ID chosen after license and pin verification.

~~~bash
export PATCHTRACE_CALIB_ROOT="$HOME/.patchtrace-calibration"
python -m tools.calibration.tier_r toolchain
python -m tools.calibration.tier_r catalogue-check
python -m tools.calibration.tier_r schemas
python -m tools.calibration.tier_r build-card --help
python -m tools.calibration.tier_r build-suite --help
python -m tools.calibration.tier_r aa --help
python -m tools.calibration.tier_r noise --help
python -m tools.calibration.tier_r mutate --help
python -m tools.calibration.tier_r evaluate --help
python -m tools.calibration.tier_r manifest --help
python -m tools.calibration.tier_r annotate --help
~~~

Actual operation shape, once case IDs exist:
~~~bash
python -m tools.calibration.tier_r fetch CARD_ID
python -m tools.calibration.tier_r build-card CARD_ID --opt O2
python -m tools.calibration.tier_r evaluate --symbols hidden --engines ghidriff,rz-diff
python -m tools.calibration.tier_r manifest --corpus-id known-answer-tier-r --tool-git FULL_SHA
~~~

Fetch may access network only with explicit operator permission and validated license/pins. Build output files are test inputs to static engines and **must never be executed**. Default import folder for external results is store/imports, containing per-pair .BinDiff and .ghidriff.json when available. A missing rz-diff/Ghidriff or BinExport must be accurately reported as blocked. Some R1 observations show a status parsing error when backend returns identical and 0 outcome rows; fix the parser/regression before treating a built sample as evaluated.

Tier R expected output is known-answer-labels/1, tier-r-engine-output/1, tier-r-report/1, calibration-corpus/1, tier-r-feature-rows/1 and verified SHA/digests. A build-only report or a label produced without an actual engine run is **not** a binary-similarity evaluation.

## 3. Run the existing dev-only calibration train command

The real parser is tools/calibration/train.py. It accepts exactly **one** of:
- --labels FOLDER with --outputs FOLDER,
- --rows FOLDER,
- --merge FILE (optionally --aggregate FILE).

Required flag --out FOLDER. Optional --prereg FILE, --tool-git SHA, --locked-form, --artifact and --smoke. Smoke lowers computational effort and group minima; never cite smoke evidence for promotion.

~~~bash
python -m tools.calibration.train run \
  --labels "$PATCHTRACE_CALIB_ROOT/known-answer/labels" \
  --outputs "$PATCHTRACE_CALIB_ROOT/known-answer/outputs" \
  --prereg docs/plans/c9-preregistration-v1.md \
  --tool-git FULL_SHA \
  --out "$PATCHTRACE_CALIB_ROOT/r5-dev"
python -m tools.calibration.train report \
  "$PATCHTRACE_CALIB_ROOT/r5-dev/report.json" \
  --out "$PATCHTRACE_CALIB_ROOT/r5-dev/report-reviewed.md"
python -m tools.calibration.train shift \
  --rows "$PATCHTRACE_CALIB_ROOT/known-answer/rows" \
  --prereg docs/plans/c9-preregistration-v1.md \
  --out "$PATCHTRACE_CALIB_ROOT/r5-shift"
~~~

These are command templates: the displayed paths require data generation and verification; existence is **not** assumed. The train command creates deterministic report.json/report.md on success, may produce an experimental dev-only artifact when --artifact is given, and exits 0 on success, 1 findings/split failure, 2 usage/contract issue, 3 blocked input. The report must explicitly identify status: synthetic or Tier R-only can check tooling, **never enable Windows numeric percentages**. The dev tool's artifact is experimental and not a shipped model.

The training adapter currently reports some feature limitations: absent B engine, no full G match-type flag provenance, synthetic call counts, limited similarity columns, zero or missing values. Record unavailable feature families and train/serve parity before considering a profile for product inference.

## 4. Freeze and single-look evaluation

C9 v1 documents the protocol and gating values but was still a **draft** in the checked main. An owner/integrator must settle open Q1/Q2 and O1/O2/O3/O4, verify source corpus/licensing, shift declaration, label guideline g1, independent label audit, sample list hash, reproducible build and exact configuration before locking. A change after the locked-test look requires a v2 prereg with the old result retained.

Pre-lock checklist:
1. The immutable manifest and label guideline have exact SHA and are versioned in git.
2. Role identities and accidental duplicate bodies across dev/locked/shift are audited; labels have not been peeked.
3. Every model candidate, hyperparameter, accepted features, profile, threshold and statistical test is chosen entirely from dev evidence.
4. The sample plan specifies natural/adversarial and IPW weights, eligible denominator, group unit, field-exclusion rules, and OOD population.
5. The owner records approval and the actual **committed file byte SHA** of C9 v1 in docs/qa.md row C9-PREREG-v1, with no CR/LF drift.
6. The locked runner, trusted host and evaluation function are pinned and identify all input digests.
7. The exact tests and package CI are green on approved Linux/Windows runners.

The helper tools/calibration/run_locked_test.py::run_locked_test creates a local receipt **before** evaluating and refuses to run again for the same prereg SHA **in that directory**. This guard does not verify the SHA matches a trusted commit or prevent fresh-directory/other-host runs; a trusted external ledger or release attestation is necessary before calling the test globally single-use. Preserve crashed results/receipts. Never re-run with a new directory to improve a metric.

Expected locked outcome includes separate exact metrics for each G, G+R, G+B and G+B+R profile supported by native input. Missing engines mean a profile cannot pass. Compute the locked result with frozen tau exactly once; report all failed/insufficient gates. Reserve shift-test data for the distinct declared domain challenge, never for rescue tuning.

## 5. G0/G1/G2/G3 evidence worksheet

| Gate | Required evidence fields / test | Failure mode |
|---|---|---|
| G0 | Natural >=12,000, locked >=3,000, locked effective negatives >=150; total >=40 lineages/10 families; locked >=12 lineages/5 families; Tier W >=6 families and kernel/user DLL/driver; >=2 toolchains and >=1 shift lineage; annotation kappa and symbol audit; subtype counts | Insufficient data or label leakage -> no model claim |
| G1 | Tier R pipeline on valid known-answer samples, reproducible engineering runs with native tools | Failed backend, zero outcomes, unrun compiler or invalid metrics -> pipeline not accepted |
| G2 | Per-profile data minimums; precision point >=.95, CI lower >=.90 and width <=.10; coverage point >=.40, lower >=.30; Brier skill CI lower >0; FDR comparator benefit, tau, OOD and subgroup gates | No probability bands |
| G3 | G2 plus precision lower >=.93, width <=.06; coverage >=.50, lower >=.40; null-ECE excess .03/upper .05; slope/intercept intervals; FDR relative reduction >=.25, shift precision >=.90; independent second annotator and verified owner signoff, reproducibility, frozen EXE smoke, UI caveat | No numeric probability |
| Safety/CI | Artifact/schema corruption rejected, calibrated results never override contested, snapshots immutable, no target execution/network, Windows/Linux actual tests, package integrity | No promotion/merge |

The gate thresholds come from tools/calibration/gates.py and the C9 draft, not observed measurements. A source-built Tier R pass cannot substitute for a Tier W Windows proof. Any stratum with too few independent groups is insufficient, not automatically passing.

## 6. Experiment matrix and artifacts expected

**R5-E01 / native-output admission:** For each real Tier R pair record compiler, SHA, engine success/failure/blocked, candidate count, truth label count and native output digest; assert nonzero when the fixture should yield results. Save a single minimal negative fixture for every parse/output defect.

**R5-E02 / split and identity integrity:** Reproduce SHA/PDB/project/identity contamination tests, including duplicates across independently named repos, source-level function rename, shared CRT and repeated mutation template. Artifact: split-audit.json, witness report, no lock consumption.

**R5-E03 / baseline:** Train M0/M0b/M1/M2 and grouped M3, with all held-out predictions, stratum counts, exact training weights, calibrator choice and C grid. Artifacts: dev-report.json, per-profile reliability.csv and risk-coverage.csv, learned-coefficients.json, eval manifest.

**R5-E04 / ablations:** Remove each dependency family, compare paired lineage-bootstrap CI at fixed coverage, quantify false matches and false abstention. Preserve each feature schema/fit digest, not only a summary score.

**R5-E05 / OOD:** Shift by compiler family/version, flags and architecture/domain, measure hard flag recall of errors, false flags on corrects, risk after abstention. Artifact: ood-shift.json and named failing cases.

**R5-E06 / selective guarantee audit:** Simulate cluster-correlated errors and compare false-certification rate at target risk; annotate statistical assumptions. Artifact: reproducible simulation code and JSON with seeds, N, clusters, ICC and confidence bounds. A standalone simulation is not proof of PatchTrace accuracy.

**R5-E07 / frozen test:** Only after protocol signature and dataset complete; one locked-result.json per defined held-out analysis, tied to receipt and SHA, plus unattested failures. No extra look after observing performance.

**R5-E08 / Windows package:** Verify a release-pinned Windows build loads valid and invalid artifacts, rejects wrong engine major/arch, displays correct ordinal fallback, preserves analyst review workflow and raw snapshots, and records exact executable checksum.

For every run log command, UTC time, host OS, Python/package/tool versions, commit and inputs, pydantic/schema versions, exit code, N pass/fail/skip/blocked, stdout/stderr digest, output digests and independent witness. Keep test-grade and real-data-grade evidence separate. A figure is generated from locked aggregates **after** gating; never publish raw Tier W code or paths.

## 7. Correctness tests to add before runtime behavior changes

~~~bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_calibration_math.py \
  tests/test_calibration_metrics.py \
  tests/test_calibration_cv.py \
  tests/test_calibration_tools.py \
  tests/test_calibration_runtime.py \
  tests/test_calibration_scope.py \
  tests/test_calibration_hardening.py \
  tests/test_tier_r_contracts.py \
  tests/test_tier_r_eval_metrics.py \
  tests/test_tier_r_eval_engines.py
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q
~~~

Additional red/green tests:
- All external promotion conditions absent/forged/mismatched -> no promotion.
- Soft engine-major mismatch cannot yield auto-accept without explicit domain compatibility.
- A test group/score outside training cannot alter learned means, calibrator, feature selection or tau.
- One repeated source function with different names cannot cross locked roles.
- A non-finite supplied FeatureRow never yields a numeric accepted decision.
- Contest, one-sided, N:M, missing engine, OOD, unsupported PE remain manual or abstain regardless of score.
- Model snapshot invalidation, restart/recovery, expired scope and stale UI must never show a pre-expiry numeric claim.
- Each changed Ghidriff/BinDiff/rz-diff feature schema invalidates old artifact or causes explicit warning/abstention.
- Tier W local reports cannot accidentally serialize Microsoft code or PDB symbol names.

## 8. Release and rollback

Even a successful G3 does not authorize automatic release or production deployment. Stage a signed-by-build-provenance artifact in an opt-in QA package, use pinned exact profile/domain, run a frozen exe smoke, validate with real analysts, then separately authorize the release. Keep the previous ordinal policy available. On artifact load/prediction/gate/domain/expiry error, **fail closed to L0** and log a non-sensitive reason. Never overwrite an original project snapshot; all calibrated output is derived with model/version digest. Never silently fall back to a different probability model.

**Session-specific execution record:** This dossier was authored from GitHub code inspection. None of the shell snippets was executed here. No compiler acceptance, Tier W labels, locked-test report, GUI package or current-head CI result is being claimed in these notes.
