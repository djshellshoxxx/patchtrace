# R5 — Statistical calibration, confidence semantics, false-match control

**Status: research and implementation audit; NOT an accepted calibration release.**  
**Prepared:** 2026-10-30  
**Repository baseline inspected:** main at a04f5a299a8d4afef023261e52e08d14678cf1e7 (PR #124 merged).  
**Working branch:** chatgpt/r5-calibration-research-20261030.  
**Input:** owner's R5 research brief, existing SPEC-27/28, SPEC-31/32, C9 preregistration v1 and calibration code.  
**Mode of evidence:** source/contract review through the connected GitHub repository; literature review and reproducible research protocol. No local PatchTrace checkout or calibration data was available to this session. No new PatchTrace tests, Tier R/Tier W accuracy experiments, or Windows acceptance runs were executed. Historical results quoted here are identified as prior repository records, not this session's test results.

## Decision in one paragraph

PatchTrace already has the **structure of a calibration system**: typed feature extraction, ordinal-only default, dev-only training, grouped CV, leakage checks, lineage bootstrapping, conservative artifact loading, OOD detection, threshold selection, optional secondary-engine features and GUI display boundaries. It **does not yet have evidence sufficient to advertise a calibrated correspondence probability** for Windows system binaries. The R5 engineering path is therefore to reconcile existing R1–R4 work, repair high-priority trust-boundary and statistical-assumption issues, assemble independent labels, freeze the protocol, execute a lineage-separated evaluation, validate out-of-distribution behavior, and only then consider a bundle promotion. Do not implement a parallel calibration framework.

## Navigation

1. [Live code and evidence inventory](01-implementation-audit.md) — specific modules, boundaries, contract versions, current verification and risk findings.
2. [Scientific methods and preregistered protocol](02-statistical-methods.md) — calibration methods, prediction targets, sampling, leakage, clustered inference, selection, metric suite, comparison rules and primary-source references.
3. [Corpus, evaluation, and reproducibility runbook](03-data-and-experiment-runbook.md) — build/admission pipeline, working CLI syntax, manifests, gate reporting, locked-test protocol, expected evidence files and executable acceptance matrix.
4. [False-match, shift, artifact, and UI engineering](04-robustness-policy-and-ui.md) — failure taxonomy, OOD behavior, proposed fixes, feature ablations, analyst-facing explanations, regression fixtures, and cross-layer policy.
5. [Prioritized implementation handoff and R6 dependencies](05-engineering-handoff.md) — owner-aware tasks, review gates, evidence register, acceptance criteria, blockers and copy-ready QA/tracker updates.
6. [Executed dependence illustration](06-dependence-toy.md) — analytic toy calculation showing why naive function-level iid risk testing fails when functions share lineages; **not** a PatchTrace performance estimate.

The files above are deliberately separate from runtime contracts and any locked preregistration. Research alternatives are **not permission to silently change frozen C9 thresholds or the shipped model schema**.

## Essential invariant map

- **Target A:** correctness of a one-to-one candidate function correspondence (same source-level function under the adopted label standard). Only this target is implemented for calibration today.
- **Not target A:** whether a function changed materially, whether a patch fixes a vulnerability, causal attribution to a KB/CVE, or analyst review status. Those require **independent targets and separately preregistered datasets**.
- Ghidriff remains the primary comparison source; BinDiff and rz-diff are secondary observations. Engine-native similarity and engine-native confidence are not probabilities; missing evidence is unknown rather than disagreement.
- Unified L1 pairing, L2 materiality and human corrections remain separate. Contestation and non-comparable N:M relationships are not overridden by model probabilities.
- Primary project snapshots and raw tool output stay immutable; calibrated results are derived, traceable records. No target image is executed, and no private Windows binary/PDB is committed or silently uploaded.
- **Current user-visible level: ordinal.** No released probability is justified by the inspected evidence. Tier R / test-library results cannot authorize a Windows system-file claim.
- A locked final test is evaluated once according to a sealed protocol; the score or threshold may not be tuned after inspection of that test. A source code implementation existing is not equivalent to an empirically validated claim.

## Evidence levels used throughout this dossier

| Level | Meaning | Allowed statement |
|---|---|---|
| Observed code | Specific code and tests exist at checked main SHA | Implemented interface or guard, not statistical performance |
| Historical QA | A checked-in QA report, PR, or CI run describes an earlier execution | Prior result only; environment and exact head must be specified |
| Protocol | Written spec, preregistration, threshold or fixture plan | Requirement, not an observed acceptance result |
| Literature | Published statistical/binary-similarity work; assumptions differ from PatchTrace | Methodological evidence, not PatchTrace accuracy |
| Hypothesis / audit candidate | Potential correctness weakness inferred from code or assumptions | Investigate with regression or experiment; not yet a demonstrated defect |
| Blocked / unknown | Required artifact, independent label, validation run, or owner action missing | No pass and no numeric guarantee |

## Live repository reconciliation

| Topic | Inspection on 2026-10-30 |
|---|---|
| Default branch | main, a04f5a299a8d4afef023261e52e08d14678cf1e7 |
| R5 branch before this work | No R5 branch returned by GitHub branch search |
| Open PRs | 23 at inspection; refresh before merge |
| R1 research | [#128](https://github.com/djshellshoxxx/patchtrace/pull/128), ground-truth corpus, in progress; do not duplicate label ownership |
| R3 research | [#129](https://github.com/djshellshoxxx/patchtrace/pull/129), semantic proof accuracy, in progress |
| R4 research | [#130](https://github.com/djshellshoxxx/patchtrace/pull/130), CVE/KB/product/build provenance, in progress |
| Calibration overlap | [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) preregistration; [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) output persistence; [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) and [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) recipe/noise controls; [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) corpus candidates |
| Coordination | [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) owns milestone ledger and shared QA/handoff reconciliation |
| Existing C9 protocol | [docs/plans/c9-preregistration-v1.md](../../plans/c9-preregistration-v1.md) is a **draft**, with lock SHA placeholder and pending owner sign-off; do not regard final test as released |
| Historical Tier R G-U note | R1 [README](https://github.com/djshellshoxxx/patchtrace/blob/codex/r1-ground-truth-research-20261030/docs/research/ground-truth-corpus/README.md) on #128 reports 273 built pairs but zero A/A outcomes in the observed failed live gate; these are **not** precision/recall measurements |

**Ownership:** This R5 PR owns only docs/research/calibration-r5/. It does not modify shared specs, QA/tracker files, calibration runtime, corpus files or active R1/R3/R4 branches. Specific change proposals are prepared for a subsequent integrator-owned and regression-tested slice.

## Minimum release decision

A future numeric display requires all applicable G0/G2/G3 dataset, evaluation and external review gates, tested Tier W Windows-system-code coverage, nonexpired valid artifact provenance, verified domain compatibility, independently reviewed labels, and acceptance on untouched locked test lineages. Pass/fail/insufficient-data must remain distinct. The present dossier authorizes **no** promotion.

**Next action:** Start with the prioritized P0 tasks in [05-engineering-handoff.md](05-engineering-handoff.md); synchronize with the R1/PR #128 data owner before collecting or consuming truth labels. Re-check PR heads, CI, and current main immediately before any implementation or merge.
