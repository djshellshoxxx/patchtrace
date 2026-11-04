# PatchTrace release blockers — exact evidence and gates

**Verdict: NOT READY for a new fully accepted current-main release.** Main `a04f5a299a8d4afef023261e52e08d14678cf1e7`, assessment from integration `f18687fd035b67961c1072af84f8c2b3442979e0`. The previous [v0.1.0-beta.543](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.543) published 2026-10-29 with ZIP/Setup/Linux assets, **before** main #124 was merged; it is not an attestation of the current implementation. A subset of main exact-head QA/native tests passed; an independent unified evidence pipeline and Sonar check did not.

## Mandatory gates for a verified essential Windows alpha

| Gate | Present evidence | Status | Blocker / required proof | Ticket |
|---|---|---|---|---|
| RB-01 live unified G-U1–G-U8 | [run 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449): 273 built fixture pairs, 27 failing child jobs (26 live pairs/mutants and one Ubuntu bench), 0 observed evaluated pairs; advisory parent green | **FAIL** | Repair actual first failure in child logs; ensure verified >0 evaluated A/A, release, mutant pairs on Windows and Linux; per-class numerator/denominator and signed exact-head report | GT-01 |
| RB-02 held-out correspondence/materiality precision | R2 #131 native cJSON 262/side, two reviewed positives; real Windows Tier W final not validated, R1 #128 active | **UNVERIFIED** | Predeclared independent positive/negative labels and release acceptance threshold, leakage/lineage controls, held-out real PE results, no false-benign regression | GT-02/04/05 |
| RB-03 real secondary/native interoperability | Main live rz-diff workflow passed selected CI, but R2 native rz-diff 20/22 strict-parser attempts failed and two parsed runs showed conditional reversal; BinDiff native oracle requires licensing/pin | **PARTIAL** | Versioned native BinExport2/BinDiff/rz-diff receipts, identity+orientation+source ownership, end-to-end persistence/GUI; unsupported cases visibly abstain | GT-03 |
| RB-04 vendor correlation/verified patch pair | `kbcorrelation/sources/cvrf.py` synthetic placeholder dialect; #130 research not merged, #136 fixtures pending | **UNVERIFIED** | Real pinned MSRC/CSAF, Winbindex exact SHA, product/revision/build lineages, actual positive + negative pair; never function→CVE causality | GT-06/07 |
| RB-05 clean Windows GUI analyst journey | Qt/Windows CI passed selected jobs; no recorded one-pass clean Win11 native KB→pair→unified→report acceptance at current SHA | **UNVERIFIED** | Manual + automated clean-profile, keyboard/DPI, cancellation/reopen/review/report and no-backend UX | GT-08/09 |
| RB-06 security host isolation | Static guards and selected native CI. `--no-symbols` ≠ OS air-gap; hostile deadline/process tree pending | **UNVERIFIED** | Win11 OS deny-egress probe, sensitive env inheritance, timeout/RSS/Job Object kill-tree, hostile binary and archive resistance with original results intact | GT-10 |
| RB-07 actual candidate asset integrity | v0.1.0-beta.543 published with Portable ZIP, Setup, SHA256 files; old head | **UNVERIFIED** | Current code-head reproducible frozen ZIP/Setup build, real extracted/installed smoke, release assets/checksum/commit provenance, correct notices | GT-09/13 |
| RB-08 CI exception reconciliation | main `a04f5a` 58 check-runs: standard QA, Qt, native Windows Ghidriff and rz-diff successes; SonarCloud failure and failing unified child jobs | **OPEN** | Triage exact Sonar annotations, check required-policy impact; distinguish advisory/optional from mandatory but never reclassify true failures as success | GT-01/10/13 |
| RB-09 owner/spec integration | R1–R8, #126, #136 and legacy PRs open; integration documentation ahead of main | **OPEN** | Content-level ownership and branch disposition, merge only independently reviewed passing work, no source/QA overwrites | GT-00/14 |

## Conditional gates: not prerequisites to a limited, correctly labelled alpha

| Feature | Current state | Policy |
|---|---|---|
| Numerical calibrated correspondence probability | R5 #132 defines research and protocol; valid Tier W locked test missing | Keep **ordinal-only**. Optional probability enablement requires separate labelled calibration promotion gates, cannot block a strictly ordinal beta |
| AI provider inference | Mocked/contract tests; live model and privacy/false attribution acceptance unverified | Make **optional/disabled** unless explicit configured consent; no auto CVE fix claim |
| Fully offline native runtime bundle | Installer/producer tested with synthetic bundles; real relocatable Ghidra/JDK/Ghidriff/Python and disconnected Windows acceptance missing | Advertise **manual external backend** only; never claim full offline no-setup runtime |
| Diaphora, QBinDiff-inspired expansion, N:M inference, R7 high P-code slicing | Independent plans/prototype/issues #35/#36/#39, no release acceptance | Defer as optional; prevent code duplication and label experimental |
| Windows code-signing | Existing portable package may be unsigned; signing policy must be explicit | Unsigned pre-release can be accepted if plainly disclosed and required integrity artifacts pass; no fabricated trusted signature |

## Release-gate evidence capture template

Required for each gate receipt:
```yaml
gate: RB-01
repository: djshellshoxxx/patchtrace
head_sha: exact 40-character SHA
workflow_run_id: integer
job_ids: [integer]
platform: Windows 11 x64 or pinned runner
source_pair_sha256: {older: digest, newer: digest}
engine_versions: {ghidra: version, ghidriff: sha, bindiff: pinned-or-absent, rzdiff: version}
build_recipe_sha256: digest
case_count: positive integer
evaluated_count: positive integer
passed_count: nonnegative integer
failed_count: nonnegative integer
unknown_count: nonnegative integer
cancelled_count: nonnegative integer
outcome: PASS | FAIL | INSUFFICIENT_DATA | BLOCKED
artifact_sha256: digest
limitations: [explicit text]
reviewed_by: github user / review link
```
Never fill template fields from an earlier SHA; no empty list or zero-evaluated pipeline is a PASS. A successful parent job with failing matrix children is insufficient. For gates requiring licensed binaries or real Windows, record the exact access blocker and keep optional tasks isolated.

## Exact next action to remove highest-value blocker

1. From [unified gate run 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449), collect failing Ubuntu/Windows live pair and mutant step logs; identify common exception, process argv, output root, data identity and first failure time. Preserve all raw receipts. This audit observed the 27 failed job conclusions and failing steps through GitHub but **did not retrieve all their logs** or prove one root cause.
2. Reproduce an identified fault in the smallest fixture and write regression before modifying the handler; never alter expected status to make CI green.
3. Rerun exact-head per-OS pair/mutant jobs; publish counts of genuinely evaluated positive and negative cases and any case exclusions. Recompute G-U1–G-U8. Keep the gate closed when data are missing.
4. Only after this gate is credible, integrate approved R2/R3/R8/secondary changes and rerun all affected gates for the new SHA.
5. Freeze a release candidate after remaining RB gates, run clean Win11 and reproduce checksum integrity. Include explicit unsupported optional feature limitations.

## Why earlier green jobs do not unblock release

The exact-main CI native Windows Ghidriff matrix and standard QA are genuine **scoped** successful results. They validate selected tool installations and fixtures. They do not prove held-out vulnerability matching precision, full CVE provenance, strict rz-diff performance across real binaries, airgap isolation or clean Windows GUI acceptance. This separation is fundamental to preventing a premature complete-status assertion.

## Primary evidence

- [Main head commit](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7)
- [Consolidation assessment](https://github.com/djshellshoxxx/patchtrace/blob/main/docs/audits/20261030-consolidation-review.md)
- [G-U live workflow](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449)
- [R2 native results and integration findings](https://github.com/djshellshoxxx/patchtrace/pull/131)
- [R4 MSRC placeholder analysis](https://github.com/djshellshoxxx/patchtrace/pull/130)
- [R6 final integration dossier](https://github.com/djshellshoxxx/patchtrace/pull/133)
- [Latest prerelease](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.543)


## 2026-10-30 exact-job failure-log follow-up — GT-01 diagnostic checkpoint

The assessment subsequently fetched raw GitHub Actions logs from [unified gate run 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449), instead of inferring root causes from job summaries. Distinguish the following independently:

- **Ubuntu benchmark/integrity** job `124087550789`: `pytest` fails during `pytestqt` initialization with `ImportError: libEGL.so.1: cannot open shared object file: No such file or directory` (job log line ~319, exit 3). This specifically evidences a runner's missing Qt-linked runtime library, **not** a demonstrated source-code logic defect. Required: add/verify proper Linux EGL runtime dependency for this job, then rerun exact head.
- **Ubuntu A/A and release pairs** job `124094490545`: A/A path/rebuild cases report `RuntimeError: Ghidriff run identical: None`. Other same-build transformations and release comparisons report `PT-BACKEND: ghidriff exited with code 1; Filesystem permissions or locks prevent Ghidra analysis; check writable paths; inspect analysis.log`. The message is a *classifier*, not proof filesystem permissions caused the upstream failure. Required: preserve/fetch the exact `analysis.log`, original argv and project scratch paths to determine actual cause. Determine whether byte-identical A/A cases should be recorded as a valid unchanged control or as a skipped, explicitly excluded case.
- **Windows A/A and release pairs** job `124094490578`: A/A path/rebuild cases report `Ghidriff run identical: None`; others report `UnifiedError: PT-UNIFIED-INPUT: The unified inputs are not usable [no-completed-run]`. This is an observed missing prerequisite completed Ghidriff run, not proof that unified matching produced an incorrect verdict. Trace comparison state and run identity before touching the matcher.
- **Next red-first action:** separate runner provisioning, identical-input control semantics, underlying native Ghidriff execution/analysis output, and resulting unified no-completed-run precondition into independent repros. Preserve the failed result artifacts; treat no evaluated rows as insufficient data. Only after repairing actual causes should rerun A/A and changed pairs in both orientations and compute real G-U denominators. Do not simply suppress these failures or loosen thresholds.

These log snippets were observed from the named 2026-10-30 run; no fix or new CI run is claimed.

