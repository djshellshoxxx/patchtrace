# R5 / 05 — Prioritized engineering handoff, blocker register, and R6 integration prerequisites

**Prepared:** 2026-10-30. **Inspected main:** a04f5a299a8d4afef023261e52e08d14678cf1e7.  
**R5 owner:** proposed calibration research/integrator, docs isolated to this directory.  
**Truth boundary:** No R5 Tier W labels, frozen-test report, numeric calibration artifact or current-head native-run acceptance was produced in this GitHub-documentation session. The correct product state is ordinal-only.

## Executive disposition

R5 **research and implementation audit notes** are ready to hand to an engineer. R5 **scientific and product acceptance is not complete**. C9 training/inference machinery and safety fallbacks are already present. The critical path runs through independently defensible truth labels and a sound calibration acceptance protocol, not through adding an unvalidated model. This handoff gives ordered tasks, file owners, input contracts, tests and exact exit artifacts.

## 1. Current project/research dependencies

| Input stream | Source/owner | Evidence at inspected baseline | Handoff requirement |
|---|---|---|---|
| R1 corpus and label truth | PR #128, docs/research/ground-truth-corpus/; Tier R source factory | Research in progress; cited native gate failed with zero A/A outcomes, though 273 pairs were constructed | Obtain verified labels, nonzero native engine evaluation, source/license/pin identity, manifest and split audit |
| R2 matching/benchmark prior art | docs/research/calibration/prior-art-corpus-factories.md, docs/research/phase-c/matching-calibration-ground-truth.md, older Tier R/engine work | Relevant sources already researched; no separately verified complete R2 accuracy report in this inspection | Reconcile actual outputs, don't duplicate research or claim R2 complete from a file title |
| R3 semantic changes | PR #129, docs/research/semantic-analysis-r3/ | L1/L2 proof implementation exists; proof-contract EH discrepancy hypothesized; no full false-cosmetic acceptance | Keep L2 independent of A; pass class-wise mutation and G-U semantic safety gates |
| R4 CVE correlation | PR #130, docs/research/vulnerability-correlation-r4/ branch | Research/documentation in progress; no proof that A score implies KB/CVE correctness | Separate KB -> product -> binary -> patch -> changed function provenance confidence |
| C9 calibration | src/patchtrace/calibration/, tools/calibration/, SPEC-28 | Core machinery built, validated primarily on synthetic data; no admissible G0/G2/G3 Windows report | Retain existing framework and fail-closed policy; add real-data admission, proof and promotion checks |
| Unified engine | src/patchtrace/unified/, SPEC-31, G-U1..G-U8 | L1 pairing, L2 semantic facts, ordinal fusion exist | No numeric score inside fusion or proof system until independent policy specifically accepts it |
| GUI/product | secondary/evidence_view.py, unified/read_model.py, scope.py | Ordinal current state; numeric bands/number read model not production integrated | Analyst explanation must distinguish native score, evidence tier, pairing likelihood, L2 and CVE |
| CI/release | .github/workflows, PyInstaller Windows packaging | Historical CI in docs/qa.md; this session did not execute a job | Exact-head Linux and Windows CI, pinned native engines, frozen EXE smoke and rollout gate |
| Shared tracking | PR #126, docs/qa.md, tasks/todo.md | Active coordinator owns changes to shared status files | Apply copy-ready updates from §5 by coordination rather than competing edit |

Refresh open PRs, heads, repository rules and worker ownership **before** touching any shared code.

## 2. Critical execution packets (ranked)

### R5-P0-A — Reconcile authoritative truth dataset with R1

**Assigned:** R1 corpus owner + R5 dataset evaluator. **Files:** R1-owned tools/calibration/tier_r, corpus/ours, Tier W data outside tree; R5 only consumes agreed data/metadata.  
**Input:** exact manifest, labelled source revisions, compiler recipes, engine raw output with version and symbols-hidden flags, lineage/identity graph, natural sampling list.  
**Tasks:** audit public-source pin/license and reproducible hash; reproduce source-to-binary truth; adjudicate ICF, thunks, inlining and duplicate source symbols; validate natural/adversarial split; link all duplicate/near-duplicate copied code; record independent labels and errors. Repair native R1 "identical" backend result parsing and 0-outcome recording with a red/green test under R1 ownership, rather than masking skipped results.  
**Tests:** tier_r contracts/factory/labeler/evaluate, lineage/guards leak tests, native Ghidriff and rz-diff on source-built pairs, Windows MSVC/clang where required.  
**Output:** verified natural candidate rows, label-audit report, exact role-and-manifest digest, engine-output completeness report, case failure witnesses and license matrix.  
**Exit:** R1 verifies real matching-engine results, independently defensible source truths and no split leakage; otherwise R5 data-gate is BLOCKED. No minimum G0 claim from synthetic examples.

### R5-P0-B — Validate theoretical risk-control assumptions before numeric language

**Assigned:** calibration statistician + integration owner. **Files:** research experiments under tools/calibration/ (only if uncontested), existing cv.py/threshold.py/stats.py/gates.py after spec-first review; new tests owned by this packet.  
**Input:** exact C9 proposed alpha/delta/tau, lineage distribution, weights, ICC assumptions, current LTT code and dev OOF protocol.  
**Tasks:** reproduce a cluster/null simulation with known actual risk; compare measured false-certification probability to nominal delta; study dev-selected threshold optimism, effective-n rounding and binomial dependence assumptions; assess independent group-held-out calibration split. If the existing method is unsupported, retain its computation as a heuristic or modify under a **new prereg version** before any final-test look. Do not silently change prereg v1 after lock.  
**Tests:** deterministic simulation harness with fixed seeds, empirical false-certification CI for null cells, threshold boundary cases, ICC=undefined, extreme unequal clusters and weight ratios, frozen split proof.  
**Output:** mathematical assumptions note, reproducible simulation configuration/results, risk-control protocol decision, signed-off threshold criterion.  
**Exit:** a justified conditional statistical guarantee or explicitly limited empirical rule; no unqualified distribution-free guarantee.

### R5-P0-C — Harden model promotion and engine-domain checks

**Assigned:** calibration runtime integrator; must coordinate specs and release pipeline owners. **Files:** calibration/{policy,ood,artifact,predict}.py, tools/calibration/fit.py, packaging config, schema generator, tests/test_calibration_runtime.py and tools tests.  
**Input:** agreed current feature schema, Tier W domain, CI conditions and immutable report/prereg/label digests.  
**Tasks:** red test that forged/missing owner signoff/repro/frozen-EXE evidence cannot promote; replace default assumed-true external conditions in fit._reproduce_gates with trusted attestation verification. Domain-compatibility guard: engine major, BinExport producer, arch/PE class and profile must be explicitly supported before numeric/auto-accept; a soft engine-version flag alone must not justify acceptance. Add last-boundary nonfinite-feature rejection without changing ordinal semantics. Ensure old artifacts/failed imports are safe and schemas are versioned.  
**Tests:** fake accepted report with missing attestations, wrong exact engine version, unsupported architecture, malformed SHA, duplicate profiles, expired model, developer override, nonfinite feature, missing family, contested, one-sided and N:M.  
**Output:** reviewed code and spec PR with before/after red/green tests, current-head CI, trusted release-attestation contract, no Windows claim from Tier R.  
**Exit:** **no path** from an untrusted or wrong-domain artifact to a numeric/auto-accept decision; original results never mutate.

### R5-P0-D — Lock an admissible protocol and run real native measurements

**Assigned:** product owner, dataset owner, statistical integrator; **requires P0-A/B/C decisions**.  
**Tasks:** settle C9 O1 Tier W legal/publication, O2 independent second annotator, O3 targets/policy/rounding, O4 Tier W families and Windows-only budget; resolve prereg Q1/Q2 and write precise source list. Freeze C9 file bytes (or a justified v2) and record SHA. Allocate 60/25/15 lineage roles and declared shift lineages, ensure group source separation. Execute pinned native Ghidriff/rz-diff/BinDiff (only where available) on validated data. Evaluate dev models M0/M0b/M1/M2/M3/M4, ablations and OOD. **Only after dev freeze**, execute single locked-test through authorized process; preserve failure and report shift separately.  
**Output:** locked-test aggregate with exact digests/receipt, per-profile Brier/log loss/ECE/reliability, ROCs/PRCs, precision/coverage/FPR/FNR, lineage-bootstrap intervals, ablation gains, shift and subgroup risk, independent approval ledger.  
**Exit:** reproducible statistical metrics and gates with real Windows samples; if G0/G2/G3 fail or data insufficient, the correct outcome is **ordinal + explicit remaining blockers**.

### R5-P1-E — Make trained feature profiles representative of production

**Assigned:** evaluation owner + runtime feature engineer. **Files:** calibration/features.py, tools/calibration/train.py and serialization tests, no parallel framework.  
**Problem:** Tier R current adapter may omit G match types and use synthetic callee counts; full production feature vector differs.  
**Tasks:** serialize exact feature names, provenance and numeric values for representative native Ghidriff/secondary records from both the training adapter and runtime extractor. Require parity or declare the reduced domain; measure feature missingness and source dependency, use a versioned schema where necessary; evaluate proper G, G+R, G+B, G+B+R profiles separately. Do not label data with an untrusted engine score.  
**Exit:** byte-identical or equivalence-justified train/serve vectors for measured input population with per-profile evidence, or explicit narrowed support.

### R5-P1-F — Failure reduction and OOD under real data

**Assigned:** binary-matching engineer + statistical evaluator + R3 collaborator. **Files:** own targeted fixtures and tested calibration metrics, avoid changing R3 proof files without coordination.  
**Tasks:** exercise FP-01…FP-12, FN-01…FN-04 and CAL-01…CAL-06 in [04-robustness-policy-and-ui.md](04-robustness-policy-and-ui.md). For every real failure, preserve independent source labels and the exact pair/alternative/atom graph. First fix source-correctness problems in L1/L2, then refit/ablate A model; do not "calibrate away" incorrect matching or hide a semantic materiality defect by lowering confidence. Validate Mahalanobis flag error enrichment, categorical-domain abstention and version drift with group-held-out outcomes.  
**Exit:** per-class false-match/error table, before/after group-CI and native non-regression suite; known blind spots and review routing recorded.

### R5-P1-G — Analyst GUI and reporting contract

**Assigned:** Qt GUI owner + calibration read-model owner, after G2/G3 evidence. **Files:** unified/read_model.py, secondary/evidence_view.py, scope.py, UI/export serializers and tests.  
**Tasks:** keep raw engine score with source-specific unit, evidence tier and L1/L2 verdict distinct. Display validated band only if G2 and number only if G3 plus valid domain/attestation/expiry; C9 floor-down-to-5% rounding applies **only** to accepted target A. Show contested alternatives, missing input, model profile, engine producer, OOD status, calibration population and provenance. Link analyst edits as independent explicit records, never retroactive training features. GUI absence of a number must not remove evidence-strength semantics.  
**Exit:** fully bounded and accessible views, session/project switch safety, exports preserve original provenance and cannot advertise a raw percentage as probability; Windows screen-reader and frozen smoke evidence.

### R5-P1-H — Windows packaging, CI, release and rollback

**Assigned:** release integrator.  
**Tasks:** pin source/engine versions and supported package profile; build Windows on Windows, not Linux cross-compile; verify legal payload license and SHA; run full offscreen Linux pytest+Ruff and Windows pytest, native engine/parity acceptance, package smoke. Confirm any promoted artifact is bundled and loaded from trusted package data only; dev override remains experimental; expired/failed/changed model returns ordinal and does not crash.  
**Exit:** exact commit+CI+package+model SHA evidence and human release decision; do not automatically deploy.

## 3. Work that must remain explicitly out of scope

No automatic vulnerability likelihood, CVE exploitability score, malware execution, external upload, redistributable Microsoft binary/PDB cache, changed R1 truth labels to improve metrics, unreviewed boosted model as a mandatory dependency, false "two independent engines" agreement for shared Ghidra export, unproven semantic equivalence, or final-release automation. Do not widen PatchTrace's feature roadmap to unrelated AI guidance, static-analysis engines or UI decoration during this R5 gate.

## 4. R5 deliverable accounting

| Owner R5 requirement | Delivered in this documentation PR | Outstanding external/code/evidence prerequisite |
|---|---|---|
| Calibration research report | README + 02 methods | A completed measured research report |
| Live implementation inventory | 01 audit | Exact refreshed PR reconciliation, current-head CI |
| Ground-truth quality report | 03 label admission plan and 01 gaps | Native R1/Tier W labelled rows and adjudication audit |
| Leakage prevention | 02 matrix, 03 tests | Run manifest and function-identity audits on real corpus |
| Feature ablation | 02 comparison design | Actual per-family dev experiment and paired CI |
| Model comparison | M0–M4 protocol in 02 | Measured grouped native outputs |
| Reliability diagrams and metrics | 02 definitions, 03 output contract | Generated real charts/tables from held-out rows |
| OOD report | 04 domain grid and protocol | Shift lineages, measured flags and errors |
| False-positive/negative taxonomy | 04 FP/FN/CAL register | Verified fixtures and defect correction |
| Validated artifact | Conservative artifact and gate audit | G0/G2/G3 report + owner signoff; **not produced** |
| Policy improvements | 01 P0 defects, 04 policy behavior spec | Red/green runtime implementation and CI |
| GUI integration | 04 design contracts | Accepted model evidence, UI tests and owner approval |
| Regression tests | Exact fixtures/test names in 03/04 | Actual code/tests, Linux and Windows results |
| QA/task updates | Copy-ready coordinator text in §5 below | Shared files controlled by #126, not edited in this PR |
| Research blockers | §6 register | Resolve legal, data, platform and statistical issues |
| R6 final integration handoff | §7 dependencies and staged handoff | R6 recipient's environment and signed acceptance |

This table intentionally does not call R5 "complete": required empirical outcomes are missing.

## 5. Copy-ready coordinator updates — NOT YET APPLIED to shared files

Recommended new section for docs/qa.md, to be merged by the integration coordinator:

> R5-20261030: Research/implementation audit under docs/research/calibration-r5/ at main a04f5a2. Verified code paths and versioned contracts via GitHub source inspection. No new local pytest, Ruff, Windows CI, native Ghidriff/rz-diff/BinDiff calibration benchmarks, Tier W labels, locked-test, numerical report, confidence artifact or GUI number acceptance performed. R1 #128 corpus still in research, with a previous failed native G-U gate and no demonstrated match accuracy from its built sample count. C9 v1 prereg SHA not recorded at inspection; numeric display remains ordinal. Audit P0: external promotion attestations are assumed in fit._reproduce_gates; unknown engine version is a soft OOD flag in ood_flags, while policy abstains only on hard; LTT exact-binomial effective-n guarantee under cluster weighting needs independent justification. Regression/experiment specs in R5 notes; all acceptance gates insufficient/no result until evidence exists. Shared-file updates are integrator-owned.

Recommended new subsection for tasks/todo.md, after current C9 entries and PR-head refresh:

- [ ] R5-A: consume R1 #128 independently validated Tier R/Windows truth and native outcomes; audit label provenance, duplicates and split integrity.
- [ ] R5-B: resolve cluster-dependent LTT risk guarantee and dev OOF threshold selection bias; prereg any protocol change before locked test.
- [ ] R5-C: replace assumed external promotion conditions with independently verified sign-off/CI/smoke evidence; exact engine-version/domain abstention; finiteness defense tests.
- [ ] R5-D: settle O1/O2/O3/O4, freeze prereg and sample/role manifest, execute audited Tier W native benchmark and single locked evaluation.
- [ ] R5-E: train/serve feature parity, M0–M4 ablations and grouped precision/Brier/ECE/risk–coverage plus independent bootstrap CIs.
- [ ] R5-F: OOD/shift and FP/FN fixture validation, no invented numeric or false independent-engine claims.
- [ ] R5-G: after G2/G3 and separate UI review, implement scoped bands/numbers, test Linux/Windows/frozen executable and guarded rollback.
- [ ] R5-R6: feed immutable verified results into unified-engine release decision; do not merge as completion until acceptance gates.

These entries are documentation suggestions. **Ownership:** #126's coordinator should reconcile and commit them rather than overlapping an active writer.

## 6. Blocker / uncertainty register

| ID | Blocker / unknown | Depends on | Can proceed independently? | Escalation decision |
|---|---|---|---|---|
| B-R5-01 | No independent representative Tier W labelled population and locked-test report shown | Owner Windows machine, legal permission, acquisition and annotators | Yes: Tier R / source audits, synthetic correctness tests | O1/O4 and labelled corpus admission |
| B-R5-02 | C9 prereg draft and lock not yet approved/recorded | O3, Q1/Q2 and sample design | Yes: review draft before any locked look | Exact owner signoff and file SHA |
| B-R5-03 | Independent second annotator not confirmed | O2, label guideline and budget | Yes: devise blind labeling tool and audited source labels | G3 cannot pass without an independent second reviewer |
| B-R5-04 | Full Tier R native outcome pipeline had historical failure | R1 #128 and native backends | Yes: inspect failure fixture and design regression | Zero outcomes never becomes a passed gate |
| B-R5-05 | Some B profiles require BinExport/BinDiff executable and input | Provisioned compatible engines | Yes: run G and G+R only, mark others unavailable | No B-model claim without native B outputs |
| B-R5-06 | Risk-control guarantee under clustered functions uncertain | Statistical review, simulation proof | Yes: maintain ordinal fallback, implement conservative external gate | No unqualified "certified" wording |
| B-R5-07 | Promotion lacks trusted external prerequisites | Release/integration code ownership | Yes: write red tests and spec | G2/G3 cannot be trusted by declared flags alone |
| B-R5-08 | Engine version/producer drift domain policy ambiguous | Domain spec and validation data | Yes: implement fail-closed regression in owned branch | Unknown major should abstain until approved compatibility |
| B-R5-09 | No exact-head Windows/frozen GUI acceptance from this session | CI runners, Windows PyInstaller | Yes: pure code + offscreen Linux suite | No Windows packaging claim |
| B-R5-10 | R2 benchmark artifacts and active historical PR diffs not exhaustively reconciled | Integrator remote branch inventory | Yes: continue R5 distinct file ownership | Re-check before any cherry-pick or merge |
| B-R5-11 | Real subgroup coverage inadequate for all rare transforms/OOD | R1, R3 and Tier W sampling | Yes: keep insufficient-data strata separate | No extrapolation to unseen class |
| B-R5-12 | GitHub-connected research environment lacks a local PatchTrace checkout/native Windows executables | Coding executor with repo checkout | Yes: source review, docs and host-independent statistical examples | No assertion of freshly executed repo tests |

If O1/O2/O3/O4 are unresolved, record the explicit required approval and perform independent research and test fixture design; do not repeatedly consume data or lock test.

## 7. Exact R6 final-integration handoff contract

R6 may start final integration only with *all* of the following objects and SHA references from R5:

1. **Reconciled repository manifest:** main SHA, open/merged PR table, worker ownership/changed files, resolved R1/R2/R3/R4 dependency revisions, current AGENTS/security rules.
2. **Provenance graph:** project/version/source lineages; binary/PDB/engine hashes and tool versions; Tier R/Tier W legal and measured support; trusted sample/label audit; distinct natural/adversarial/shift roles.
3. **Statistical evidence:** frozen prereg SHA and owner acceptance, model candidate/profiles, independent calibration labels, OOF/dev selection provenance, exact locked-test receipt and report, baseline comparison and group-CI, calibration/OOD metrics and subgroup limitations.
4. **Engine + L2 safety:** L1 contested/ambiguous/manual semantics preserved, G-U1..G-U8 pass/fail/blocked table, L2 material/cosmetic proof provenance and false-cosmetic controls. An A score must never override semantic classification.
5. **R4 correlation boundary:** KB/CVE/product/binary evidence with exact source URLs/digests, dated build linkage and confidence/correlation uncertainty stated *without* borrowing A probabilities.
6. **Trusted artifact/release:** feature schema/model/policy/dataset digests, independent gate attestation, exact domain/engine version, package SHA, Windows frozen smoke, rollback to ordinal.
7. **User experience:** audited raw engine evidence, ordinal tier, candidate decisions, calibrated display only if G2/G3, OOD/unknown/contested state and analyst review; accessible and no misleading percent.
8. **Gate review:** current-head Linux/Windows tests, lint, native benchmarks, source snapshots unchanged, no target execution/network, legal guard, security review and explicit human authorization before release.

**R6 procedure:** refresh main, close/merge reviewed compatible R1–R4+R5 changes in dependency order, rerun native corpus plus integration suites at the resulting exact SHA, run a cross-module E2E sample from acquisition -> project -> binary pair -> Ghidriff/secondary -> unified L1/L2 -> KB/CVE graph -> GUI/report, preserve every raw/provenance record, run Windows packaged smoke, and produce a sign-off matrix. If data or approval is missing, ship only the well-tested ordinal alpha behavior and record the blocked calibration feature. A docs-only R5 PR is not grounds to mark final product complete.

## 8. End-of-session report template

- Checked default SHA: a04f5a299a8d4afef023261e52e08d14678cf1e7; R5 docs branch and draft PR as linked in README.
- Research: inventory, model-method comparison, strict data and evaluation runbook, false-match/OOD/control taxonomy and priority task handoff.
- Experiments executed **in this repo session**: none on PatchTrace checkout or Tier W; independent illustrative calculations must say so separately.
- Metric table: Brier **not measured**, ECE **not measured**, N natural/negative/lineages **not established**, precision/coverage **not established**, G0/G1/G2/G3 **not demonstrated**.
- Code defects corrected: none; audit candidates logged for regression.
- Tests: none executed by this session; historical QA is prior evidence only.
- Known limits: research-only; no frozen artifact/no new Windows data/no production release.
- Next command: start P0-A/B/C in parallel under disjoint owner scopes with exact branch/PR reconciliation.

**Final status:** R5 documentation and handoff prepared; R5 empirical and software acceptance **open**.
