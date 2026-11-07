# 08 — Essential feature completion, QA coordination and engineer handoff

**R6 reference:** main `a04f5a299a8d4afef023261e52e08d14678cf1e7` (2026-10-30); draft research PRs #128–#132; coordinator #126; R6 [draft PR #133](https://github.com/djshellshoxxx/patchtrace/pull/133). The percentages below are **conservative provisional evidence/readiness scores**, not independently measured “percent of code written,” story points, accuracy rates or accepted release progress. Real completion requires a new exact-head native and human test execution.

## 1. Fixed, reproducible scoring rubric

Per essential capability, assign a score in each of five dimensions:
- **I = implementation, 30%:** 0 = absent on main; 0.5 = partial/adapter/tooling; 1 = substantial main implementation.
- **J = integration, 25%:** 0 = no coherent product path; 0.5 = partial/offline/flagged integration; 1 = normal main product path.
- **T = automated tests, 20%:** 0 = no relevant exercised test; 0.5 = synthetic/test code but incomplete current-head results; 1 = substantial tests evidenced on current main (not necessarily real-world).
- **N = native/real acceptance, 15%:** 0 = no required genuine acceptance or current failed data; 0.5 = demonstrated genuine smoke but incomplete breadth; 1 = complete required real native/Windows acceptance. No N=1 is asserted in this dossier.
- **D = documentation and packaging, 10%:** 0 = not documented; 0.5 = developer specs/draft/partial release instructions; 1 = strong current docs, clear contracts/handoff.

Formula: `R = 30×I + 25×J + 20×T + 15×N + 10×D`. To avoid a high score hiding a current P0 data-integrity issue, the top score is capped at 60 for F10, F13 and F24. All other features are capped at 85 **until actual required full native acceptance is documented**. This produces a consistent, explainable **readiness estimate**, not a statistical confidence interval. Reviewers should revise entries only with a linked new SHA/test receipt and leave historical grades auditable. High I/T score does not automatically unblock release.

## 2. Main-branch feature-by-feature readiness matrix

Dimension column is `I / J / T / N / D` (values 0, 0.5 or 1). “Present” means a user-facing code route is present, **not** end-to-end passed.

| ID | Essential feature | Source spec | I / J / T / N / D | Estimated R6 readiness | GUI / output state | Main blockers/tests |
|---|---|---|---|---:|---|---|
| F01 | Project and PE ingest | SPEC-01/02, ingestion | 1 / 1 / 1 / .5 / .5 | **85%** | Present | A/G/H |
| F02 | Ghidriff primary comparison | SPEC-31 and backend | 1 / 1 / 1 / .5 / 1 | **85%** | Present | B/C; D-R6-001 |
| F03 | BinExport2 validation/producer | SPEC-10b | 1 / .5 / 1 / 0 / 1 | **72.5%** | Partial | N-BE, D-R6-008 |
| F04 | BinDiff native adapter | SPEC-29 | 1 / .5 / .5 / 0 / 1 | **62.5%** | Partial | N-BD, D-R6-008 |
| F05 | rz-diff integration | SPEC-11/28 | 1 / .5 / 1 / .5 / .5 | **75%** | Partial | N-RZ, D-R6-014 |
| F06 | Unified L1 ladder and fusion | SPEC-31 ``04/05 | 1 / .5 / 1 / 0 / 1 | **72.5%** | Present (flagged) | D-R6-007/013 |
| F07 | ProgramIR/Ghidra extraction | SPEC-31 `03 | 1 / 1 / 1 / .5 / 1 | **85%** | Partial | UE-05; G-U8 |
| F08 | Semantic L2/proof rules | SPEC-31 `05 | 1 / .5 / 1 / 0 / 1 | **72.5%** | Present (flagged) | D-R6-003, G-U2 |
| F09 | N:M groups and conflicts | SPEC-31 ``02/04/07 | 1 / .5 / .5 / 0 / .5 | **57.5%** | Partial | D-R6-013 |
| F10 | Project persistence and backups | SPEC-01/31 and storage | 1 / .5 / 1 / .5 / .5 | **60%** | Present | D-R6-005, G/H |
| F11 | Winbindex and acquisition | SPEC-acquisition | 1 / .5 / 1 / 0 / .5 | **67.5%** | Partial | D-R6-004; E/F |
| F12 | CVE/KB product correlation | SPEC-kb-cve | 1 / .5 / 1 / 0 / .5 | **67.5%** | Partial | D-R6-002/015 |
| F13 | Real MSRC CVRF provider | SPEC-kb search adapter | 0 / 0 / .5 / 0 / .5 | **15%** | Not real compatible | D-R6-002; VC-01/02 |
| F14 | Patch search/pair resolution | SPEC-kb patch search | 1 / .5 / .5 / 0 / .5 | **57.5%** | Partial | E/F; D-R6-004/015 |
| F15 | Enrichment and attention ranking | SPEC-07/WIL | 1 / .5 / .5 / 0 / .5 | **57.5%** | Partial | E/B |
| F16 | Tier R truth and mutation gates | SPEC-32/G-U | 0 / .5 / .5 / 0 / .5 | **27.5%** | Dev-only tools | D-R6-001/009 |
| F17 | Tier W real local corpus | SPEC-27/C9 | 0 / 0 / .5 / 0 / .5 | **15%** | Not accepted | D-R6-009/016 |
| F18 | Calibration framework | SPEC-27/28/C9 | 1 / .5 / 1 / 0 / 1 | **72.5%** | Ordinal only | D-R6-006/016 |
| F19 | Unified Qt analyst workflow | SPEC-04/31 `07 | 1 / .5 / 1 / 0 / .5 | **67.5%** | Partial | D-R6-012/018 |
| F20 | Evidence-backed exports | SPEC-report-export-v2 | 1 / .5 / .5 / 0 / .5 | **57.5%** | Partial | Scenario A/E/G/I |
| F21 | Windows desktop build and installer | SPEC Windows acceptance | 1 / 1 / 1 / .5 / 1 | **85%** | Beta published | D-R6-011/012 |
| F22 | Offline native runtime | SPEC-offline-backend | 1 / .5 / .5 / 0 / .5 | **57.5%** | Separate provisioning | D-R6-019 |
| F23 | Security/privacy/recovery | SECURITY; SPEC-31 G-U8 | 1 / .5 / .5 / 0 / .5 | **57.5%** | Partial | D-R6-005/010, H |
| F24 | R6 end-to-end release acceptance | R6 scenarios A–J | 0 / 0 / 0 / 0 / .5 | **5%** | Not accepted | D-R6-001/011/012 |

**Reading the scores correctly:** F02 and F21 can show high development readiness because main has working native primary smoke/desktop packaging, but the product remains **NOT READY** while F13/F16/F17/F24 and required acceptance are unresolved. F18 rates the existing *framework*, not the readiness of numeric probabilities. F16 considers only main status; the unmerged R1 pilot is described separately and is not counted as shipped functionality.

## 3. Evidence, GUI, remaining work and research per feature

| ID | Existing evidence | Next executable work | Outstanding research and evidence |
|---|---|---|---|
| F01 | Main CI 41060959610 | Real Windows create/save/reopen A, invalid input; source present | A/G/H |
| F02 | Native 41060959854 | R1 linked-patch native truth, identical status harness failure | B/C; D-R6-001 |
| F03 | Main sources; nightly fuzz | Real Ghidra-exported SHA-bound older/newer images; frozen producer | N-BE, D-R6-008 |
| F04 | Linux historical small research | Independently trusted pin and real Windows BinExport pair | N-BD, D-R6-008 |
| F05 | Native 41060959715 | Full native dialect/orientation/alternative set and regression | N-RZ, D-R6-014 |
| F06 | R2 source + G-U failed | R2 #131 integration, G-U3/U7, real pairs | D-R6-007/013 |
| F07 | Native 41060959558 | Real MSVC/GZF identity and robust native extraction | UE-05; G-U8 |
| F08 | R3 draft; negative tests | R3 #129 EH and register-only; zero false benign | D-R6-003, G-U2 |
| F09 | R2 draft audit | Additive stored group membership, roundtrip and GUI | D-R6-013 |
| F10 | Audit #121 / current code | Same-size/mtime tamper and interrupted recovery | D-R6-005, G/H |
| F11 | Existing acquisition tests | Measured Microsoft file SHA and genuine PA30/31, catalog | D-R6-004; E/F |
| F12 | Existing KBC unit tests | Real MSRC ProductID/Type-2, revision, scope conflicts | D-R6-002/015 |
| F13 | cvrf.py synthetic-only | Implement official dialect, pin real response and acceptance | D-R6-002; VC-01/02 |
| F14 | R4 draft / KBC code | Real CVE→KB→file→verified SHA pair→run/reopen | E/F; D-R6-004/015 |
| F15 | Existing enrichment code | Validate explanations against real evidence, no causal leap | E/B |
| F16 | R1 pilot; 41063115449 | Integrate R1 #128 and native labels / fix 0-outcomes | D-R6-001/009 |
| F17 | R5 docs, no accepted data | Owner-local real PE/PDB and independent labels | D-R6-009/016 |
| F18 | Source fit.py; R5 docs | Verify sign-off trust and G0/G2/G3, OOD/locked test | D-R6-006/016 |
| F19 | Main UI tests | Real A–J GUI scenario with keyboard/DPI/large data | D-R6-012/018 |
| F20 | Existing reports.py | Real source-to-function report, hashes/limits/contradictions | Scenario A/E/G/I |
| F21 | Beta.543 earlier SHA | Clean W-01/02/13/14, exact current R6 SHA package | D-R6-011/012 |
| F22 | backend_pin.json only | Airgapped Windows I and all pin/licence checks | D-R6-019 |
| F23 | Main source, audit #121 | Backup tamper, child env, malformed input and cancel tests | D-R6-005/010, H |
| F24 | 41063115449 NOT READY | All essential real native/GUI/KB/offline gates pass at released SHA | D-R6-001/011/012 |

Every row's **automated-test status** and **native-acceptance status** are intentionally independent. Before claiming an individual feature is 100% complete, link its current-head automated test report, real-tool run/provenance and GUI acceptance (where applicable), original-project consistency and release docs. If the tool is unavailable, mark it `BLOCKED/UNSUPPORTED` and document implications for accepted essential scope.

## 4. Contract and research dependency graph

```text
R1 ground truth + native Ghidriff pipeline
   -> R2 L1 matching/fusion (source-independent pair correctness)
   -> R3 L2 proof (material/cosmetic safety)
   -> G-U1..G-U8 genuine unified acceptance
   -> stable read model and single Qt project workflow
R4 official MSRC/source/product/KB
   -> Windows Winbindex/CBS/PA30/PA31 actual verified PE pair
   -> CVE/KB search -> existing project -> unified/function evidence
R5 model fitting/runtime
   -> independent Tier W lineages and labels + trusted prereg/signer
   -> G0 -> G2 -> G3 -> optional probability; ordinal otherwise
All above + backup/security/GUI/offline acceptance
   -> main exact-head CI + clean Windows A–J + release manifest
   -> READY/CONDITIONALLY READY/NOT READY decision
```

Research missing is **specific and experiment-scoped**, not a reason to stop all coding: correct independent labels, exact native parser orientation, relocation-target semantics, MSRC vendor data dialect, update provenance, BinDiff executable source/signature, false-benign statistical bounds, in/out-of-domain risk and end-user usability.

## 5. Immediate work packages and file ownership

| Phase | Priority / proposed owner | Files and expected deliverables | Exact exit |
|---|---|---|---|
| R6-I01 | P0 integrator | Updated PR/worktree ownership, branch merge-base, per-slice acceptance test, record blockers in draft R6 report | Every unique PR work item mapped to owner; no active worker overwritten |
| R6-I02 | P0 live gate owner | `tools/unified/live_pairs.py` and tests, native Ghidriff logs, Linux `libEGL` runner setup, real Tier R pair admission | Nonzero A/A/mutant outcomes, failed/blocked precise; original report preserved |
| R6-I03 | P0 data integrity owner | `verified_backup.py` plus test of same-size/mtime corruption and history pruning | Reproduced red, fixed green on Windows/NTFS and Linux |
| R6-I04 | P0 semantics owner | Review #129 `unified/facts/verdict.py` and R3 tests/spec; coordinate R2 | PC01/PC08, versioned proof change and native linked negative fixtures |
| R6-I05 | P0 MSRC owner | `kbcorrelation/sources/cvrf.py` and official-real fixture, synthetic backward compatibility | Real CVRF v3 ProductIDs/Type-2 remediations via offline CLI/GUI |
| R6-I06 | P0 native acquisition owner | `acquisition/*`, `kbcorrelation/pairs.py`, Windows CI and file trust | Two SHA-verified real PE x64 versions with correctly scoped update relation |
| R6-I07 | P1 L1 integrator | R2 #131 narrow fusion/IR/cfg/cache fixes, tests | All basic L1 and evidence preservation tests + G-U3/G-U7 |
| R6-I08 | P1 secondary tools owner | `secondary/*` and real BinDiff 8 / BinExport2 / rz-diff | N-BE/N-BD/N-RZ genuine input/out proof or explicit external blocker |
| R6-I09 | P1 UI/report owner | `ui_unified.py`, `kbcorrelation/panel_qt.py`, existing single-window read models, exports | Essential A–J GUI routes tested and saved/reopened |
| R6-I10 | P1 security owner | `backend.py` environment, `jobs.py`, PE/SQLite/download; privacy | No secrets inherited offline; hostile input and cancellation tests |
| R6-I11 | P1 calibration owner | `tools/calibration/fit.py` trust gate; R1/R5 owner-collab; ordinal policy | No self-attested promotion; C9/locked Tier W evidence or explicit blocked |
| R6-I12 | P1 release owner | CI aggregator + Windows portability/installer + optional offline bundle | Exact-head full acceptance and real release asset hashes; no false readiness |

Suggested time priority: I02, I03, I04, I05 are P0 and can run independently if isolated. I06 depends on official source and trusted binary availability. I08 must not fake missing BinDiff. I09/10/11 can start with synthetic UI/security tests, without preempting owner-shared files.

## 6. Paste-ready `docs/qa.md` reconciliation entries for the existing coordinator

**Do not directly edit the coordinator's current PR #126-owned `docs/qa.md` from this documentation branch.** The integrator should reconcile and append only after checking the current SHA, verifying the source run artifacts, and confirming no newer successful runs supersede these.

```markdown
### R6 research and gate baseline — 2026-10-30 UTC
- main SHA: a04f5a299a8d4afef023261e52e08d14678cf1e7
- Research PRs: R1 #128; R2 #131; R3 #129; R4 #130; R5 #132
- QA/main workflow: 41060959610 completed SUCCESS (Windows/Ubuntu QA/package; not end-to-end R6)
- Native Ghidriff: 41060959854 SUCCESS (specified native smoke only)
- Native rz-diff: 41060959715 SUCCESS (specified smoke only)
- Native unified extraction: 41060959558 SUCCESS (specified smoke only)
- Tier R shard: 41060959579 SUCCESS (incomplete G-U native acceptance)
- Unified live gates: 41063115449 overall workflow SUCCESS but 27 child jobs FAILED, 3 SUCCESS; gate verdict NOT READY
- Gate-report SHA256: 6328006a60e94c51aec6e0cc182f84bb3dbc8bfdd76c32685d0e888e06204710
- Blocking: zero evaluated A/A/release outputs, native backend failures, libEGL.so.1 unavailable on Linux integrity, G-U1..G-U8 incomplete.
- Main release: v0.1.0-beta.543 at f4063c3cc7e0c9d02d972e798699ad206628a5f1 (2026-10-29); NOT current main/R6.
- Source findings: CVRF parser synthetic-only; R3 benign proof guard on unmerged #129; backup trust cache same-size/mtime; calibration promote external conditions assumed true.
- Independent native tests in R6 document author environment: NOT RUN. Windows clean-profile end-to-end: NOT RUN.
- Required next evidence: actual Ghidriff outcome counts; real MSRC source/provenance; PE hash pair; G-U gate artifact; A–J clean Windows verification.
```

## 7. Paste-ready `tasks/todo.md` updates for coordinator

```markdown
### R6 — final integration: acceptance-led (not release-ready)
- [ ] [P0] Reconcile R1–R5 PRs #128/#131/#129/#130/#132, historical PRs and active worker ownership against current main; preserve unique work.
- [ ] [P0] Repair live unified gate harness native outcomes/status and input logging; rerun real Tier R A/A and all material mutants.
- [ ] [P0] Reproduce and fix trusted backup cache (size+mtime same-state tamper) before destructive prune.
- [ ] [P0] Integrate R3 pseudo cosmetic proof/EH/register guard with red tests and proof policy version.
- [ ] [P0] Implement/validate real official MSRC CVRF v3 dialect, ProductID/KB scope and provenance.
- [ ] [P0] Validate two real SHA-bound Windows PE versions and precise KB/product/build pair lineage (PA30/31/signature checks where needed).
- [ ] [P1] Integrate reviewed R2 fusion/evidence cap/determinism/CFG/cache and IR unmatched fixes.
- [ ] [P1] Run native Ghidriff/BinExport2/BinDiff/rz-diff compatibility and independent evidence conflicts.
- [ ] [P1] Complete G-U1–G-U8 with nonzero independent Tier R labels and locked thresholds.
- [ ] [P1] Add single-window source→verified pair→analysis→proof→correction→report GUI workflow and E2E A–J tests.
- [ ] [P1] Remove trust assumptions in calibration model promotion; require genuine Tier W/C9/locked independent evidence or preserve ordinal.
- [ ] [P1] Harden child environment/network, hostile PE/SQLite/Protobuf/ZIP inputs, cancellation and project recovery.
- [ ] [P1] Require exact-head CI native/unified success and a clean Windows release package from the audited SHA; no READY claim until all essential acceptance receipts.
- [ ] [P2] Measure large-data/Qt accessibility/performance, verify offline runtime bundle, align documentation and nonessential adapters.
```

## 8. Outstanding R6 research register

| ID | Question; current evidence | Smallest reproducible experiment and prerequisite | Exit |
|---|---|---|---|
| Q-R6-01 | How accurate is L1 on different Windows toolchains? Only synthetic/live smoke and R1 pilot labels | 40+ independent lineages of pinned source/PDB Windows x64, symbols-hidden native engines, grouped evaluator | G-U3 per compiler/optimization, real precision/recall CI and missed/ambiguous counts |
| Q-R6-02 | Does strict L2 ever prove a security-relevant material change cosmetic? R3 structural counterexamples | R3-PC01/08 plus linked reloc/EH/callee/guard mutants, independent source review | No known false benign; G-U2 on real measured cases |
| Q-R6-03 | Are B+B engine votes independent? Assumption only | Compare truth error rates by dependence component/evidence class with ≥30 B+B examples/class | G-U7 CI, unsafe class pairs joined/demoted |
| Q-R6-04 | Can current CVRF decode actual Microsoft product/remediation structure? Synthetic-only parser | Pinned real official CVRF JSON/XML revisions, schema audit, exact ProductID/Type-2 negative fixture | Verified real source adapter with acceptance |
| Q-R6-05 | Is an ordered Windows binary pair actually pre/post fix? Source index != signed package truth | Known KB, full PE hashes, catalog/servicing/PA30/31 checks and source link | Verified exact old/new SHA and uncertainty |
| Q-R6-06 | How should a single CVE map to many changed functions? No causal oracle | Source commit + binary symbol/patch diff, human verification, contrast unrelated LCU edits | Hypothesis trace/evidence grades, no unsourced causal claims |
| Q-R6-07 | Does BinDiff 8 produce stable Windows-native results on real inputs? Verified source pin incomplete | Independent trusted binary, Ghidra export of real known pair, native Windows CLI, deep SQLite/orientation | N-BE/N-BD acceptance, version and source digest |
| Q-R6-08 | Can numeric correctness be shown? G0/G2/G3 incomplete | Tier W independent truth, frozen prereg, trusted sign-off, locked single-look and OOD | G2/G3 pass with CIs, else ordinal |
| Q-R6-09 | Does offline Ghidra/Java/runtime actually work on disconnected clean Windows? Desktop prerelease only | Provision signed/checksummed external tool archives before disconnect, run frozen native analysis/search | Scenario I pass with network audit and logs |
| Q-R6-10 | Can backup trust survive same-size/mtime tamper? Current code trusts metadata | Actual altered SQLite and NTFS mtime restore, destructive-prune test | Old backup rejected and no valid history lost |
| Q-R6-11 | Are large histories/performance acceptable in Windows frozen Qt? Synthetic Linux results only | 10k/60k/250k IR and 100k-row GUI, Windows p95/RSS/IPC | G-U5 and W-03 thresholds met |
| Q-R6-12 | Are release claims tied to exact required native gates? Advisory can appear green | Inject failed G-U2 with green QA, missing native artifact and canceled job | No release-ready decision/required publish when mandatory gate fails |

## 9. Required artefacts and decision ledger

**Accepted checkpoint package (per slice):** source/head SHA, PR and reviewer, module spec/amendment, test source commit, manifest of verified inputs and legal provenance, raw tool logs and output digests, per-stage outcomes, exact OS/tool versions, measured native result counts, QA and release impact, rollback instructions. Preserve all failed/partial records, and mark re-run attempts with new immutable run IDs.

**Release package:** reconciled branch/PR inventory; R1–R5 integration summary with their SHA; essential matrix; unified/secondary/semantic/CVE search/performance/calibration/native reports; GUI A–J acceptance; security issue disposition; Windows ZIP/Setup SHA and tag; open defect/research registers; owner-authorized release decision and explicit unsupported features. A file named `report.md` or closed checklist is not itself an acceptance gate.

Current product decision remains **NOT READY** because the required native evidence, real vendor correlation and source-paired Windows GUI workflow have not passed. The development baseline is functional in multiple paths, but R6 completion cannot be established by synthetic tests or by the release of an earlier beta.

## 10. Handoff to the next autonomous integrator

1. Fetch main/PR refs and open worktree list; record exact active owners and instruction files. Do not overwrite anything dirty, bypass protection or submit a GitHub APPROVE review on another person's behalf.
2. Read this dossier, source specs and full R1–R5 documents. Compare each draft's fixes to main to avoid replaying already merged work; amend any stale assumptions with exact SHA.
3. Start with real live-harness red test and backend logging, and small independent high-impact security, fusion and semantic fixes. Commit and push reproducible checkpoints as separate PRs.
4. Reconcile shared `docs/qa.md` and `tasks/todo.md` with PR #126's owner; do not paste this snapshot over their active edits.
5. Integrate only reviewed, green exact-head changes; run real native Windows/Linux and separate error/blocked reporting. Fill this matrix with **new actual evidence**, not inflated scores.
6. Continue through full CVE/KB→verified pair→native comparison→analyst report and clean Windows acceptance. Publish an R6 release candidate only if the authoritative gate is READY; otherwise preserve an honest NOT READY record and a next-task handoff.
