# R6 — Final integration, end-to-end acceptance, patch search and Windows release

**Status: engineering dossier / release NOT READY.** Prepared 2026-10-30 against `main` at `a04f5a299a8d4afef023261e52e08d14678cf1e7`. Scope: the owner's R6 mission, with R1–R5 research in active draft PRs. This directory is an implementation-ready handoff, **not** evidence that these changes were built, merged, run locally, or validated on a clean Windows installation.

> **Non-negotiable distinction.** Source present ≠ merged fix ≠ unit tests passed ≠ native tools executed ≠ end-to-end accuracy accepted ≠ Windows package published. Preserve the original evidence and show the actual state of each gate.

## Decisions the R6 integrator should adopt

1. **Integrate instead of replacing.** The repository already has the Qt application, Ghidriff primary comparison, immutable runs, unified ProgramIR/L1/L2 engine, BinExport2/BinDiff/rz-diff adapters, KB correlation and acquisition, and a sophisticated but not yet accepted calibration system. Extend these contracts and fix demonstrated gaps. Do not implement an alternate matcher, CVE database, GUI, corpus factory, or probability system.
2. **Fix the evidence pipeline before tuning.** The live unified gate [run 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449) ended with an overall green workflow but 27 failed child jobs and a **NOT READY** gate report. Its fixture build produced 273 pairs; the A/A and release pipeline produced **zero measured outcomes**. Zero evaluated cases are not zero errors. Resolve the status/harness and real backend errors, then rerun G-U1–G-U8 on the exact code/image hashes.
3. **Adopt verified R1–R5 findings in small independent slices.** R1 supplies label admission and a reviewed deterministic pilot, R2 supplies bounded matching/fusion fixes and measurements, R3 supplies conservative proof fixes and falsification tests, R4 supplies source- and scope-aware vulnerability semantics, R5 supplies a calibration acceptance protocol and trust-boundary findings. These are active draft PRs, **not** functionality shipped on main.
4. **Prohibit false attribution.** A vendor CVE→KB/product claim, a verified older/newer PE pair, a matched function, a semantic change, and a hypothesis that this change fixes the CVE are **different statements**. Neither a Ghidriff “modified” row nor a generative model conclusion establishes vulnerability causation.
5. **Keep confidence ordinal.** An engine similarity value or multi-engine vote is not a calibrated probability. Numeric correspondence confidence is prohibited until valid held-out, lineage-separated Tier W evidence, trusted promotion checks, and all applicable G0/G2/G3 gates pass.
6. **Protect committed data.** Every sidecar, imported vendor snapshot and derived result must be identity-verified, versioned and atomic. Never mutate Ghidriff primary matches, existing completed results or analyst notes in order to make a newer experiment pass.
7. **Test native tools and the actual published package.** The “Windows standalone” ZIP/Setup packages bundle the PatchTrace desktop/Python/Qt; Ghidra, Java, Ghidriff and some optional engines remain external unless a separately verified offline runtime payload is provided. A passing PyInstaller build or synthetic backend is not full native acceptance.

## Repository and evidence snapshot

| Item | Verified value / exact qualification |
|---|---|
| Default branch | `main`, `a04f5a299a8d4afef023261e52e08d14678cf1e7`; PR #124 integrated |
| R1 corpus | [Draft #128](https://github.com/djshellshoxxx/patchtrace/pull/128), head `a02a1774a1617441072f4a8770348cc22038eeac` |
| R2 matching | [Draft #131](https://github.com/djshellshoxxx/patchtrace/pull/131), head `c704a39c8ece56c3215c1d765d79e7f4780ddcbd` |
| R3 semantic analysis | [Draft #129](https://github.com/djshellshoxxx/patchtrace/pull/129), head `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` |
| R4 vulnerability | [Draft #130](https://github.com/djshellshoxxx/patchtrace/pull/130), head `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` |
| R5 calibration | [Draft #132](https://github.com/djshellshoxxx/patchtrace/pull/132), head `4d9d9051aea87319847a0b321a14d37b95cb8abd` |
| Shared coordinator | [Draft #126](https://github.com/djshellshoxxx/patchtrace/pull/126); shared `docs/qa.md`, `tasks/todo.md` and integration ownership must be reconciled |
| Source QA | [Run 41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610), completed successfully on main; release job skipped |
| Primary native | [Run 41060959854](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959854), native Windows Ghidriff cases succeeded |
| rz-diff native | [Run 41060959715](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959715), Windows and Linux smoke succeeded; does not establish broad parser/accuracy coverage |
| Unified extraction | [Run 41060959558](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959558), native extraction jobs succeeded |
| Tier R shard | [Run 41060959579](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959579), smoke/shard merge succeeded with warning; not a full Ghidriff corpus evaluation |
| Unified end-to-end | [Run 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449): **NOT READY**, 27 failed jobs; G-U1–G-U8 incomplete |
| Last observed published prerelease | [v0.1.0-beta.543](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.543), 2026-10-29, target `f4063c3cc7e0c9d02d972e798699ad206628a5f1`; **not current main** |
| Primary baseline / support | Windows 11 x64, supported PE AMD64 input; static analysis only; desktop carries Python/Qt, analysis toolchains separate |

These are time-stamped observations. Before applying any instructions, refresh the remote SHA, open PR list, exact-head CI, local worktrees, untracked changes, workers, licences and source ownership. Branch ancestry alone cannot tell whether equivalent work was already merged by squash.

## Dossier navigation — read in this order

| Document | Why the implementer needs it |
|---|---|
| [01 — Repository and research reconciliation](01-repository-reconciliation.md) | Sources, owners, exact evidence, cross-PR collision map, safe integration and CI interpretations |
| [02 — Unified engine, semantics and persistence](02-unified-engine-implementation.md) | Current module boundaries and L1/L2 contracts, R2/R3 fixes, data model, implementation slices and acceptance tests |
| [03 — Secondary tools and native compatibility](03-secondary-tools-compatibility.md) | Real Ghidriff, BinExport2, BinDiff and rz-diff matrix, version/identity/orientation, cancellation, hard failure cases |
| [04 — Vulnerability intelligence and patch search](04-vulnerability-correlation-patch-search.md) | MSRC real-dialect blocker, CVE/KB/product/build, Winbindex, verified pairing, source graph, reversible search and evidence UX |
| [05 — Corpus, calibration, accuracy and performance](05-ground-truth-calibration-performance.md) | R1–R5 dependency closure, strict truth rules, locked tests, G-U1–G-U8, G0–G3, scale and statistical reporting |
| [06 — Qt workflow, security and Windows release](06-gui-security-release.md) | Persistent analyst workflow, hostile-input/privacy audit, recovery, package and clean-Windows acceptance |
| [07 — Executable acceptance plan and defect register](07-acceptance-defects-runbook.md) | Scenario A–J scripts/receipts, P0/P1/P2 defects with owner/test/gate, CI workflow corrections |
| [08 — Feature matrix, QA reconciliation and handoff](08-feature-matrix-and-handoff.md) | Unambiguous status/percentage rubric, dependency graph, task ordering, evidence templates and release decision |

Every file is written to guide an engineer who starts with an actual checkout. Commands are **proposed runbooks**, not tests claimed to have been executed in this documentation pass.

## Immediate critical path

`
SOURCE RECONCILIATION
  -> coordinate shared files, import verified R1/R2/R3 work
  -> repair native live-pairs result persistence and preserve actual failures
  -> R1 validated labels + real Ghidriff production pair
  -> L1 Tier R truth/ambiguity and L2 hostile semantic mutation gate
  -> real MSRC CVRF parser and product-scoped CVE/KB evidence
  -> two SHA-verified real PE images + correct update boundary
  -> complete offline GUI scenario from search to saved analysis/report
  -> real secondary backends, recovery, privacy and clean-Windows acceptance
  -> release gate and published SHA-verified build
  -> only then reconsider feature default and optional numeric calibration
`

The prerequisite chains are not strictly serial: MSRC source research, native tool provisioning, Windows GUI validation and independent security tests can proceed alongside corpus work in separate files/worktrees. A single integration owner must approve any shared contract changes.

## Mandatory source-of-truth and safety rules

Read `AGENTS.md`, `CLAUDE.md`, `SECURITY.md`, `docs/modules.md`, `docs/specs/unified-engine/00-decisions.md`, `01-architecture.md`, `02-data-model.md`, `04-matching-pipeline.md`, `05-fusion-and-noise.md`, `08-evaluation.md`, `docs/qa.md` and `tasks/todo.md` before changing code. For contract changes amend `10-amendments.md`, write red tests, implement, regenerate schemas, run focused then full Qt-offscreen pytest and Ruff, and require actual Linux/Windows CI plus real native acceptance where appropriate. Never run target EXE/DLL/SYS binaries. Do not force-push, bypass review protections, overwrite another worker, leak Microsoft binaries/PDBs or private tokens, or auto-promote a released model.

## Completion and handoff protocol

Each slice must report: base and head SHA; owner and source PR; touched files; requirements/spec decisions; before/after test cases with exit status and counts; actual native executable version, OS and input SHA pair; persisted output/manifest digest; GUI/CLI route; limitations and failed outcomes; CI run/job URL; reproducible steps; release impact; unresolved blockers; next owner. Never mark `pass` for `not run`, `queued` or `blocked`. Reopen old projects after every persistence change. Use the canonical [feature matrix](08-feature-matrix-and-handoff.md) to report completion dimensions separately.

**Current R6 recommendation: NOT READY.** This is a release-gate decision based on missing live evidence and verified outstanding gaps, not a claim that PatchTrace is generally unusable. Do not advertise full unified accuracy, causal CVE-to-function certainty, a fully offline backend, calibrated probabilities, or a clean Windows end-to-end release without corresponding receipts.
