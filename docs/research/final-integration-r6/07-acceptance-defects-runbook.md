# 07 — Executable acceptance matrix, defect register, CI gates and reproducible runbook

**Scope:** mandatory R6 end-to-end scenarios A–J, failing live unified baseline, real backend compatibility, security and packaging. **Status at 2026-10-30:** acceptance design and investigated current evidence; **not executed** in this documentation pass. Revalidate command syntax with current `--help` and applicable `AGENTS.md` on an actual checked-out revision before use. Use Linux and a genuine Windows 11 x64 runner for platform-specific claims.

## 1. Definition of an acceptance result

Each test row must include: unique ID, requirement/spec ref, step version, exact git SHA and merge-base, test/OS/runner identity, start/end UTC, CLI command and effective config, fixture manifest and both PE SHA, labels and independent witnesses, external executable versions and binary hashes, source raw result digest, expected/actual values, collected/pass/fail/skip/blocked counts, manifest/output digest, status, specific failure category, log/CI URLs and responsible owner. **A missing input or unavailable tool is BLOCKED/INSUFFICIENT, never PASS.** A queued CI job is QUEUED, not PASS or FAIL. An overall green advisory workflow is not equivalent to green child jobs or quality gates.

Before any changed-code acceptance: record the original project snapshot SHA, copy/backup verified project to an isolated directory, capture pinned external tools and input. After acceptance: compare hashes, project history and note contents, and note every intentional derived change separately.

## 2. Scenario A — Create a persistent project and analyze two Windows PE x64 files

**Goal:** demonstrate the basic user-facing product, not a sample-only frontend.

- Inputs: two permitted real PE32+ AMD64 DLL/SYS/EXE files with known size/SHA, selected older/newer orientation and valid local Ghidra/JDK/Ghidriff.
- Steps: launch frozen or dev GUI, New Project, choose both, show PE overview and raw byte views **before** analysis, verify identity and compatibility, configure native backend, run primary Ghidriff, run unified if enabled, inspect function list and at least one paired function, save, close and reopen.
- Expected: original and derived run IDs in history, artifact SHAs unchanged, correct nonzero function inventory when source has functions, analysis success or legitimate identical status, deterministic pair orientation and code/IR view, no stale error or duplicate current set, original run unchanged after unified.
- Negative variants: wrong machine, malformed PE, unreadable path, two equal images, identical file names but different SHAs, file changed after selection, Unicode folder and OneDrive-style sync root.
- Evidence: Windows GUI screenshots/accessibility record, Ghidriff native output and versions, project manifest/raw/unified hashes, database integrity report and reopen pass. Backend mock alone does not satisfy A.

## 3. Scenario B — Known source-level security patch

- Inputs: R1 admitted public-source old/new compiled Windows-targeted PE pair with linked changes, independent source-to-function truth and real native backend; include a true semantic change and benign relocation control. If using a Windows cumulative security update instead, state what cannot be attributed to a specific source commit.
- Steps: verify labelled source/PE/PDB hashes and symbols-hidden engines, run Ghidriff/unified, locate expected old/new RVA(s), inspect L1 decision and L2 delta, check case-specific source witness and all “unmodified/cosmetic” judgments.
- Expected: material source mutation appears as `material` or `review` (no unsupported benign proof); correct correspondence if independently demonstrable; out-of-scope/ambiguous remains unknown; any attempted CVE association remains a separate sourced analyst hypothesis.
- Evidence: label manifest SHA, independent reviewer, actual source/build hashes, true/false/abstained row matrix, semantic proof IDs, native logs/CI job.
- Reject if only mock IR or fabricated patch description was used.

## 4. Scenario C — Compiler noise and false-benign controls

- Inputs: source-equivalent A/A images, rebuild nuisance options link order/ICF/timestamp/GUID/path, and different optimizations, plus **material** same-shape changes including relocation to different symbol, callee, branch predicate, register/frame/EH.
- Steps: run each eligible pair, record L1 precision and L2 confusion table per transform, evaluate every `UNCH/1` / `COS-*` proof and target map, compare Ghidriff and unified output; run genuine Windows/MSVC and cross-Linux controls where licensed.
- Expected: no material mutation misclassified benign; A/A true identical shows no spurious material; compiler-induced differences beyond proof scope return review/unknown rather than guaranteed equivalence. Coverage denominator and unanswered cases exposed.
- Evidence: generator recipe, compile flags/target, exact image hashes, per-class outcome counts, false-benign tally and independent proof review.
- Do not treat “different compiler flag but equal source” as proof that every observed native difference is cosmetic.

## 5. Scenario D — Genuine multi-engine conflict and orientation

- Inputs: two valid PE SHA and trusted native Ghidriff, plus real BinExport2/BinDiff and rz-diff where provisioned; adversarial static fixture with two possible correspondences, renames/ICF and conflicting endpoints.
- Steps: run each genuine engine, preserve raw/native SHA and output, normalize coordinate basis and older/newer, fuse with current dependency registry, inspect contest alternatives in GUI/CLI; compare reversed orientation and repeated run.
- Expected: independent component and evidence class rules honored, no fake B+B from correlated algorithms, contest visible with sources, manual correction reversible, no last-wins loss; missing engine is unavailable, not negative vote.
- Evidence: executable versions/digests, raw output artifacts, atoms with alternative endpoint, decision manifest, correction history and no original snapshot change.
- A synthetic injected `SecondaryMatchSet` is unit testing only; not native engine acceptance.

## 6. Scenario E — CVE-first patch search

- Inputs: actual official source-permitted and SHA-pinned monthly CVRF (or other vendor artifact with verified adapter), known CVE with exact product applicability, Winbindex/candidate and verified old/new source files. Suggested research case: `CVE-2024-38143` / `KB5041585`, but verify official data before treating as accepted.
- Steps: import permitted source, search CVE offline, select ProductID/release/build/arch, inspect Type-2 vs mention-only and conflicting statuses, resolve update and file candidates, create verified pair and native comparison, link changed-function evidence and export.
- Expected: all source pointers, coverage and product alternatives visible; correct two final full PE SHAs; no function causality claim from change alone; no silent network; re-open and recover context.
- Evidence: original source URL/revision/SHA and parser version, ProductID pointer, update metadata, measured PE hashes, run/result IDs, GUI and report receipts.
- Current P0 blocker: main CVRF parser only accepts synthetic dialects. Synthetic source fixture does not satisfy E.

## 7. Scenario F — KB-first patch search and supersedence

- Inputs: genuine Microsoft KB, published product/build applicability and candidate binary versions across update revisions.
- Steps: search KB offline, enumerate product/release/arch and direct/inferred supersedence, resolve component names only from sourced evidence, detect same hash across KBs and missing predecessor, inspect candidate pair scope, compare and save.
- Expected: direct KB relationships separately from mention and supersedence; no cross-product KB join; multiple candidate hashes left ambiguous; no fabricated historical prepatch file.
- Evidence: source revision/pointer, supersedence chain and scope, hash/version candidate list, unknowns, selected plan and actual native run if bytes are available.

## 8. Scenario G — Durable reopen and repeatability

- Steps: save finished project with multiple runs, manual match correction, notes, KB context, GUI layout/settings and export; close app; backup and restore project; restart app on another OS-compatible user profile; reopen all historical runs; repeat analysis with same and changed engine config.
- Expected: full original artifact SHA, raw results and run IDs unchanged; derived result stable for identical inputs; new result key for changed policy/tool/version/source; notes retained; no orphan enrichment cleanup; read-only old-project migrations safe.
- Evidence: before/after snapshot and unified manifests, SQLite quick/integrity checks, journal recovery, exported JSON and history transcript.

## 9. Scenario H — Failure recovery and hostile input

- Inject: process-tree cancel during Ghidra, crash before unified pointer publish, corrupt temporary .BinDiff, invalid Winbindex/CSAF/CVRF input, interrupted export, low disk, exclusively locked project, parent environment with dummy secrets, stale cache, symlink/path traversal, changed source SHA, same-size/mtime backup tamper, nested malicious protobuf and SQLite, failed PA30/PA31 reconstruction.
- Expected: typed bounded failure; children and grandchildren terminated, no private network without consent, no leaked secret in child/out, no false checksum or trust status, no overwriting committed previous run/backup and clear recovery in GUI.
- Evidence: captured state transitions, process tree/handles, old and restored hashes, per-input rejected reason, elapsed/RSS and response to cancellation. Treat a true input validation failure as test PASS only when its **expected** rejection is correctly observed.

## 10. Scenario I — Offline operational test

- Windows 11 x64 disconnected VM, all relevant external tool packages acquired separately and verified before disconnection, no Python/Ghidra network access; optionally preseed approved MSRC/Winbindex source cache, a known signed/hash-checked pair and local Ghidriff/Ghidra/JDK.
- Steps: verify NIC/host firewall disconnection and network audit, start actual frozen desktop, create project, inspect PE, run primary/unified, perform cached CVE/KB search, notes and report without any connector/proxy/telemetry/symbol-server request.
- Expected: full workflow succeeds to extent supported by locally provisioned runtime; absent optional provider clearly unavailable with stale-source notice; no attempted socket connect. A desktop-only sample that doesn't perform native analysis is **not** scenario I.
- Evidence: VM manifest/OS build, runtime/executable SHA, network trace/audit, PE and output hashes, real GUI record, source-cache provenance.

## 11. Scenario J — Published Windows portable/installer release

- Build reviewed R6 commit in Windows QA matrix, verify `tools/frozen_smoke.py` and full Windows package CI plus release gate; publish only under existing authorized release policy.
- Download *published* ZIP and Setup assets from exact release, compare release SHA/size with CI artifact, extract/install on clean Windows profile, perform A/E/G/H/I applicable workflow and uninstall preserving user-created data.
- Expected: pinned version/commit metadata, notices, no placeholder dependencies, no missing Qt resources, frozen workers/extractor available, real backend configured correctly, accurate release notes explicitly listing unsupported features.
- Evidence: release tag/peeled commit, asset digests, runner/tester, screenshots, PDB/licence restrictions, signing status and public URL. Beta.543 is earlier main and not proof of a future R6 candidate.

## 12. Priority defect register (verified observations versus research hypotheses)

| ID / severity | Status/evidence | Exact owner and proposed change | Regression / gate to close |
|---|---|---|---|
| **D-R6-001 P0** | **Confirmed failed acceptance:** [41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449) 27 failed child jobs, 0 evaluated A/A/release outcomes | Native harness owner: `tools/unified/live_pairs.py` and actual backend logs; handle legitimate `identical` without fabricating matches, fix other root causes separately; make aggregate status fail closed | Nonzero A/A, mutation, genuine Ghidriff results; preserved raw errors; G-U1–G-U8 reports and exact result hashes |
| **D-R6-002 P0** | **Confirmed source gap:** `cvrf.py` supports only synthetic `cvrf-json/0` / `cvrf-xml/0` | MSRC adapter owner: real CVRF v3 schema, pinned official source and versioned adapter preserving synthetic | Two real monthly source captures with ProductIDs/Type-2 rows, conflict/status tests, offline CLI/GUI E/F |
| **D-R6-003 P0** | **Draft unmerged R3 source fix:** absent EH guard/register-only pseudo blocker on main | Semantic owner: review #129 `facts/verdict.py`, `PSEUDO_BLOCKERS`, proof policy digest; redact/test counterexample | PC01/PC08 red→green, material false-benign = 0 on eligible mutants, actual Windows linked PE cases |
| **D-R6-004 P0** | **No accepted real MSRC+two verified PE+fix boundary** | R4 acquisition/native owner: Winbindex/source hash, PEx64, Windows PA30/31/Authenticode/catalog, source/KB product scope | Two final measured PE SHA, older/newer credible window, native acquisition and E/F |
| **D-R6-005 P0** | **Source-observed data durability risk:** `verified_backup.py` cached trusted verdict uses only size+mtime | Persistence owner: first reproduce same-size/mtime-tamper before history prune, then implement rehash/verified trust before destructive action | Backup tamper red/green Windows/NTFS and Linux; no history prune using stale copy; G/H |
| **D-R6-006 P0** | **Source-observed calibration promotion trust risk:** `fit.py::_reproduce_gates` forces 4 external conditions true | Calibration trust owner: independently verified, externally signed/authorized evidence and fail-closed ordinal | Forged/missing sign-off, frozen smoke and prereg receipt rejected; never numeric by self-assertion |
| **D-R6-007 P1** | **Unmerged R2 code fixes** (fusion cap/order/CFG/cache and leftover projection) | L1 integrator: narrow reviewed #131 slices, no whole-branch stale overwrite | Real provenance, deterministic atom/component, `matching/2` cache miss, all tests and original SHA |
| **D-R6-008 P1** | **No proven native complete BinDiff on real PE pair**; BinDiff pin `verified:false` | Native-tool owner: verify signature/digest, genuine Ghidra export, Windows headless BinDiff 8 and SQLite deep check | N-BE/N-BD real output, cancel/reversed/partial SQLite rejection, pinned SHA |
| **D-R6-009 P1** | **Sparse R1 labels/actual Tier W**; no universal precision evidence | R1/R5 independent owners: admit corpus, source/PDB truth and lineage-separated tests | G-U3 and G0; natural, A/A, mutation/shift report denominators and CIs |
| **D-R6-010 P1** | **Source-observed child env inherited by default** `backend.restrict_env=False` | Backend/security owner: restricted default and compatibility allowlist; actual Ghidriff runtime tests | Dummy secret no child inheritance, socket audit, Windows/Linux native and frozen |
| **D-R6-011 P1** | **Release has no hard native/unified gate**; green advisory workflow masks failures | CI/release owner: required aggregate gate keyed by exact SHA, no zero/missing report PASS | CI fail-injection, missing artifact/job fails closed; release not triggered if declared essential gate fails |
| **D-R6-012 P1** | **Real end-to-end GUI E/F and clean Windows I/J unmeasured** | Integration/QA owner: existing single Qt window + project/KB/run/export wiring and native Windows test | A–J receipt matrix; no CLI-only essential workflow |
| **D-R6-013 P1** | **N:M persisted group evidence incomplete** per R2 audit | Unified store/read_model owner: additive group rows, legacy readers, UI alternatives | N:M split/merge/collision roundtrip, no invented 1:1 or hidden endpoint |
| **D-R6-014 P1** | **Secondary rz-diff parser/orientation anomalies** per R2 native probe | rz adapter owner: inspect raw 0.9.1 output and strict dialect/known input orientation | N-RZ-01/02 with exact tool SHA, alternatives, native parser acceptance |
| **D-R6-015 P1** | **Independent source/provenance graph from R4 is design, not live bridge** | KB integrator: additive read-only graph, source lineage and reverse SHA index | VC-01..18, deterministic reverse SHA and no false CVE→function |
| **D-R6-016 P1** | **Calibrated accuracy not accepted**; C9 prereg draft, Tier W absent | Calibration owner: G0/G2/G3 held-out truth, independent reviewers and signed external receipt | Zero unauthorized numeric UI; locked/test single-look and OOD acceptance |
| **D-R6-017 P2** | **Malformed optional Diaphora SQLite time/alloc risk** described [audit #121](https://github.com/djshellshoxxx/patchtrace/issues/121) older SHA | Optional security owner: verify current code, absolute wall-clock deadline, bounded subprocess and RSS | Slow-per-row malicious SQLite must hit global deadline, no partial record; optional feature doesn't block if disabled |
| **D-R6-018 P2** | **Perf and accessible large Qt histories not measured on clean Windows** | Qt/perf owner: model virtualization, processing limits and keyboard/screen-reader QA | 10k/100k rows, 100/150/200% DPI, NVDA/Narrator, p95 responsiveness |
| **D-R6-019 P2** | **Backend offline bundle packaging not proven as distributed** | Runtime packaging owner: exact pin verification, local installation and network-off native run | Source/provenance hashes, proper offline backend smoke and I |
| **D-R6-020 P2** | **R1–R5 PRs and historical overlaps unmerged/unreconciled** | Integration owner: preserve unique commits, compare main functionality and current reviews | Exact branch inventory and child PR diff; no active worker overwrite or redundant patches |

The P0/P1 labels are **release priority recommendations**, not externally assigned vulnerability severities. “Source-observed” describes a code risk, not a reproduced exploit; “unmerged” is not a confirmed main bug repair.

## 13. Prioritized implementation dependency order

```text
Gate 0: inspect updated main/worktrees/owners/AGENTS + secure branch
    |-- independent P0 D-R6-005 backup integrity and D-R6-010 env tests
    |-- P0 D-R6-001 native live-harness/root-cause => 273-pair measured outcomes
    |      -> R1 source-built ground truth + UE-01 R2 + UE-02 R3
    |      -> G-U1/G-U2/G-U3/G-U4 => G-U5/G-U6/G-U7/G-U8
    |-- P0 D-R6-002 real vendor MSRC parser => product/KB graph
    |      -> verified real binary pair, native PA30/PA31/signing
    |      -> CVE/KB search -> persisted real run and report
    |-- Native BinExport/BinDiff/rz-diff and GUI workflows
    |-- C9 trusted calibration (optional numeric; keep ordinal by default)
    -> required R6 CI aggregator -> clean Windows A–J -> published asset SHA
    -> release gate decision; evidence-backed handoff
```

**Parallelization:** one integrator owns shared contract/DB/`ui.py`/`docs/qa.md`/`tasks/todo.md`/release workflows. Worker A owns live-harness/unit fixture tests, B fusion/ladder, C semantic facts, D MSRC source importer, E acquisition native Windows, F label/calibration local datasets, G Qt acceptance/packaging. Do not concurrently edit central schema or same feature files; if two workers need one module, serially hand off a reviewed commit. Use disjoint branches/worktrees; do not overwrite active workers or their dirty local-only changes.

## 14. Environment preflight and focused commands

**Python** >=3.12 and project locked dependencies in `pyproject.toml`; current Windows/Ghidra binary analysis may require Ghidra 12.0.4, Java 21, Ghidriff pin and optional external tool. Test-lab setup should install *project* dependencies only, not unrelated packet-analysis libraries.

```bash
git status --short
git worktree list --porcelain
git fetch --prune origin
git rev-parse HEAD
gh pr list --repo djshellshoxxx/patchtrace --state open --limit 100
python --version
python -m pip install --only-binary=:all: -e ".[dev,calibration-dev]"
python -m patchtrace --help
python -m patchtrace unified --help
python -m patchtrace secondary --help
python -m patchtrace kb --help
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Check optional extras exactly in `pyproject.toml` before installation; the quoted install command assumes extras exist on that head. Use `python -m pip check` afterward, record resolved versions and state whether Ghidra/Java are actually installed. Keep `PATCHTRACE_CALIB_ROOT` outside the checkout, do not copy Windows binary/PDB data into public test fixtures.

**KB focused smoke:**
```bash
python -m pytest -q tests/test_kbc_ids.py tests/test_kbc_cvrf.py tests/test_kbc_index.py tests/test_kbc_products.py tests/test_kbc_lineage.py tests/test_kbc_pairs.py tests/test_kbc_resolver.py
python -m pytest -q tests/test_acquisition_delta.py tests/test_acquisition_winbindex.py tests/test_acquisition_workflow.py
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_ui_kb_panel.py tests/test_ui_acquisition.py
```

Check each path exists before batch execution; absent test names should be reported, not silently ignored. **Calibration unit smoke:**
```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_calibration_math.py tests/test_calibration_metrics.py tests/test_calibration_cv.py tests/test_calibration_tools.py tests/test_calibration_runtime.py tests/test_calibration_scope.py tests/test_calibration_hardening.py
```

**Native live commands:** obtain exact flags from `python -m patchtrace unified run --help`, `secondary run --help` and `kb ... --help`. Use verified real PE files and legal locally provisioned tools. Do not execute native Ghidriff via an invented CLI flag, do not run a target binary, and do not start network acquisition without specific operator-approved hosts/plan. Save logs including failures.

**Full post-change gate:**
```bash
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q
# Run existing schema generator and drift test only after confirming current command.
# Trigger all required existing Linux and Windows workflows for THIS head.
# Consume gate-report/1 and external artifact checks; do not use workflow badge alone.
```

## 15. CI workflow corrections required for release-grade evidence

Proposed minimal change:
1. Add a purpose-built release-acceptance aggregation job (or an external attested status) which gathers **the same exact head SHA** and verified result manifest digests for each required native gate. Enforce a policy table deciding essential vs optional engine by accepted release configuration; all essential must pass.
2. For `unified-live-gates.yml`, leave exploratory advisory jobs non-gating if desired, **but produce a separate machine-readable failed/blocked/insufficient result that a required aggregator can consume**. Report zero outcomes and missing lineages as NOT READY irrespective of workflow conclusion.
3. Keep `qa-windows.yml` existing `qa` + `qt-gate` + `linux-smoke` dependency (verified current main); do not regress it. Add clean Windows release smoke with a representative actual analysis and persistent project/KB search case; do not use sample-only smoke to replace native.
4. Distinguish source PR CI, exact-head main CI, native BinDiff provisioning, local-only Tier W (cannot upload private PDBs) and manual Windows human acceptance. A nonpublic Tier W receipt must expose hashes/statistics without disclosing bytes and be explicitly signed/approved.
5. Use unique run/commit keyed artifacts with immutable digests, no recycled latest-run artifact ID and no “skipped equals passed” fallback. Check workflow conclusions, then every required job and **its internal gate verdict**.
6. Rehearse fault injection: force a Qt-only test failure, missing native tool, zero-labelled corpus, invalid source SHA, cancelled Windows worker, failed G-U2 and package-build pass. Publication/release-ready assessment must refuse all required failures while retaining developer beta packaging policy if deliberately separate.
7. Do not merge or publish a “READY” conclusion while mandatory artifact/test inputs are unresolved. Include an explicit `ReleaseDecision` artifact summarizing source/head SHA, gate statuses, blockers and human acceptance signature.

## 16. Exact engineer handoff / bug-report template

```markdown
### R6 task ID, short defect title, severity and owner
- HEAD/base SHA, source PR and upstream AGENTS/spec/policy sections:
- Observed behavior, environment and exact reproduction commands:
- Ground truth source, affected PE/manifest SHA and permissions:
- Expected behavior and invariant that fails:
- Minimal red unit/native test plus expected failing output:
- Root cause: observed / hypothesis / not determined:
- Fix strategy, modules owned and contracts that MUST remain unchanged:
- Implemented patch commit SHA and diff review:
- Focused tests: commands and pass/fail/skip counts:
- Full Ruff/pytest/schema: exact command/CI run URL:
- Native tests: OS, tool binary/version, old/new SHA, output digest and result:
- Original project snapshot SHA before/after and notes integrity:
- Security/cancellation/network checks:
- Source corpus/locked-test contamination check:
- Remaining limitations, failed/skipped/blocked rows and rollback instructions:
- Reviewer, final merge status and follow-on owner:
```

A task is closed only when every applicable acceptance entry contains real evidence and all failing test cases remain reproducible in regression form. Documentation completion or branch creation alone does not close an engineering defect.
