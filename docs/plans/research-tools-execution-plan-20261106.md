# PatchTrace external-tool build, verification, execution and integration plan

Status: PROPOSED / DOCS ONLY. Prepared 2026-11-06 America/Vancouver (2026-11-07 UTC). Plan authored against main 365bf1f20f481d7c49c4d15bd90a3bde4b697038. This document does not provision Codespaces, install software, execute a native benchmark, trigger cloud jobs, enable schedules, change production code, or attest to completed research. Every execution begins by refreshing exact upstream and PatchTrace commit identities.

## 1. Goals, constraints and owner boundaries

Goal: systematically qualify existing open-source profiling, binary comparison, corpus, advisory-validation, statistical and fault-testing tools; execute reproducible experiments; upstream or implement verified findings in small isolated PatchTrace pull requests.

Preserve existing tools, fixtures, evidence and responsibilities:
- Existing production and acceptance code: tools/calibration/tier_r/, tools/live_rzdiff_check.py, tools/provision_bindiff.py, tools/bindiff_pin.json, tools/provision_intel_tools.py, tools/qa_binexport_memcap.py, tools/build_windows.py, .github/workflows/{corpus-tier-r,live-bindiff,live-rizin,live-unified,qa-windows}.yml, and src/patchtrace/{backend,jobs,unified,secondary,kbcorrelation,persistence,ui}. Existing suite remains authoritative.
- Existing research: docs/research/20261103-additional-research/06-claude-action-plan-and-reuse-register.md (P01-P15), calibration-r5/, deep-uncertainty-r8/, R1-R4 PRs. Reconcile current source before treating a historical note as an open defect.
- Live product consolidation: #205 owner integrate/swarm-qualified-20261105; #218 binary investigation; #235 independent investigation; #252 data-validation repair; #254 GUI seam. Do not modify their heads or overwrite docs/qa.md, tasks/todo.md, or AUTONOMOUS-DEVELOPMENT-LATEST.md during this program. No new paid autonomous schedule.
- Public repo, but vendor PEs/PDBs, licensed fixture binaries, tokens, private paths, commercial tool payloads and large dataset archives must not be committed or uploaded as unrestricted Actions artifacts. Publish only permitted manifests, metadata, hashes and controlled synthetic results.
- Nothing advances from candidate to production solely because a third-party tool produces a number. Keep raw evidence, original pair orientation, independent provenance, unknown/abstention, and immutable prior results.
- Establish costs and quotas before heavy experiments. Standard Actions runners on a public repo differ from larger billed runners; Codespaces storage/compute and artifact retention are separately budgeted. Default to bounded manual dispatch for heavy stages.

## 2. Source/licensing/tool admission gate (R0)

Before a third-party executable, dataset or library can be used in a trusted experiment, create a versioned record with:
- canonical upstream URL, commit/tag/release and checked-out SHA; source license and copyright notices; binary redistribution restrictions; dependency and SDK licenses; source versus binary provenance; exact download digest and byte length; whether an upstream hash/signature is independently available
- supported host OS and architecture, Python/JVM/compiler/SDK ABI, trust model, network needs, selected versions, sandbox permissions, reproducible build recipe and build-log hash
- fixture source/license, permitted storage and distribution, upstream corrections, known coverage gaps, known mutating behavior, and whether a tool is reference-only, development-only, opt-in runtime or proposed production code
- qualification states: planned, fetched, built, smoke-passed, fixture-verified, native-verified, cross-platform-verified, integration-qualified, rejected or blocked. Never infer a later state from an earlier one.

Store read-only records under docs/research/tool-qualification/; initially use JSON with a stable hand-authored schema documented in the first code PR. Upstream source code is not copied until file-by-file license and behavior review. Keep Node/Rust/Java/C++ research stacks outside the distributed Python/Qt application by default. Only opt-in tool execution is allowed. Reject unpinned downloads in reproducible CI; do not auto-fetch on Python import.

Fresh upstream leads (not automatically adopted):
- https://github.com/google/bindiff — Apache-2.0 native matching; current source build requires BinExport 12 and a modern C++ toolchain; Java GUI requires commercial yFiles, excluded. Ghidra exporter/integration is Tier 4, so independent qualification is mandatory. Do not silently replace the existing pinned BinDiff 8 path.
- https://github.com/assemblage-dataset/assemblage and https://assemblagedocs.readthedocs.io/en/latest/dataset.html — MIT corpus-building code; individual released binaries retain origin licenses; DeepHistory has corrected labels and large payloads. Prefer author-built small legal cases before selective dataset import.
- https://github.com/benfred/py-spy — Python sampler, useful for child-process diagnosis, subject to attachment permissions.
- https://github.com/bloomberg/memray — detailed Python/native allocations on Linux/macOS, NOT native Windows; trace overhead must be measured.
- https://github.com/async-profiler/async-profiler — JVM profiler on supported hosts; permissions and native JVM symbols are experimental preflight requirements.
- https://github.com/secvisogram/csaf-validator-lib — independent development-only CSAF 2.0 oracle; Node >=22 for current library; select offline schema/mandatory tests, not network-dependent full presets.
- https://github.com/HypothesisWorks/hypothesis — property/state-machine testing; use existing project test/dependency conventions.
- scikit-learn and scipy already supply statistical reference methods; MAPIE is optional research only, not a guarantee for correlated function observations.
- Windows patch extraction helpers, LLVM/PDB and reproducible-build tooling: source-inspect and license-qualify before adopting. Native Windows checks must run on a Windows host.

## 3. Execution environments (R1)

Environment A — local analytical Python: bounded synthetic fixture creation, deterministic regression design, statistical simulations, source-independent parsers and audit/report verification. Never claim local execution of Ghidra, BinDiff, Rizin or Windows without proof.

Environment B — isolated Linux Codespace: development, Ghidra/Ghidriff, Rizin, compilations, py-spy, Memray, async-profiler and open-source BinDiff source experiments. Add .devcontainer/devcontainer.json only in a dedicated PR after identifying image digest, Python 3.12, Java version, architecture and storage limits. Start with modest compute; raise it only after an RSS measurement. An active Codespaces terminal is required to run commands there; this GitHub connector alone does not open a Codespace shell.

Environment C — Linux GitHub Actions: repeatable headless tests and small native acceptance, artifact collection with size/time limits. Extend existing workflows or create an explicitly manual workflow at .github/workflows/research-tool-qualification.yml. Required permissions contents: read; no secrets unless explicitly needed; no unattended paid matrix. Use SHA-checked downloads, pinned host images and timeouts. Persist digests, timestamps, sanitized structured summary, log tail and exit codes, not licensed executable archives.

Environment D — Windows GitHub Actions / interactive Windows VM: MSVC, PE/PDB, Windows update extraction, actual native process supervision, PyInstaller/NSIS, clean-device UI, NVDA and DPI. Background CI can cover headless tests; interactive screen-reader, monitor and original-pair validation require an appropriately provisioned Windows desktop. Codespaces do not substitute for Windows.

Resource sequence: small synthetic pair, one bounded native pair, several independently labeled real pairs, then stress tiers. Never download the entire DeepHistory corpus into a Codespace. DeepHistory's full DuckDB and binary archives are hundreds of GiB; use selective metadata manifests or an approved subset source with verified digests and license records.

## 4. Parallel workstream ownership and concrete delivery

Each stream owns only its dedicated tools/research_qualification/ modules, tests/test_research_qualification_*.py and docs/research/tool-qualification/<stream>.md initially. Separate PR per stream. No concurrent editing of shared production modules or trackers. Assign independent reviewer(s) across streams before a source-facing change.

| Lane | Priority | Reuse/build scope | First runnable experiment | Promotion gate |
|---|---|---|---|---|
| A — performance / timeout | P0 | Existing backend-execution receipt, Ghidriff pin, psutil, py-spy, Linux Memray, JVM async-profiler. Build perf_harness.py and stage_parser.py. | Reproduce a bounded two-PE run, capture subprocess/JVM/Python CPU and RSS, stage intervals, last output age, candidate counts, exit/timeout and output hashes; isolate repeated candidate/metadata traversal after Sorting functions. | Same accepted output and match identities; no changed semantics or new concurrency; deterministic predeclared performance objective verified in >=3 controlled repeats; real cancellation/timeout + prior-result preservation. A longer timeout is not an optimization. |
| B — multi-engine qualification | P0 | Existing live BinDiff 8/Rizin/Ghidriff acceptance; optional source-build google/bindiff + BinExport12 as separate opt-in oracle. Build engine_parity.py and producer_receipt.py. | Same approved synthetic or source-built pair into Ghidriff, pinned Rizin and BinDiff; run orientation reversal, identical, no-match, 1:1, N:M and malformed-output controls. Preserve each engine's native function inventory/producer version and raw hash. | Independent labels, orientation/inventory invariants, correct unmatched partitions, typed blocked vs failed states; exact source digest, native success, no hardwired cross-engine equality. Source-built v12 and prebuilt v8 results remain separately tagged. |
| C — corpus / reproducibility | P0 | Existing Tier R factory, Assemblage/DeepHistory selective metadata, CVEfixes/OSS-Fuzz candidate references; use own compile fixtures first. Build corpus_bridge.py and source_admission.py. | Two self-built old/new PE or ELF pairs, optimization-noise and known material mutation; optionally one small licensed corpus subset after corrections/lineage review. | Reproducible source/build/PE SHA manifests; independent function truth incl. aliases and unmatched; no label leakage or source duplication across train/locked test; no unauthorized binaries committed. |
| D — advisory and Windows servicing | P1 | Existing kbcorrelation, CSAF parser, versioned MSRC fetch, Winbindex, Secvisogram validation; qualified Windows MSU/CBS tooling, LLVM/PDB identity. Build csaf_parity.py and windows_lineage_probe.py. | Offline 2.0 mandatory CSAF cases, ambiguous product/CVE/KB case, read-only package/component/hash lineage on authored/test MSU fixture. | Validator disagreements typed by test ID and dialect; no network in offline oracle; product/build/arch strict; no CVE-to-RVA proof inferred from shared KB; signatures/trust UNKNOWN unless independently verified. |
| E — calibration / semantic rigor | P1 | Existing R1/R3/R5/R8 contracts, scipy/scikit-learn, optional MAPIE, diffoscope/reprotest, compiler test families. Build calibration_audit.py and semantic_fixture_runner.py. | Group-held-out synthetic false-match labels, ICF/typed-literal/relocation/EH fixtures, dependency and null-model simulations, train-versus-inference feature comparison. | Explain statistical assumptions and counterexamples; no numerical probability promotion without independent Tier W/locked evaluation, source adjudication and explicit owner decisions; retain ordinal/abstain. |
| F — persistence / release / GUI | P1 | Existing verified backup, replay, PySide6/pytest-qt, Hypothesis, native Windows package and UI workflows. Build project_fault_matrix.py and release_receipt_check.py. | Reopen/restore interrupted project with corrupt sidecar and retained previous result, then bounded settings/shutdown races; inspect exact installed ZIP and Setup output hashes on Windows. | No lost committed evidence, mixed projects or promoted partial output; Windows-native package and human GUI/accessibility acceptance separately recorded. |

Crosswalk to prior P01-P15 research plan: A=P02/P04/P12; B=P03/P04/P09; C=P09/P11/P12/P14; D=P05/P06/P09/P14; E=P13; F=P01/P07/P08/P10/P14/P15. This is reuse and qualification, not an instruction to reimplement existing output stores or GUIs.

## 5. Gated waves and dependency graph

Wave 0 — baseline and conflict-free admission (no heavy cloud compute)
1. Refresh main, heads and owners of #205/#218/#235/#252/#254; document exact SHA and owned paths. Separate source-based findings from outdated research inventories.
2. Audit current available Code/runner access and runner pricing/quota. Verify tool versions, terms, source hashes, licenses and permitted fixture distribution. Set per-run cost, memory, disk and wall-clock budgets; use manual triggers.
3. Add a small research receipt contract and deterministic validator tests. Make unsupported environments report BLOCKED with exact missing prerequisites, never SUCCESS.
4. Proposed devcontainer is optional; test its build/entry first with no Ghidra/BinDiff download. Source-level development can start on the existing Python 3.12 workflow immediately.
Exit W0: source-pinned registry, a valid receipt schema, one local synthetic smoke and no overlap with active PRs. This plan document alone does not satisfy the exit.

Wave 1 — parallel bounded tools (A/B/C/D can begin independently)
1. Build and test in isolated PRs using red/green regression first; include command-line --help, --dry-run or --plan, resource caps, deterministic return codes and no import-time execution.
2. For every tool: an intentionally failing test, a valid fixture, hostile/unavailable fixture, cancellation, timeout, exact hash mismatch, and reproducible JSON result. Explicitly test no private path/key leakage. Preserve errors and previous results.
3. On approved host, execute the small pair, verify exit + artifact receipts, and independently review tool behavior. Prefer existing Tier R/live native Actions jobs to new duplicate workflows. No real vendor data in GitHub artifacts.
Exit W1: each selected tool has a reviewed PR, source/fixture receipt, captured executable version, deterministic synthetic result and specified unsupported cases; actual native proof claimed only when run logs exist.

Wave 2 — experimental native oracles
1. A: execute the owner's timeout reproduction on approved Windows host or a representative reproducible pair first; collect phase/candidate/RSS/CPU traces. When feasible compare repeated Ghidriff metadata calls vs a bounded cache of immutable function facts. Submit upstream issue/fix if defect belongs upstream.
2. B/C: compare produced manifests on source-validated binaries; qualify Ghidra/BinExport12/BinDiff-from-source as a distinct version. Do not weaken existing v8 or Rizin gates; report exact disagreement clusters and alternate matches.
3. D: differential CSAF and product/build tests; offline MSRC payload replay. Vendor package extraction and digital-signature proof only on Windows where supported.
4. E/F: use real mismatches as new corpus controls and feed fault/replay tests, while withholding unproven risk/probability ratings.
Exit W2: independently labeled cases, native tool/build inputs, raw hashes, error taxonomy, timing/resource table and precise known-unverified gaps. No claim that separate data-source membership proves a CVE fix.

Wave 3 — turn findings into small product PRs
Classify each finding:
- upstream defect: isolate a minimal repro, propose upstream fix or version upgrade, verify against fixed and original pins;
- PatchTrace adapter/logic defect: write failing regression in isolated branch, fix minimum production module, rerun focused + existing full/Windows/native gates, and require a semantic-owner review;
- integration/interop issue: preserve original input/producers, add explicit BLOCKED/UNKNOWN/provenance instead of falsely accepting;
- experimental algorithm or performance idea: keep opt-in until stable output equivalence and repeatable resource evidence; do not replace default matching/calibration automatically;
- research-only result: publish hashes, methods, contradictions and limitations; no production modification.

Each product PR must name: hypothesis, original source commit/versions, failing fixture, new test, exact changed paths, raw/normalized before-after observations, risk, rollback route, and reproducible acceptance/unsupported matrix. Do not rewrite the active #205/#218/#235 heads. Integrate in dependency order after the current qualification gates, without force-push, review dismissal or Sonar bypass.

Wave 4 — release and regression
Build the exact accepted SHA on Linux and Windows; run full pytest, Ruff, Qt repeated host gate, native engine and Tier R workflows, Linux packaging/smoke, Windows portable/installer smoke, deterministic replay; inspect SonarCloud and code review. Repeat final original-pair comparison on approved Windows hardware, and interactive GUI/NVDA/DPI tasks where required. Ensure optional research tools remain external and don't silently enlarge offline desktop bundles. Merge to main only after established required checks/reviews. Then update central QA/TODO/handoffs through its owner.

## 6. Receipt schema and acceptance definitions (first code PR)

One JSON record per attempt, emitted atomically and keyed by source + tool + experiment + input hashes; the contract should include:
- schema_version, experiment_id, scenario_id, PatchTrace repo/ref/SHA, tool name, upstream URL/SHA/tag, executable digest, runtime and operating-system identifiers
- test fixture/license/source pedigree, ordered older/newer hashes, options hash, environment allowlist fingerprint and declared network policy
- start/end UTC and monotonic duration, CPU/RSS peaks where measured, stage timings/candidate inventory, status PASS/FAIL/BLOCKED/CANCELLED, exit/stop reason and explicitly unverified measurements
- engine result hashes and quality/coverage counters, false-match/unknown evidence, retained artifact relative paths and checksums, limits/truncations and which validations actually ran
- reviewer identity/decision/accepted commit only after human or independent code review; source licensing and publication permissions for artifacts.

No raw environment dump, absolute home path, token, private vendor binary, extracted licensed dataset or unlimited profiler trace in the receipt. Re-run on fresh runner; deterministic fields must agree, while timestamps and resource samples remain observational rather than exact-byte identical.

## 7. Tests and hard stop policy

Common acceptance: unit/fuzz/hostile-input fixtures, separate PASS/FAIL/BLOCKED semantics, no uncontrolled network, strict URI/file containment, source hash and orientation binding, bounded RAM/disk/runtime, cancellation/process-tree cleanup, no mutation of original artifacts, provenance preservation, explicit missing coverage.

R1 native: signed/unsigned/typed literal, changed constants, ICF, EH, data references, 1:N/N:1 aliases, reversed pairs, wrong architecture and incomplete producer JSON. A source parser test alone cannot qualify Ghidra/BinDiff interoperability.

R2 performance: compare against baseline with cache policy and input/flags fixed; retain at least three attempts and hardware/version identity, report median and max, overhead of profiler and exact output equality. Agree on a measurable gain threshold before optimization; no post-hoc cherry-picking and no scalar speed win that degrades correctness.

R3 statistical: group by source family/lineage before splitting, independent reviewer labels, explicit negatives and abstentions, calibration/OOD/false-certification tests. An observed high score without sample size, split proof and uncertainty is not a probability guarantee.

R4 advisory: compare exact supported CSAF dialect/test IDs; do not collapse NVD/CNA/ADP disagreement or source version; no assertion of verified patch/cause without independently documented update/file/function evidence.

R5 release: no unsigned/binary payload automatically redistributed beyond original terms; no auto-main merge, no approval bypass, no silently promoted partial states. Existing SonarCloud failures and unrelated integration CI gates remain blockers.

## 8. First scoped implementation PRs (recommended order)

1. RQ-00: receipt schema and validation tests, source/fixture rights ledger; docs-only result states until parser is actually tested. Path: tools/research_qualification/receipt.py, tests/test_research_qualification_receipt.py.
2. RQ-01: bounded process performance harness reading existing backend execution receipts and optionally sampling one controlled child. Path: tools/research_qualification/perf_harness.py; tests. Start with offline parsing/dry-run; no Ghidriff changes.
3. RQ-02: Tier R/engine normalized result comparator with explicit orientation and row-level provenance. Path: tools/research_qualification/engine_parity.py; tests. Initially consumed recorded synthetic outputs; real engine runs later.
4. RQ-03: selective corpus manifest and license validator. Path: tools/research_qualification/corpus_bridge.py; tests. A small self-authored fixture precedes any DeepHistory import.
5. RQ-04: development-only CSAF 2.0 differential oracle using fixed fixtures; tool runner optionally invokes Node in a job, never packaged in desktop.
6. RQ-05: fault-state model and calibration audit in separate branches after their own ownership and upstream contract check.
7. RQ-06: opt-in Codespaces profile and manual GitHub Actions qualification workflow only after RQ-00/01/02 run locally, source/tool pins are known and cost/data controls have passed review.

As independent lanes demonstrate actual findings, open separate targeted product PRs. Keep the initial six research workstreams logically independent; do not allocate all workers to the same source modules. Original vendor pair and final human Windows tests require a provisioned executor; do not call them complete from a synthetic Linux smoke.

## 9. External sources and compatibility notes

- Google BinDiff upstream source/build/support: https://github.com/google/bindiff and https://github.com/google/bindiff/blob/main/docs/disassemblers.md (Ghidra Tier 4; yFiles commercial Java GUI).
- Assemblage data/license and dataset corrections: https://assemblagedocs.readthedocs.io/en/latest/dataset.html and https://huggingface.co/datasets/changliu8541/assemblage-deephistory (2026-10 label audit means old labels are not ground truth by default).
- py-spy: https://github.com/benfred/py-spy; Memray supported systems: https://bloomberg.github.io/memray/supported_environments.html (no native Windows).
- CSAF oracle: https://github.com/secvisogram/csaf-validator-lib (Node >=22, CSAF 2.0); optional service https://github.com/secvisogram/csaf-validator-service may be deployed only in isolated dev environment.
- GitHub Codespaces Linux devcontainer: https://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/adding-a-dev-container-configuration/introduction-to-dev-containers.
- GitHub Actions billing: https://docs.github.com/en/billing/concepts/product-billing/github-actions. Standard hosted public-repo runner usage and larger runner billing differ.
- Internal prerequisites: docs/qa/ghidriff-timeout-20261106.md, docs/plans/branch-merge-plan-20261106.md, docs/research/20261103-additional-research/, docs/research/calibration-r5/, docs/research/deep-uncertainty-r8/, .github/workflows/corpus-tier-r.yml.

## 10. Definition of program success

Success is a set of independently reviewed, reproducible, source-pinned and license-qualified experiments that identify real defects or supported improvements, plus small accepted fixes with full current-head CI and the relevant Windows/native evidence. Merely creating workers, downloading packages, storing a research plan, or producing plausible results is not success.

Explicit missing prerequisites at this checkpoint: provisioned interactive Codespace/Windows machine, approved original Windows PE pair for timeout reproduction, permission to use any restricted third-party binary/data, exact version/commit pins for newly proposed upstream programs, and eventual approved Tier W/locked calibration evaluation. The independent synthetic/tooling tasks do not need those prerequisites to begin.