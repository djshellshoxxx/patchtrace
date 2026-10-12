# SPEC-12 planning package: Ghidra-hosted semantic and runtime patch analysis

Status: PROPOSED / PLANNING ONLY. Nothing in this document claims a working Ghidra extension, semantic detector, or runtime tracer. Maintainers must reconcile this roadmap with current SPEC-01 through SPEC-11 and active PRs before coding. Last drafted 2026-10-12.

## Goal and non-goals

Evolve PatchTrace from a Ghidriff-backed, persistent patch investigation desktop into an optionally Ghidra-hosted platform connecting (1) matched binary functions, (2) cross-version CFG/p-code/data-flow evidence, (3) debugger/instrumentation observations and (4) analyst review. Preserve current standalone desktop, CLI, SQLite projects, offline defaults, explicit older/newer orientation, provenance, no target execution during static comparison, and user control over optional network actions. No automatic vulnerability verdict, exploitability probability, assertion of exhaustive tracing, or assumption that matching engines are independent.

### Intended workflow (ASCII)

```text
 Analyst selects OLD and NEW binaries, target architecture/profile
                      |
            +---------v-----------+
            | PatchTrace project  |  immutable artifacts, hashes, run IDs
            +---------+-----------+
                      |
        +-------------v-----------------------------------------+
        | Analysis scheduler (optional concurrent adapters)   |
        |   Ghidriff/Ghidra    BinDiff      rz-diff             |
        |   primary match      graph match  cheap second look  |
        +----------+---------------+---------------+----------+
                   |               |               |
                   +---------------v---------------+
                                   |
               +-------------------v-------------------+
               | Match reconciliation and provenance   |
               | agreements / disagreement / unmatched |
               | NEVER treat vote count as correctness |
               +-------------------+-------------------+
                                   |
                +------------------v------------------+
                | Ghidra plugin / static extraction    |
                | matched functions, blocks, edges,    |
                | p-code, references, call relationships|
                +------------------+------------------+
                                   |
          +------------------------v------------------------+
          | PatchTrace semantic engine (pure core + jobs)   |
          | block mapping -> CFG edit -> def-use/slicing     |
          | dominance -> memory alias limits -> detectors   |
          +------------------------+------------------------+
                                   |
            +----------------------v-----------------------+
            | Optional runtime adapter / controlled lab     |
            | Ghidra Debugger <-> WinDbg/GDB backends       |
            | trace snapshots + targeted branch coverage   |
            | module-relative addresses + run provenance   |
            +----------------------+-----------------------+
                                   |
                     +-------------v-----------------+
                     | Evidence graph and confidence |
                     | observed / inferred / AI      |
                     +-------------+-----------------+
                                   |
          +------------------------v------------------------+
          | Ghidra docking UI AND existing Qt standalone   |
          | CFG overlay, slices, trace paths, match disputes|
          | findings, notes, ranking, reports, audit trail  |
          +-------------------------------------------------+
```

## Architecture decisions and rationale

ADR-12A. **Plugin first, not Ghidra fork.** Ghidra already exposes static/decompiler/p-code APIs, CFG, docking UI, debugger and Trace abstractions. Using supported Java extension points lowers long-term upstream merge costs. No Ghidra core patch without a demonstrated missing API plus compatibility proof. Pin and test supported versions; do not assume Java/PyGhidra binary compatibility.

ADR-12B. **Shared analysis core and adapter boundaries.** Keep existing Python domain/persistence and Qt standalone. Ghidra Java plugin owns docking/navigation and extracts versioned artifacts through a local, authenticated-by-process, loopback or stdio IPC contract; prefer stdio or named pipe for lowest exposure, and document threat model. No Java<->Python bridge in UI thread. Never run arbitrary received code; typed JSON/CBOR schema, size limits, cancellation, timeout, and version negotiation. Do not reuse a project's SQLite writer concurrently from Ghidra and Qt.

ADR-12C. **Static, dynamic and inferred claims distinct.** Runtime traces cover observed executions only; debugger Trace snapshots are not exhaustive instruction traces. Record backend/capture mode, gaps, coverage completeness, build/symbol/module mapping, environment/test-input digests, missing data and errors. No memory contents in reports by default.

ADR-12D. **Semantic over lexical where evidence supports it.** Keep BND/INT/OVF/VAL/ERR/SIZE/WIL/SCRUB as first-pass heuristics; add CFG, SSA/p-code def-use, slicing, dominance and controlled memory/alias modeling behind separate modules. Do not claim a new branch protects a sink solely from dominance; validate predicate constraints, reachability, data identity and bypasses.

ADR-12E. **No automatic consensus truth.** Ghidriff, BinDiff and rz-diff may share Ghidra imports, labels and underlying evidence. Retain native quality values with engine/version/algorithm; never average raw confidence/similarity or turn voting into exploitability likelihood. Define disagreements as analyst queues; prefer independent graph/block clues and held-out benchmark ground truth.

ADR-12F. **Why not angr-management or Cutter fork?** angr is excellent for optional symbolic reasoning and path constraints but is not a drop-in replacement for Windows debugger tracing/Ghidriff's Ghidra project context. Cutter/rizin adds a second primary UI/decompiler ecosystem and GPL distribution considerations. An angr adapter remains a future opt-in, and rizin is useful as lightweight independent-ish corroboration. Fork Ghidra only after an ADR documents an unmet extension need.

ADR-12G. **Execution isolation.** Static analysis never intentionally executes target. Dynamic runs require explicit opt-in and separate lab/VM snapshot; kernel-driver targets need a separately specified kernel-debugging path, never naive user-mode injection. Trace import is allowed without execution. Airgapped operation and disabled online symbols remain first-class.

## Required developer-ready specs (create and review BEFORE implementation)

Each spec must contain: objective/out-of-scope; dependencies; versioned typed schema and JSON fixtures; algorithms and failure semantics; performance/resource budgets; security/privacy; staleness/provenance; platform constraints; migration and rollback; threat model where relevant; observable logging; CLI/GUI UX; test matrix; acceptance criteria; interfaces; assumptions and rejected alternatives. Assign one owning module per contract.

- [ ] **SPEC-12 Core modularization and ADRs**: package graph, API boundaries, preservation of existing service/Qt CLI contracts, compatibility matrix for Ghidra/Ghidriff/Java/Python/Windows/Linux; no giant coordinator module.
- [ ] **SPEC-13 Analysis interchange and identity**: schema for function/block/edge/p-code/varnode/call/reference/trace record; stable SHA/content IDs; artifact SHA + image base + module-relative RVA + run provenance; unknown/missing semantics; no cross-version address-as-identity.
- [ ] **SPEC-14 Ghidra Java extension**: GradleDev/GhidraDev packaging, docking panels, selection/navigation, task monitor, plugin lifecycle, resource cleanup, headless exporter, compatibility tests, licensing/notices.
- [ ] **SPEC-15 Local IPC and job scheduler**: stdio/named-pipe preference, schema negotiation, typed errors, rate/size/timeout limits, cancellation propagation, supervision, partial-result policy, multiple competing applications and writer lock, secure opt-in tracing.
- [ ] **SPEC-16 CFG extraction and correspondence**: block/edge taxonomies, exceptional/indirect edges, Ghidra basic-block API, deterministic canonicalization, old/new block matching, graph-edit operations, inlining/optimization/ambiguous match handling, complexity caps, confidence provenance.
- [ ] **SPEC-17 p-code SSA, slicing, dominance and memory model**: high-p-code vs raw p-code selection; def-use; phi/MULTIEQUAL; branch predicate normalized expressions; dominance/postdominance; backward/forward slices; interprocedural bounded summaries; pointer alias/memory-load-store uncertainty and call side effects.
- [ ] **SPEC-18 Semantic detector contracts**: guard-to-sink, validation, arithmetic, size, scrub and error-path detectors; evidence proof obligations; source→transform→sink and path witnesses; explainable ranking separate from empirical reliability; FP/FN fixtures.
- [ ] **SPEC-19 Runtime capture adapters**: Ghidra Debugger/Trace and WinDbg first; GDB where supported; optional DynamoRIO/Frida research; block/branch and targeted memory-event capture; ASLR and module remapping; clock alignment; redaction; sandbox/VM process boundaries; capture-gap indicators.
- [ ] **SPEC-20 Differential replay and trace matching**: equivalence of old/new test cases and environments, deterministic harness/fixtures, trace event schema, edge coverage/branch divergence, exception and return differences, causal ambiguity, trace-to-static mapping, no claims beyond observed paths.
- [ ] **SPEC-21 Multi-engine matching and arbitration**: Ghidriff primary; BinDiff export/import and native metadata; rz-diff graph/function vs raw Levenshtein modes; engine-specific strengths, conflict sets, uncertain/missing; opt-in engine discovery, local resource budgets, async parallel fan-out, per-engine failure isolation.
- [ ] **SPEC-22 Evidence, migration, caching and history**: SQLite additive migrations after verified backup; raw and derived provenance, stale invalidation, lock strategy, dedup hashes, quota/eviction, analyst overrides/history, immutable raw external results.
- [ ] **SPEC-23 UI/UX and reports**: Ghidra docking views, paired CFG overlay, block-to-p-code slice, trace timeline, disagreement explorer, keyboard navigation, accessibility, textual fallback, export citations and redaction; standalone feature parity policy.
- [ ] **SPEC-24 QA benchmarks/fixtures/release**: known positive and negative ground truth for matches and semantic guards, compiler optimization variants, Windows user/kernel fixtures, live debugger trials, airgap acceptance, Ghidra extension matrix, time/memory budgets, CI matrix, release signing/checksums.
- [ ] **SPEC-25 Symbolic optional provider**: angr subprocess/API integration, state/environment models, budgets/timeouts, solver and path limitations, non-blocking failure, no conflation of solver feasibility with observed execution.

## Specification production process

1. Inventory current code/specs and PRs, especially SPEC-09/10/11 and Phase 3 secondary/*; map requirements to implemented functions/tests. Avoid renumbering existing SPEC IDs: reserve SPEC-12 onward only after checking files.
2. Write SPEC-12/13/15 plus ADRs first and freeze v1 interchange contracts with schema/examples. Require review from Java/Ghidra and Python contributors before code.
3. Parallel spec workers: (14 UI/plugin), (16/17/18 semantic), (19/20 runtime), (21 matching), (22/23 data/UI), (24/25 QA/optional symbolic); coordinate by shared immutable interface docs, no overlapping files. Validate cross-spec consistency.
4. Red-team threat model and adversarial fixtures; define source trust, parsers, archives, IPC, process containment, secrets and report handling.
5. Gate specs with example schemas, bounded algorithms, acceptance tests, reproducible command lines, platform-specific errors and decision log. No build work until dependencies are accepted.

## Rough implementation plan AFTER spec approval

- [ ] **M0 baseline and audit:** merge/close outstanding coordinated PRs; snapshot test/benchmark baseline; verify current Phase 3 adapters; do not overwrite existing projects.
- [ ] **M1 refactor seams:** extract analysis core from Qt, define adapter protocol, preserve existing CLI and standalone; contract tests and migration-free compatibility.
- [ ] **M2 Ghidra proof of integration:** plugin loads pinned Ghidra, lists project pair, navigates old/new matched functions; local IPC and job cancellation tested on Windows; first release behind feature flag.
- [ ] **M3 deterministic CFG layer:** extract old/new graphs, canonical IDs, block correspondence and edit records; record ambiguities; render overlay with analyst trace-back.
- [ ] **M4 def-use/dominance/slices:** implement intraprocedural p-code analyses with memory uncertainty labels; golden fixtures for true/false bounds guards; differential detectors augment existing rankings.
- [ ] **M5 interprocedural summaries:** bounded call relationships and side-effect models; explicit unknown for unresolved indirect calls; computational ceilings and cancellation.
- [ ] **M6 engine fan-out/reconciliation:** finish existing BinDiff/rz-diff live adapters and GUI; compare consensus/disagreement against hand-validated corpus; configurable primary/secondary modes; fallback to single-engine always works.
- [ ] **M7 dynamic trace MVP:** WinDbg via Ghidra Debugger with reproducible user-mode test harness; trace import, module-relative address mapping, basic block/branch observations and side-by-side differences; lab-only controlled launch.
- [ ] **M8 advanced capture:** targeted instruction/memory events where debugger/backend supports; kernel-driver VM debugging in separately gated track; trace quota, gaps and resource tests.
- [ ] **M9 symbolic optional:** angr sidecar on selected slices, bounded path search, cross-validation where possible; independent disable/failure.
- [ ] **M10 QA/performance/release:** static/dynamic positive and negative accuracy, benchmark datasets, profiles, frozen Windows plugin/standalone acceptance, airgapped tests, safe migrations, rollback, docs, notices and tagged beta.

Each milestone requires RED failing contract tests, GREEN implementation, refactor, integrated regression, static checks, perf thresholds and an individually reviewable PR. Maintain a module catalog (owner, public API, version, dependencies, fixtures, stability) and an interface-first code review. Run multiple agents only with exclusive file/module ownership and one integrator responsible for PR ordering; prohibit orphan branches, parallel writes to the same schema and undocumented feature expansion.

## Multi-engine decision: should we run Ghidriff + BinDiff + rz-diff in parallel?

**Recommendation:** Yes, opt-in and benchmarked, with Ghidriff remaining the default required engine. BinDiff is the meaningful graph-structural complement; rz-diff is a low-cost alternative perspective or filter, not a substitute for semantic CFG/p-code analysis. Parallel fan-out may reduce latency when CPU/RAM permit, but Ghidra instances, BinExport and BinDiff setup can be expensive; cap concurrency and prefer reuse of existing exported artifacts.

Potential extra findings:
* BinDiff graph/call-graph and basic-block matching can align functions Ghidriff misses after refactoring/inlining or expose Ghidriff false matches. Inspect actual algorithm IDs, confidence and block mapping rather than assuming independent truth.
* Conversely Ghidriff's decompiler-oriented evidence may clarify semantic changes overlooked by structure-heavy BinDiff.
* rz-diff can notice byte, symbol/import and function differences, and supports graph comparisons; raw-byte Levenshtein is sensitive to relocation/build noise and should not be promoted as a semantic match score.
* Disagreement and missing-match queues can identify high-value manual review candidates. Agreement raises investigative confidence only after calibration with labeled cases; correlated errors remain possible.
* Multiple engines do NOT create complete data flow, runtime tracing, ground-truth CVE attribution or sound vulnerability proofs. Those require Ghidra semantic and debugger work above.

Experiment before making three-engine mandatory: build 30–100 hand-labeled old/new PE pairs spanning unchanged, optimized, renamed, inlined, split/merged, PDB/no-PDB, patchguard and unrelated-build noise; compare match precision/recall, correct block correspondence, disagreement yield, wall clock, peak RAM, setup failures and incremental unique findings. Randomize evaluation order; hold out a test set. Default remains one engine unless demonstrated net benefit; BinDiff optional high-value corroboration, rz-diff optional targeted triage.

Source research and upstream:
* https://github.com/google/bindiff/blob/main/docs/concepts.md (structural function and basic-block matching, similarity/confidence)
* https://book.rizin.re/src/tools/rz-diff/intro.html (rz-diff mode taxonomy)
* https://github.com/NationalSecurityAgency/ghidra
* Existing PatchTrace SPEC-10, SPEC-11 and tasks/todo.md are the baseline, not work to replicate.

## Definition of done

From both standalone and Ghidra views, analyst opens unchanged existing project; compares exact binary pair; optionally runs secondary engines; reviews reconciled function/block matches; inspects changed CFG and verified value-dependency slice with explicit uncertainty; optionally imports/captures real trace; navigates source-linked evidence; corrects matches; saves and reopens; exports fully attributed, non-executable report. Offline default works. Failures/cancel/timeout preserve previous committed data. Full Windows PE x64 static fixture and separate debugger-backed behavioral fixture pass on clean test machines; no unsupported feature is marked complete.
