# 30. History and process

How PatchTrace was built in the five days from 2026-10-11 to 2026-10-15: the phases, the multi-instance process, the spec-first discipline, the audits, and what each instance contributed. Sources: `git log` (this checkout is a shallow clone: 48 commits are visible, the oldest dated 2026-10-12, plus 45 tags; earlier history is known only from tags, the version history and the ledgers), `docs/version-history.md`, `docs/plans/ledger-A.md` to `ledger-D.md`, `docs/plans/multi-instance-coordination.md`, `docs/plans/program-e-execution-plan.md`, `docs/plans/worker-brief.md`, `docs/audits/`. Dates are commit dates. Session identifiers, trigger identifiers and tokens are deliberately omitted. Previous: [27](27-testing-and-ci.md). Next: [31 decisions](31-decisions-and-tradeoffs.md).

## Origin

The repository began as a **specification-only task**: `docs/project-brief.txt` asks for a developer-ready specification package for PatchTrace (a tool that compares two Windows binaries and investigates what a patch changed), explicitly "do not implement application code". `AGENTS.md` records the turn: the user then authorized full modular implementation, repair of incomplete specs before the corresponding code, a code audit, QA, a Windows standalone build and prompt merging, and "the latest instruction governs delivery". Two rules from that file shaped everything after: update the specification before changing a contract, and do not call the project complete while release acceptance gates remain unverified.

## Phases

| When | Phase | What landed (PR or tag) |
|---|---|---|
| 2026-10-11 | Foundation (M1 to M6) | contracts and schemas, ingestion, normalization, supervised backend and cancellation, SQLite persistence, desktop, optional AI providers, reports, diagnostics, first audit and Windows standalone. First desktop beta `beta.8` |
| 2026-10-11 | Hardening | dot-path fix for Ghidra (`beta.13`), isolated Ghidra workspace (`beta.21`), symbol lookups made opt-in (`beta.29`), read-only runtime discovery (`beta.36`), first Linux build and cached-PDB fix (`beta.70`), offline-backend ZIP importer (`beta.72`) |
| 2026-10-11 to 12 | Phase 2 enrichment | change signals, `attention/1` ranking, WIL, CVE context, derived cache, profiles, CLI `rank flags correlate cache` (`beta.80`, `beta.85`); full code audit and acquisition (`beta.82`) |
| 2026-10-12 | Phase 3: multi-build and second opinions | N-way series, acquisition dialog, BinDiff import and rz-diff (`beta.90`); planning documents for Ghidra semantic tracing, cross-engine evidence and calibration, CSAF and three-tool intelligence (PRs #14, #16, #17) |
| 2026-10-13 | Alpha inspection | file overview without a backend (#19), verified artifact byte reader (#21), bounded PE overview and Authenticode probe (#22), Hex/Binary/Base64 raw views (#23), semantic tooltip registry (#24), PE comparison in the GUI (#25), autonomous-alpha handoff and CI triage (#20), code audit with fixes (#29) |
| 2026-10-13 to 14 | Phase C: multi-engine integration | specs and decisions (#30), engine scheduler and runs registry (SPEC-28, #31), Series window (#32), Windows acceptance automation (#33), evidence panel C6, BinDiff execution C4 and calibration tooling C9 (#34), BinExport2 support C3 and the SPEC-31 unified-engine specification (#38) |
| 2026-10-14 | Phase D wave 0 (#42, `beta.202`) | CSAF core, capa/FLOSS/DiE adapters, BinDiff GUI setup, unified-engine contracts, known-answer corpus and Tier W, bug-hunt fixes |
| 2026-10-14 | Program E wave A | plans and specs for every remaining feature, unified ladder S2, GitHub Pages tooling (#46); unified S0a-FIX/S0b/S1, pilot contracts, CSAF reports and CLI (#49, published as `beta.225`) |
| 2026-10-14 | Zero-download bundle | pins, builder, discovery, `backend` CLI, acceptance harness and workflow (BUNDLE B1 to B8, #48) |
| 2026-10-14 | Feature build phase | release gate, CLI registry, GUI foundation and WBQ exports (#52); label training foundation (#51); specs SPEC-46/47/49/55 and C9 preregistration (#54); patch-intent adapters, YARA-X engine, anchor fabric, KEV core, AI hardening (#53); KEV transport and CLI, YARA candidates, patch-intent engine, unified stages (#57) |
| 2026-10-14 to 15 | GUI framework | panel host, tasks, widgets, themes, Leads/Unified/WBQ Qt panels, task-runner hardening (#58 at `21a005e`) |

The tag counter `N` in `v0.1.0-beta.N` is the CI run number, so it jumps; only some tags carry a recorded published package (beta.8, 101, 103, 225). See [version history](../version-history.md).

## How the work was organised

**Spec first.** Interfaces change in `docs/specs/` before code (`AGENTS.md`). The registry `docs/specs/REGISTRY.md` is the numbering authority and `docs/specs/INDEX.md` lists every file; numbering collisions that arose in parallel drafting (several files proposed "SPEC-28") were recorded and resolved there rather than silently renumbered. Program E added one *integration plan* per feature (`docs/specs/program-e/*-integration-plan.md`): contracts, limits, error codes, copy text, slice cards and gates. Workers are told that a card's contracts are binding and, if a card is thin, to build the smallest correct thing and say so.

**Red/green tests, hermetic.** Behaviour is test-first; mocked tests are never live evidence ([27](27-testing-and-ci.md)).

**One slice, one worker, one worktree.** Each worker builds a slice (or a short chain) in its own git worktree, commits locally with the co-author trailer, touches only the exclusive files on its card, appends a uniquely headed block to the append-only docs (`docs/modules.md`, `tasks/todo.md`, `docs/qa.md`), and reports in at most 250 words including "Integrator asks" for shared-file changes. Shared files are frozen for workers: `ui.py`, `tooltips.py`, `panel_manifest.py`, `cli.py`, `tools/frozen_smoke.py`, `pyproject.toml`, `optional_deps.py`, `backend.py`, the `KINDS` set, `tools/build_*.py`. This is why features arrive as `panel.py` plus a view model, or as `cli_commands/<verb>.py`, and the integrator wires the seam ([32](32-how-to-extend.md)).

**Integration waves.** An instance merges worker branches in dependency order into its integration branch, runs the full suite twice, runs `ruff`, merges `origin/main`, and opens one PR per wave; squash-merge when all checks are green. Every code merge to `main` runs `qa-windows.yml`; every third counted merge publishes a prerelease.

**Cost discipline** (`CLAUDE.md`, coordination doc): the cheapest capable model for each task (Haiku for mechanical fixtures, registries and lint; Sonnet for research, specs, frameworks, builds and QA; the top tier only after two failed lower-tier attempts or for a nuanced security invariant); a budget governor reads the account's rate-limit status before launching a wave and withholds the expensive tier when the status is a warning; compute-heavy runs (compiling corpora, Ghidra, evaluation) go to Actions matrix jobs, not agent loops.

## The instances

Owner-approved on 2026-10-14 (coordination doc): the remaining work was spread over parallel cloud instances, each with its own branch, ledger and 12-hour check.

| Instance | Role | Built (from the ledgers) |
|---|---|---|
| **A** | integration owner | unified engine S0a to S6a and its CLI/panel wiring; patch-intent localization contracts, adapters, rule table, engine and CLI; CSAF reports and `intelligence` CLI; GUI plans, the panel and CLI registries (F0, F1, F1b), release gate (RG); GitHub Pages tooling; wave PRs #46, #49, #52, #53, #57; prerelease `beta.225` |
| **B** | feature builder | B-0 optional dependency enablement (extras, `optional_deps.py`, hooks); KB correlation K0/K1; capa/FLOSS/diec tools core and audit fixes (TA-1 to TA-11), provisioning and pins; the `search` and `rules` dependency extras; follow-ups on licence notices and `copy_metadata` (B waited for A's integration plans for search, call graph, strings, capa, DiE, KEV, YARA-X and WBQ; in the feature build phase several of those slices, KEV and YARA-X among them, were then built by A's workers, per ledger A) |
| **C** | labels, specs, guide, audits, bundle | label training (LBL-00, evaluator, mutations, shard runner, 13-project catalogue, LBL-HARDEN), SPEC-46/47/49/55 and the C9 preregistration, audits K/T/S0a/G+acquisition, the zero-download bundle (BUNDLE B1 to B8, pin-verify tooling), guided-teacher research (deferred by the owner, not merged) |
| **D** | GUI framework and panels | F2 to F9 (runtime, widgets, host, themes, evidence migration, series/files docks), `VirtualTable`, `CodeDiffView`, `GraphCanvas`, task-runner hardening, Unified/Leads/WBQ Qt panels, GUI2 follow-through (`ui.py` ceiling lowered), migration-readiness work |

An external agent (ChatGPT Codex) was given bounded, non-colliding work on its own branches: independent audits and hostile-input tests (`docs/plans/codex-task-1.md` to `-6`, reports `docs/audits/codex-*.md`, PRs #56 and #62), and earlier a panel-spec prompt. Its findings were triaged into the owning slices.

Coordination rules that mattered in practice: push only to your own branch; message peers in at most three lines; never stop a worker that is making progress; ledgers are per-instance so there are no shared-file conflicts. Harness facts recorded along the way: new worktrees start from `origin/main`, so wave prompts began with a fast-forward merge of the integration branch; spec-writing workers left files untracked and needed a registry row and commit by the integrator.

## Audits

| Audit | Result |
|---|---|
| Runtime reliability 2026-10-11 (`docs/audits/2026-10-11-runtime-reliability.md`) | process supervision and cancellation findings, fixed in the foundation |
| Code audit at `b7e819a` (`docs/plans/audit-20261014-and-next-phase.md`) | four area audits; fixes for report leaks, path redaction, FIFO hangs, PE reads crossing mappings, CLI typo launching Qt, enrichment crashes and many GUI defects, each with a regression test; ranked backlog P1/P2 |
| Process supervision, service/storage, spec gaps (2026-10-14) | follow-up findings routed to owners; `spec-gaps` produced SPEC-41 to SPEC-45 drafts |
| Instance C audits K, T, S0a, G+acquisition, intelligence, label training | TA-1 to TA-12 in the tool adapters; transport slow-drip flaw C-01 (High); CSAF type error; CWE double count |
| Random audit 1 (`random-audit-1-20261014.md`) | 0 High, 4 Medium, 6 Low, routed to fix slices (RA-FIX-1/2, AI-FIX, B13) |
| Codex audits 1 and 2 | workflows and packaging: 2 High, 9 Medium, 4 Low combined, with hermetic regression checks |
| Per-feature audits (Program E) | each feature ends with a "Not verified here" table in `docs/qa.md` |

## Evidence discipline

`docs/qa.md` records actual commands, counts, versions and what could not be verified; `tasks/todo.md` tracks gates. Genuinely blocked external acceptance (clean Windows GUI run, NVDA/Narrator, DPI, disconnected bundle run, live AI provider, native msdelta) is reported separately from automated evidence and never claimed done. Two procedural hazards were found and written down: a `[skip ci]` marker anywhere in a commit message suppresses the build and so the release gate does not count it; and a head commit that changes `.github/workflows/` cannot publish with the default token (HTTP 403). An automated classifier also refused to let a worker record supply-chain pins without explicit owner permission, which is why two pin entries remain open.

## State at the time of writing

Built and on `main`: the desktop and CLI described in the [guide](../guide/00-index.md). Planned or unmerged: the Search, Graph, Strings, Capabilities, Build-environment, Rules, KB, KEV and Guide panels; the KB verb and consented index sync; label-training results (no calibrated model exists); a published zero-download package; a final release (none is created automatically).

## Published packages recorded in the ledgers

| Tag | Date | What is recorded |
|---|---|---|
| `v0.1.0-beta.8` | 2026-10-11 | first desktop beta, Windows zip |
| `beta.101`, `beta.103` | 2026-10-13 | publication after a token-permission problem (see `docs/qa.md`) |
| `beta.225` | 2026-10-14 | main `98182e5`; Windows zip 60,640,443 bytes and Linux tar.gz 89,535,839 bytes with checksums; Windows pytest 4,884 passed, Linux 4,891; frozen and Linux smoke on 22.04 and 24.04 |

The newest tag in this checkout is `beta.243`, at `c2070cf` (PR #55, label-training hardening); `docs/version-history.md` stops at `beta.225` and does not say whether a package was published for `beta.243`. Other tags exist (45 in this checkout) but a package for them may be only a CI artifact. Commits after `c2070cf` (PRs #53, #56, #57, #58, #62, #63) have no tag in this checkout. No full (zero-download) package and no final release have been published.

## Lessons the process recorded

1. **Parallel specs collide.** Several drafts proposed the same spec number, and parallel branches proposed overlapping engines (QBinDiff-, radiff2- and Diaphora-inspired). The reconciliation was the registry, the SPEC-31 decisions table (conflicts C-01 to C-21 with resolutions) and SPEC-55; absorbing the useful part into one engine beat building three.
2. **Shared files need one owner.** Edits to `ui.py`, `cli.py`, `tooltips.py` and the dependency lists were routed through "Integrator asks", and the GUI seam is capped in size by a test. The append-only docs use unique headings so concurrent appends merge by keeping both sides.
3. **Windows is where it breaks.** The checklist of Windows pitfalls (path length, dot-prefixed Ghidra directories, spawn-lock for pipes, CRLF fixtures, the 15.6 ms clock, `PYTEST_CURRENT_TEST` length, read-only files that cannot be deleted) came from real failures; a fixture line-ending bug and a probe timeout (`_java_version`) each cost a CI run.
4. **Teardown bugs hide in single runs.** The `qt_gate` repeat-in-one-session method came from Qt aborts that only appeared with many test files in one process; a `TaskRunner` collected off the GUI thread segfaulted in Shiboken, which produced the module-registry ownership rule.
5. **Honest scope beats a headline number.** Label-training and calibration work shipped as tooling plus an "honest scope" vocabulary (`calibration/scope.py`) so no sentence in the product can overstate what a model was validated on.
6. **Audit what you merge.** Random and independent audits found real defects after "green" merges (report leaks, slow-drip transports, workflow-file hazards, `pages.yml` invalid YAML that no test covered until a guard was added).
7. **Documentation drifts.** The earlier short docs (`docs/cli-reference.md`, `docs/privacy.md`, `docs/windows.md`, SPEC-55 N-05) each describe a moment; this guide lists the known drifts in [99](../guide/99-open-doc-questions.md).

## Where to look for what happened

| Question | File |
|---|---|
| What was released, when? | `docs/version-history.md`, `docs/release-process.md` |
| What did each instance do and what is open? | `docs/plans/ledger-A.md`, `ledger-B.md`, `ledger-C.md`, `ledger-D.md` |
| What is the current plan? | `docs/plans/program-e-execution-plan.md`, `master-plan-d.md`, `master-todo-d.md`, `docs/plans/claude-autonomous-alpha-handoff-20261013.md` |
| Why was X decided? | `docs/specs/unified-engine/00-decisions.md`, `docs/plans/spec-decisions-20261014.md`, `docs/specs/non-goals.md` |
| What was verified and how? | `docs/qa.md` (per-slice evidence tables), `tasks/todo.md` |
| What did audits find? | `docs/audits/`, `docs/plans/audit-20261014-and-next-phase.md`, `docs/plans/e4-audit-and-qa-plan.md` |
| How do workers work? | `docs/plans/worker-brief.md`, `spec-writer-brief.md`, `multi-instance-coordination.md` |
