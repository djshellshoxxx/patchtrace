# Non-goals and recorded decisions (SPEC-55)

Status: draft, 2026-10-14. Owner: integration owner (proposed; the user ratifies). Documents: deliberate exclusions and decisions on `main` at fd6cdba, plus the planned items they bound (PR #43 workbench branch, `docs/specs/program-e/`). No code. Number SPEC-55 allocated by the integration owner (2026-10-14).

## 1. Scope and purpose

1. This file lists what PatchTrace does not build, the reason, the evidence, and the condition under which the decision is reopened.
2. Each entry has one status: **non-goal** (not planned; reopen only by a new spec), **deferred** (planned later behind a named gate), **dropped** (do not build the named artifact), **folded** (its useful part lives in another spec), or **reserved** (number not available to a spec).
3. A decision is reopened only by changing its revisit condition and updating the affected spec first, as AGENTS.md requires for contract changes. Code must not drift ahead of this file.
4. This file adds no behaviour and changes no persisted contract.

## 2. Requirements

- **NG-R1** (MUST) A new top-level Qt window is not added. New UI is a dock, tab or panel of the single `MainWindow`.
- **NG-R2** (MUST) A deferred or dropped item is not partly implemented under a different name to get around its status. Example: a second matcher named after QBinDiff.
- **NG-R3** (MUST) Format and architecture support is added only with fixtures and a loader that rejects other inputs with a typed error. Recognising a foreign header for an explanation does not count as support.
- **NG-R4** (SHOULD) Each reopened item records the new evidence (test, measurement or primary-source URL with retrieval date) in its own spec before code is written.

## 3. Decisions

### N-01 Docker backend: non-goal

- **Decision.** No Docker or container backend.
- **Evidence.** No Docker code, script or CI job in `src/`, `tools/`, `tests/` or `.github/` (repository search for `docker`, case-insensitive, returns only prose). `README.md:59` states Docker is not required by the supported desktop workflow. `docs/specs/completeness-audit.md:29` and `docs/specs/verification.md:34` list it as deferred.
- **Reason.** The supported path is a Windows desktop plus an external Ghidra and Ghidriff runtime, or the offline backend ZIP (SPEC-06, `docs/specs/offline-backend-installer.md`). A container backend would be a second runtime with its own isolation and licensing questions that no spec covers. [proposal]
- **Revisit when.** A signed acceptance run shows the offline backend cannot be installed on a supported Windows machine and a container path is written up as a spec with its own isolation rules.

### N-02 Detached and separate windows: non-goal (one known exception)

- **Decision.** One main window. Dialogs are modal or owned by it; new UI is a dock, tab or panel (`NG-R1`).
- **Evidence.** `src/patchtrace/ui.py:1489` is the only `QMainWindow` subclass in `ui.py`; other windows are `QDialog` (`ui.py:220` to `ui.py:1401`). `docs/specs/unified-engine/00-decisions.md:26` (D-18) says the unified result is a view mode of the same window, never a new top-level window. `docs/plans/program-e-roadmap.md:40` and `:51` require one main window.
- **Known exception.** `src/patchtrace/ui_series.py:175` defines `SeriesWindow(QMainWindow)`, a non-modal top-level window. `docs/specs/series-window.md` section 6 specifies it. The exception is recorded, not accepted. `docs/specs/program-e/OUTSTANDING-specs-ledger.md` F1 asks for a conversion to a dock or tab.
- **Reason.** Each top-level window needs its own focus, geometry and teardown rules, and the evidence panel and code panes already share state in the main window (SPEC-04, `docs/specs/ui.md`). [proposal]
- **Revisit when.** Never for new windows. The `SeriesWindow` exception closes when it becomes a dock or tab (owner B, E-2 panel registry), and `docs/specs/series-window.md` section 6 is amended in the same change.

### N-03 Graph visualisation: non-goal for whole-program and web canvases; bounded diagram planned

- **Correction.** The request to record "graph canvases not planned" is only partly true. A bounded call-change diagram is planned, not built.
- **Non-goals.** A whole-program graph viewer; a browser or HTML canvas (`docs/specs/workbench/02-networkx-callgraph.md:138` says "not a browser canvas"); Graphviz execution (DOT text export only, `docs/specs/program-e/WB2-integration-plan.md:142`); NetworkX as the data model or a runtime dependency (`WB2-integration-plan.md:8`, `02-networkx-callgraph.md:88`); centrality or PageRank (`WB2-integration-plan.md:9`).
- **Planned, not built.** An ego-graph diagram in `QGraphicsView` with stock items for at most 2,000 nodes, always secondary to a text neighbours table (`WB2-integration-plan.md:160`, `:163`; `docs/specs/workbench/README.md:21` puts the text table first). PT-WB-02 is on PR #43 only (`docs/specs/REGISTRY.md` table B).
- **Evidence of the current state.** No `QGraphicsView` or `networkx` reference in `src/patchtrace/` on `main` (search).
- **Revisit when.** The Calls panel (WB2) is merged and a measured frame-time test at 2,000 nodes passes on Windows. Whole-program graphs need a separate spec.

### N-04 Chat and conversational AI UI: non-goal

- **Decision.** No chat transcript, follow-up thread or agent-style loop. AI use is one structured, selection-based interpretation at a time.
- **Evidence.** No chat widget in `src/` (the only `chat` hits are endpoint paths in `src/patchtrace/providers.py:78` and `:82`). `README.md:150` ("Interpret selection ... opens a preview before any AI request"), `README.md:280` (responses must satisfy a structured schema and cite the selected evidence). Native Anthropic Messages transport, remote Ollama hosts, HTTP endpoints and redirects are not supported (`README.md:270`, `:321`).
- **Reason.** Each request must show an exact preview, transmit only on consent, and treat the reply as untrusted structured text (AGENTS.md, "Keep remote transmission explicit with exact preview"). A chat history would carry unreviewed model text into later requests without that preview. [proposal]
- **Revisit when.** A spec defines a conversation log with the same preview, consent, budget and citation rules, and each new transport has its own spec and fixtures. The native Anthropic transport is a separate revisit.

### N-05 Light theme: non-goal

- **Decision.** Dark only. No theme setting.
- **Evidence.** `src/patchtrace/ui.py:97` hard-codes the dark stylesheet (`QMainWindow, QDialog { background: #10151c; }`). A search of `ui.py` for theme or light-palette switches finds none. `docs/specs/ui.md:3` specifies the "default dark neutral palette". `docs/specs/completeness-audit.md:29` defers the light theme.
- **Reason.** One palette keeps the contrast checks in the evidence and workbench specs (for example the 4.5:1 guard in `docs/specs/program-e/WBQ-integration-plan.md:183`) testable against one set of colours. [proposal]
- **Revisit when.** Accessibility acceptance (manual test M11 "High contrast" in `docs/specs/windows-acceptance-and-milestone-builds.md:128`) needs a theme. Then the palette becomes tokens with a light and a dark set, each with its own contrast test.

### N-06 ELF, ARM64 and Mach-O targets: non-goal

- **Decision.** Only Windows x64 PE inputs are analysed.
- **Evidence.** `src/patchtrace/ingestion.py:78-79` rejects a file without an `MZ` header (`PT-INPUT: missing DOS MZ header`). `src/patchtrace/acquisition/contracts.py:112` tests `machine_type == X64_MACHINE`; `src/patchtrace/acquisition/quarantine.py:122` rejects a non-AMD64 PE; `docs/specs/acquisition.md:9` excludes "Insider and ARM64 datasets (x64 only)". `src/patchtrace/secondary/binexport_pipeline.py:20-21` recognises ELF and PE magic only to explain a rejected BinExport input. `src/patchtrace/pe_overview/headers.py:16` maps machine IDs to display labels, including ARM64 (`0xAA64`); that is display only. `README.md:5` describes Windows x64 binaries.
- **Reason.** Ghidriff, the unified extractor and the acquisition path were validated only on x64 PE, and no ARM64 or ELF fixture exists. [proposal]
- **Revisit when.** A target format has a loader, a verified Ghidra path, committed or self-made fixtures, and an acquisition source (SPEC-08 amendment). The three formats are separate decisions.

### N-07 Phase 4 semantic IR and capability-graph semantics: deferred

- **Decision.** Not in current scope.
- **Evidence.** `tasks/plan.md:23` ("Phase 4 — deferred design"): "Not in current scope; requires typed IR/capability schemas, benchmarks and privacy/citation rules first." `docs/plans/ghidra-semantic-runtime-roadmap.md:1-5` is "PROPOSED / PLANNING ONLY".
- **Not the same thing.** The SPEC-31 IR (`docs/specs/unified-engine/03-extraction.md`, status line: S1 built, including IR reader and placement) is in scope and is not Phase 4. capa and FLOSS run as external tool adapters under SPEC-36 (`src/patchtrace/intelligence/tools/capa.py`, `floss.py`); their output is evidence, not a semantic IR.
- **Revisit when.** The planning package's first steps are done: SPEC-12, SPEC-13 and SPEC-15 are written with ADRs and a frozen v1 interchange schema, reviewed by a Ghidra and a Python contributor (`ghidra-semantic-runtime-roadmap.md`, "Specification production process", step 2).

### N-08 Numbers SPEC-12 to SPEC-25: reserved

- **Decision.** No spec file uses these numbers. They are held for the planning package.
- **Evidence.** `docs/specs/REGISTRY.md` section 1, item 4, and section 3 (collisions table). `ghidra-semantic-runtime-roadmap.md:98` ("Specification production process") says to reserve SPEC-12 onward only after checking files.
- **Rule.** A new spec takes the next free number (SPEC-56 today). A retired number is never reused.
- **Revisit when.** The roadmap's step 2 (SPEC-12, 13, 15) is approved. Then the owner assigns the numbers in REGISTRY.

### N-09 qbindiff, radiff2 and Diaphora decisions

Status note first. The per-spec recommendations come from `docs/specs/program-e/OUTSTANDING-specs-ledger.md` section 2.1 (dated 2026-10-14). That ledger's own vocabulary calls them recommendations for the integration owner. The repository holds a ratified decision only for the SPEC-31 items D-24 to D-26 (`docs/specs/unified-engine/00-decisions.md:32-34`), which is a draft. No ratification of the QB-02, RD-02 or DA-01 recommendations was found in `tasks/todo.md` or `docs/plans/`. The status below is therefore **recommended, not ratified**, except where marked.

| ID | Status | Reason and evidence | Revisit when |
|---|---|---|---|
| SPEC-QB-01 standalone `matching/` package | **dropped as a package; folded** | No `src/patchtrace/matching/` (directory absent). The residual-assignment idea (reject cost, margin on blocked buckets) is D-25 (`00-decisions.md:33`) and the residual passes of SPEC-31 S2 (`src/patchtrace/unified/ladder/passspec.py:7`). Two matchers would break the one-matching-path rule. | A second matcher is needed for a measured gap in SPEC-31 S5 data. |
| QBinDiff belief-propagation solver | **not built** (D-25) | `docs/plans/unified-engine-backups.md:27` (B-17): built only if S5 data show more than 10 percent of functions unresolved AND a corpus experiment shows gain. | Those two data conditions hold. |
| SPEC-QB-02 modular integration (`matching_*` tables) | **dropped (recommended)** | Its tables would add a persistence path beside `unified/store.py`. Its generic gates already live in `docs/plans/phase-d-build-coordination.md`. | Only with SPEC-QB-01 reopened. |
| SPEC-RD-01 radiff2 adapter and `comparison/` package | **dropped (D-26, draft)** | `00-decisions.md:34`: "no radiff2 adapter planned"; rz-diff (SPEC-11) already covers the external byte-level role. File-level byte, section and layout diff is re-homed to SPEC-26 (`src/patchtrace/pe_overview/compare.py`, `src/patchtrace/raw_view.py`). Opcode-vs-operand and CFG delta fold into SPEC-31 channels (C1, C2). | Never for the adapter. The alignment idea (F03) may go to `representations/` as a pure function. |
| SPEC-RD-02 modular integration | **dropped (recommended)** | Superseded by RD-01's removal. Its hazard note on radiff2 CLI changes is kept in the owner backlog only. | Only if an adapter is reopened. |
| SPEC-DA-01 Diaphora optional engine | **deferred (D-24, draft; Mode A only recommended)** | `docs/specs/diaphora-optional-engine.md` is "developer-ready DESIGN; no code". No Diaphora code in `src/`, `tests/`, `tools/` or `.github/`. `src/patchtrace/unified/registry.py:80-81` lists a catalogue entry "ideas only, no code", not an adapter. `tasks/todo.md:195` lists "Diaphora adapter and its two named tests" as not built. `docs/plans/unified-engine-backups.md:29` (B-19): none until DA-01 D3 merges. Diaphora is AGPL-3.0 and needs IDA to create any real input. | SPEC-31 S4 is merged AND the owner has a licensed IDA export to test against. Then build Mode A (import an existing `.diaphora` result) only. |

Correction for DA-01: the ledger says `secondary/scheduler.py` parses after its temporary directory is removed. That is false on `main`. `scheduler.py:136` opens the `TemporaryDirectory` and `scheduler.py:159` calls `adapter.parse` inside it. Drop that gate from the DA-01 revisit list.

## 4. Test and acceptance plan

| Rule | Covered by (existing) | Gap |
|---|---|---|
| NG-R1, N-02 | `tests/test_ui_series.py` (window construction and show, `:36` onward); `tests/test_ui.py` (`MainWindow` construction, `:18`, `:25`) | No test asserts that no top-level window beyond `MainWindow` and `SeriesWindow` is created. A test that counts `isWindow()` widgets would close the gap. The `SeriesWindow` exception remains until converted. |
| N-01 | none needed (absence) | A repository search test for `docker` in `src/` is optional. |
| N-03 | none (no call-graph module on `main`) | Canvas and frame-time gates belong to WB2 and are not counted here. |
| N-04 | none for the absence of a chat widget | Acceptable as a review item. Provider endpoint rules are outside this file's rule. |
| N-05 | none | A test that the dark stylesheet is applied at `ui.py:97` is optional. |
| N-06 | `tests/test_acquisition_quarantine.py:132` (`not an AMD64 PE`), `:146` (`x64`); `tests/test_acquisition_winbindex.py:49` (`direct.x64`); `tests/test_binexport_pipeline.py:122-125` (`test_lookalikes_explained`, which pins ELF and PE magic) | The `validate_pe` MZ rejection (`ingestion.py:78`) has no test found by grep in `tests/*.py` top level; check subdirectories before relying on it. |
| N-07, N-08 | `tests/test_spec_registry.py` (fails when a spec under `docs/specs/` is not cited in REGISTRY) | Reserved-number rule is not enforced by a test. |
| N-09 | none (documentation) | Ratification of QB-02, RD-02 and DA-01 is an owner action. |

Owner-only and Windows-only gates are listed separately and are not counted as done: M11 high-contrast review (N-05), the Windows offline-backend install (SPEC-06 M6, which is the reason N-01 holds), and the SeriesWindow dock conversion gate (N-02). None of these is a test in this file.

## 5. Open questions

1. **Ratify N-09.** Default: accept the ledger's drop of QB-02 and RD-02 and the defer of DA-01 Mode A, recorded by the user in `tasks/todo.md`. Owner: user.
2. **SeriesWindow.** Default: convert to a dock in the E-2 panel-registry work and amend `docs/specs/series-window.md` section 6 in that PR. Owner: B.
3. **Number SPEC-55.** Allocated; registered in REGISTRY with status draft.
4. **Graph diagram.** Default: keep the ego-graph diagram planned behind the text table, with the 2,000-node limit from WB2. Owner: B.
5. **Architecture label.** Default: keep ARM64 only as a display label in `pe_overview`, and say so in the UI footer if it is shown. Owner: B.

## 6. Integrator asks

- Add a row for `docs/specs/non-goals.md` to `docs/specs/REGISTRY.md` (Table A: status draft, owner integration owner, basis: this file). The registry test requires the citation.
- REGISTRY next free number advances past SPEC-55 when this file is registered.
- No shared-file change is requested.
