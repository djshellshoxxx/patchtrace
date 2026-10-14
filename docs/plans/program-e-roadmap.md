# Program E roadmap: complete feature set, audits, builds, guided RE (opened 2026-10-14)

Owner directive (user, 2026-10-14, binding): integrate the high-value tools so that the **combined** product is worth more than the tools used standalone; one research worker per spec to plan for maximum integration value and success, including how to build the GUI modules; framework workers first, then build to spec, bug-test, QA, Windows build. Finish **all** features first (KB-CVE correlator, patch search, label training, workbench, capa, FLOSS, Detect It Easy, YARA-X, CISA KEV, unified engine, CSAF and patch-intent remainders), then a full feature and code audit, a full bug check, QA and fixes, then Windows and Linux builds. Then two research workers on guiding a person through reverse engineering with the finished tool, implement that guide (a deterministic teacher, **not AI-assisted**), then feature audit, bug check, extensive QA, beta-style testing, a performance check and a Windows build. Many workers at once, cheapest capable model, modular best-practice code, check progress every 12 hours until complete.

Standing rules still in force: `AGENTS.md`, `CLAUDE.md`, `phase-d-build-coordination.md` sections 2-4 (frozen seams, builder protocol, integration protocol). Prereleases only: **no final (non-prerelease) release without an explicit owner instruction**. Microsoft-derived data (binaries, PDBs, Winbindex-derived labels) stays on the owner's machine and is never committed. Primary-source research only (vendor/standard/upstream docs and papers; no blogs, videos or AI summaries). No GPL/AGPL code is copied (Ghidriff, Diaphora, PatchDiff2, Turbodiff are references only).

## 1. Phases and exit gates

| Phase | Scope | Exit gate |
|---|---|---|
| E-0 | PR #42 (Phase D wave 0) merged; Windows prerelease in Releases | Linux, Windows, native matrix, live checks green; release asset + sha256 verified |
| E-1 | One research worker per feature writes an integration-value plan (`docs/specs/program-e/<ID>-integration-plan.md`); a synergy architect then writes the anchor-fabric contract | every track below has a reviewed plan; amendments applied to the ChatGPT specs |
| E-2 | Framework workers: GUI panel registry + shared widgets, insight/anchor fabric contracts and storage, dependency enablement (wheels-only, PyInstaller hooks, frozen smoke), offscreen Qt test helpers | frameworks merged with tests; builders can work in parallel on disjoint files |
| E-3 | Builders to spec in waves of at most 20 workers; QA and bug hunters after each wave; every wave through PR + full CI + squash merge | per-wave gate (section 5); all tracks `done` in the ledger |
| E-4 | Ten read-only code/feature auditors, bug hunters, extensive QA, fixes, Windows + Linux prerelease builds | audit findings closed or recorded; builds attached to a prerelease |
| E-5 | Two research workers on guided RE, then the guide (teacher) implemented | guide merged; every lesson step links to a real feature |
| E-6 | Final feature audit, bug check, QA, scripted beta scenarios, performance check, Windows prerelease build | gates in section 5; owner manual acceptance listed separately |

## 2. Tracks

| ID | Feature | Source specs (files) | Existing code to build on | Builder tier (provisional) |
|---|---|---|---|---|
| UE | Unified diff engine (S0b, S1, S2, S3, S4, S5, S6) | `specs/unified-engine/`, `plans/unified-engine-plan.md` | `unified/` (S0a), `secondary/`, `backend.py` | S1, S2, S3: Opus; others Sonnet |
| KB | KB-CVE correlator + KB patch search, one coherent workflow | `specs/kb-cve-correlation-and-acquisition.md`, `specs/kb-cve/`, `specs/kb-patch-search-*.md`, `plans/kb-patch-search-*.md` | `enrichment/`, `acquisition/`, `intelligence/csaf`, `ui.py` AcquisitionDialog | Sonnet; service/storage slice Opus |
| LBL | Label training: known-answer corpus completion, `evaluate.py`, mutation operators, calibration training run, honest-scope artifact | `specs/known-answer-corpus.md`, `specs/tier-w-local-corpus.md`, `specs/calibration-corpus-and-model.md` | `tools/calibration/`, `calibration/`, `corpus/` | Sonnet; statistics Opus |
| WB1 | Indexed search: SQLite FTS5, RapidFuzz, QCompleter | `specs/workbench/01-*.md` | `service.py`, `models.py`, `ui_evidence.py` | Sonnet |
| WB2 | Call graph / XREF explorer, NetworkX, Graphviz DOT export | `specs/workbench/02-*.md` | `FunctionRecord.callers/callees`, `nway/graph.py` | Sonnet; canvas Opus |
| WB3 | Strings: FLOSS extraction, per-side delta, search anchors | `specs/workbench/03-*.md`, `specs/three-tool-evidence-adapters.md` | `intelligence/tools/floss.py` | Sonnet |
| WBQ | Quick wins: Pygments, pefile, difflib review, demangling | `specs/workbench/04-quickwins.md` | `pe_overview/`, diff views | Haiku/Sonnet |
| CAP | capa: capability deltas on matched function pairs | `specs/three-tool-evidence-adapters.md` | `intelligence/tools/capa.py`, `intelligence/hypotheses.py` | Sonnet |
| DIE | Detect It Easy: build-environment fingerprint, packer/compiler noise attribution | `specs/three-tool-evidence-adapters.md` | `intelligence/tools/diec.py`, `pe_overview/` | Sonnet |
| YRX | YARA-X: analyst-reviewed discoveries to tested, provenance-carrying rules | none yet (E-1 writes it) | new `rules/` package | Sonnet; rule synthesis Opus |
| KEV | CISA KEV: verified exploitation context for CVE-driven triage | none yet (E-1 writes it) | `enrichment/intelligence.py` patterns | Sonnet |
| PIL | Patch-intent localization (30a-d) and CSAF CLI/reports | `specs/patch-intent-localization-engine.md`, `specs/csaf-cve-interpretation-engine.md` | `intelligence/` | Sonnet; Opus for localization |
| FAB | Insight / anchor fabric (cross-feature links, leads, triage) | written by the E-1 synergy architect | `enrichment/storage.py` kinds | Opus |
| GUI | Panel registry and shared widgets (single main window) | written by the E-1 GUI-architecture researcher | `ui.py`, `ui_evidence.py`, `ui_engine_setup.py`, `tooltips.py` | Sonnet |
| GDE | Guided RE teacher (E-5) | written in E-5 | all of the above | Sonnet; content Opus |

Spec numbers are reconciled in `specs/REGISTRY.md`.

## 3. Integration value charter (every track must satisfy it; the E-1 plans prove it)

1. **Pair-aware**: consumes the older/newer orientation and the matched function pairs (Ghidriff, BinDiff, unified), not just one file.
2. **Delta, not inventory**: reports what changed between the two sides (and across an N-way series), with the unknown/absent distinction (missing is not a negative vote).
3. **Anchors in, anchors out**: reads and writes the shared anchor fabric (function, string, import/API, capability, rule, build fact, advisory phrase, CVE, KB, CWE) so other features can use the result.
4. **Triage value**: improves "where do I look first" with explained, independent-channel evidence; never averages engines or channels; shared-origin evidence counts once; uncalibrated numbers are never shown as vulnerability confidence.
5. **One click to the code**: every finding navigates to the old/new code location inside the single main window.
6. **Provenance and reproducibility**: tool version and pin, parameters, input hashes, consent record, staleness; nothing silently rewritten.
7. **Offline-first, degrade gracefully**: optional components give clear blocked/unavailable states; no network without consent; no target binary is ever executed.
8. **Teachable**: exposes the "what this means / what to do next" hooks the E-5 guide consumes.
9. **Synergy test**: at least one known-answer scenario where the combined result beats each channel alone (recorded as a test, not a claim).

## 4. Worker protocol and model ladder

- Protocol: `phase-d-build-coordination.md` section 3 (isolated worktree, local commits, no push, exclusive files, red/green tests, ruff + full suite twice, report at most 250 words). Research workers write only their own files.
- Models: Haiku for fixtures, registries, cross-reference scans, lint; Sonnet for research, frameworks, most builders, QA and bug hunters; Opus only after two serious Sonnet attempts failed on one problem or for a slice a plan flags as hard. **Fable is never used** (owner instruction 2026-10-14). Be patient: never cancel a worker that is making progress.
- Concurrency and instances: three instances (A, B, C) per `multi-instance-coordination.md`, at most 12 workers each (4 CPUs per container); each instance pushes only to its own branch and merges its own PRs.
- Modularity: pure domain models and adapters separate from Qt; one package per feature; every cross-feature call goes through a Protocol (port) or the anchor fabric; no feature imports another feature's internals.
- Windows pitfalls checklist for every builder: CRLF (`.gitattributes` for pinned/generated files), 32767-character `PYTEST_CURRENT_TEST` (short explicit parametrize ids), coarse `time.monotonic()` (`>=`), YAML plain scalars with `: `, wheels-only installs (`--only-binary=:all:`), tests must be hermetic (never touch the network unless the test is a declared live test).

## 5. Gates

- Worker: ruff clean, new tests red then green, full suite twice, schema drift check, no stray files.
- Wave (integration owner): merge in dependency order, full gate twice locally, one PR, Linux + Windows QA + native matrix + live checks green, squash merge, reset the designated branch to main, ledger updated.
- Feature done: charter items 1-9 evidenced, GUI offscreen tests (20x repeat without abort), tooltips and accessibility names registered, docs and `docs/modules.md` updated, frozen smoke covers the feature's import.
- Blocked external acceptance (Windows desktop DPI and screen reader, Microsoft hosts, Tier W on the owner's machine, real third-party executables in the GUI) is reported separately and never counted as done.

## 6. Check protocol (every 12 hours until complete)

A recurring routine wakes this session. On each wake: list workers and open PRs; if work is idle or stalled, resume the next ledger item; if workers finished, integrate; report to the owner only when blocked, when a phase gate passes, or when a decision is needed.

## 7. Ledger (integration owner updates)

| Item | State | Evidence |
|---|---|---|
| E-0 PR #42 | merged 67e5a6c; prerelease v0.1.0-beta.202 pending verification | release job run 38558039288 |
| E-1 research | not started | |
