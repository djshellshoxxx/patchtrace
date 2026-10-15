# PatchTrace guide: index and map

PatchTrace is a desktop workspace and a headless CLI for comparing two Windows x64 binaries and investigating what a patch changed. It compares an older and a newer PE file with Ghidriff (on Ghidra), keeps second-opinion engines and derived evidence next to it, and records your review. It never executes a target binary, never uploads silently, and never shows an uncalibrated number as vulnerability confidence.

This guide was written on 2026-10-15 against `main` at `21a005e` (PR #58, "GUI panel framework F2-F9"). Every behavioural claim was read from the code or a spec; anything planned but not built is marked **planned**, and anything built but not accepted on a real machine is marked **unverified**. Open questions are collected in [99](99-open-doc-questions.md).

## How to read it

| If you are... | Start here |
|---|---|
| a new user who wants to try it | [10 Getting started](10-getting-started.md), then [11 Workflow](11-workflow-compare.md) |
| an analyst reading evidence | [12 Evidence and engines](12-evidence-and-engines.md), [19 Glossary](19-glossary.md) |
| scripting or automating | [16 CLI reference](16-cli-reference.md) |
| concerned about data leaving the machine | [17 Privacy and network](17-privacy-and-network.md) |
| a contributor | [20 Architecture](../internals/20-architecture.md), [32 How to extend](../internals/32-how-to-extend.md), `AGENTS.md`, `docs/plans/worker-brief.md` |
| curious how it was built | [30 History](../internals/30-history-and-process.md), [31 Decisions](../internals/31-decisions-and-tradeoffs.md) |

## Part 1: user manual (`docs/guide/`)

| File | Contents |
|---|---|
| [00-index.md](00-index.md) | this map |
| [10-getting-started.md](10-getting-started.md) | install the Windows zip or Linux tar.gz, first run, the offline bundle, how Ghidra/Java/Ghidriff are found |
| [11-workflow-compare.md](11-workflow-compare.md) | open or create a project, run or import a comparison, read results, correct matches, export |
| [12-evidence-and-engines.md](12-evidence-and-engines.md) | the Engine evidence dock, verdicts, reconciliation, conflicting evidence, the unified tab |
| [13-panels-and-layout.md](13-panels-and-layout.md) | docks, tabs, Ctrl+Shift shortcuts, palette, themes, high contrast, keyboard, accessibility |
| [14-series.md](14-series.md) | 3 to 8 builds, chains, the Series dock |
| [15-files-and-pe-overview.md](15-files-and-pe-overview.md) | Files dock, PE comparison, Authenticode probe, raw Hex/Binary/Base64 |
| [16-cli-reference.md](16-cli-reference.md) | every verb with an example, exit codes 0/2/3/4/5, JSON envelope |
| [17-privacy-and-network.md](17-privacy-and-network.md) | consent model, every host, credentials |
| [18-troubleshooting.md](18-troubleshooting.md) | symptoms, causes, error-code prefixes |
| [19-glossary.md](19-glossary.md) | terms |
| [99-open-doc-questions.md](99-open-doc-questions.md) | what this documentation could not settle |

## Part 2: how it works (`docs/internals/`)

| File | Contents |
|---|---|
| [20-architecture.md](../internals/20-architecture.md) | layers, pure models versus Qt, process boundaries, data-flow diagram (mermaid) |
| [21-data-model-and-storage.md](../internals/21-data-model-and-storage.md) | records, SQLite snapshots, enrichment kinds, sidecars, backups |
| [22-engines-and-fusion.md](../internals/22-engines-and-fusion.md) | Ghidriff, BinDiff, rz-diff, reconcile, the unified ladder, fusion rules, what is calibrated |
| [23-gui-framework.md](../internals/23-gui-framework.md) | panel host, registry, tasks and threads, widgets, theming, testing with `qt_gate` |
| [24-acquisition-and-enrichment.md](../internals/24-acquisition-and-enrichment.md) | Winbindex/symbol-server acquisition, enrichment pipeline, CVE context, providers |
| [25-intelligence-kb-kev-yara-capa.md](../internals/25-intelligence-kb-kev-yara-capa.md) | CSAF, KB correlation, KEV, patch-intent, YARA-X rules, capa/FLOSS/diec, fabric |
| [26-packaging-and-bundle.md](../internals/26-packaging-and-bundle.md) | PyInstaller builds, frozen smoke, release gate, offline bundle |
| [27-testing-and-ci.md](../internals/27-testing-and-ci.md) | test layout, hermeticity rules, workflows, live gates |

## Part 3: how it was built (`docs/internals/`)

| File | Contents |
|---|---|
| [30-history-and-process.md](../internals/30-history-and-process.md) | phases, the multi-instance process, specs first, audits, what each instance built |
| [31-decisions-and-tradeoffs.md](../internals/31-decisions-and-tradeoffs.md) | key decisions and why |
| [32-how-to-extend.md](../internals/32-how-to-extend.md) | add a CLI verb, a panel, a tool adapter, a spec and test |

## Existing documents this guide builds on

| Document | Role |
|---|---|
| `README.md` | public front page and long how-to |
| `AGENTS.md`, `CLAUDE.md` | authoritative engineering policy |
| `docs/modules.md` | per-module responsibility index (850 lines, append-only blocks per slice) |
| `docs/concepts.md`, `docs/user-guide.md`, `docs/install.md`, `docs/privacy.md` | earlier short user docs (this guide supersedes and extends them) |
| `docs/cli-reference.md` | generated flag tables per verb |
| `docs/windows.md`, `docs/linux.md`, `docs/offline-backend.md`, `docs/release-process.md` | platform, bundle and release procedures |
| `docs/qa.md`, `tasks/todo.md` | evidence log and delivery tracker (the honest record of what was verified) |
| `docs/version-history.md` | prerelease tags and what each added |
| `docs/specs/INDEX.md`, `docs/specs/REGISTRY.md` | spec index and numbering registry |
| `docs/specs/program-e/` | integration plans per feature (GUI, KB, KEV, PIL, YRX, FAB, WBQ, BUNDLE, ...) |
| `docs/specs/unified-engine/` | SPEC-31 unified engine (00-decisions through 12) |
| `docs/plans/` | worker brief, ledgers A to D, roadmaps, audits and next-phase plans |
| `docs/audits/` | audit reports |
| `docs/schemas/` | generated JSON schemas of the persisted contracts |

## Map of the source tree (`src/patchtrace/`)

| Area | Where |
|---|---|
| Entry points | `__main__.py` (desktop or CLI dispatch), `cli.py` (built-in verbs, envelope), `cli_commands/` (discovered verbs) |
| Core records and storage | `models.py`, `persistence.py`, `verified_backup.py`, `service.py`, `ingestion.py`, `artifact_bytes.py`, `normalization.py`, `alignment.py`, `sample.py` |
| Backend and processes | `backend.py`, `jobs.py`, `backend_bundle.py`, `offline_bundle.py`, `runtime_discovery.py`, `diagnostics.py` |
| AI interpretation | `evidence.py`, `interpretation.py`, `providers.py`, `reports.py` |
| Enrichment | `enrichment/` (signals, ranking, WIL, CVE, cache, profiles, storage) |
| Acquisition | `acquisition/` (Winbindex, transport, quarantine, delta) |
| Engines | `secondary/` (BinDiff, rz-diff, BinExport, scheduler, reconcile, evidence panel model), `unified/` (ladder, fusion, facts, IR, extract) |
| Series | `nway/` |
| Inspection | `pe_overview/`, `representations/`, `raw_view.py`, `preflight.py`, `symbols/`, `codetext/` |
| Intelligence | `intelligence/` (CSAF, CWE hypotheses, tools capa/FLOSS/diec), `kbcorrelation/`, `kev/`, `pilot/`, `rules/`, `fabric/` |
| Calibration | `calibration/` (runtime only; fitting is in `tools/calibration/`) |
| GUI | `ui.py` (main window), `ui_*.py` (panels and dialogs), `gui/` (pure framework), `gui/qt/` (Qt widgets, host, tasks, theme), `tooltips.py`, `panel_manifest.py` |

Outside `src/`: `tests/` (419 files), `tools/` (build, smoke, pins, live probes, calibration; dev-only, not packaged), `.github/workflows/` (15 workflows), `corpus/`, `site/` (GitHub Pages), `third_party/` (notices), `skills/` (agent skills).

## Conventions in this guide

- Paths are repository-relative. `SPEC-nn` names a spec in `docs/specs/` (registry: `docs/specs/REGISTRY.md`).
- "Built" means the code is on `main` with tests. It does not mean accepted on a clean Windows machine; the acceptance gates (clean Windows GUI run, NVDA/Narrator, DPI, a disconnected-machine bundle run, live local and remote AI provider) are listed as open in `tasks/todo.md` and `docs/plans/ledger-A.md`.
- Numbers such as test counts come from `docs/qa.md` and the ledgers at the date given; they are not re-measured here.
- Nothing in this guide is a statement that a function contains or fixes a vulnerability. Neither is anything PatchTrace prints.
