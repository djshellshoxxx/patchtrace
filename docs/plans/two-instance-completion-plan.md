# Two-instance completion plan (DRAFT: planned 2026-10-14, NOT started)

Start only when the go/no-go checklist in section 7 is true. Numbers marked [inf] are estimates from this session's observed agent usage (Opus builders 0.45-0.7 M tokens each, Sonnet research/finder agents 0.3-0.65 M); no billing data was available.

## 1. Goal and split
Finish every remaining feature with two coordinated Claude Code cloud instances sharing one GitHub repository.
- **Instance A** = the current session (integration owner of the unified engine SPEC-31, the corpora, hardening, GUI seams, audits and the missing-spec work).
- **Instance B** = a new session with 26 workers (integration owner of KB/CVE correlation + patch search, patch intent, Diaphora, packages, bundle, verification).
The instances share nothing but GitHub: disjoint file ownership, frozen contracts on `main`, one designated branch and one PR per wave per instance.

| Feature | Spec | Owner | Slices |
|---|---|---|---|
| Unified engine | `specs/unified-engine/` (SPEC-31 UE) | A | S0b, S1, S2, S3, S4, S5, S6 |
| Known-answer + Tier W corpora, evaluation | known-answer-corpus (SPEC-32), tier-w (SPEC-33) | A | merge D, W, finders, creators; S6 runs |
| KB/CVE correlation + patch search | ChatGPT `kb-cve-correlation-and-acquisition.md` (calls itself SPEC-31; refer to it as KBC / SPEC-34) | B | 31-A..H, I = B integrator |
| CSAF follow-ups (correlate, scoring) | csaf-cve-interpretation-engine | B | after track K merges |
| Patch intent | patch-intent-localization-engine (SPEC-30) | B | 30a-d |
| Tool adapters follow-ups | three-tool-evidence-adapters | B | pins, live CI |
| Diaphora optional engine | diaphora-optional-engine | B | D0-D9 (import first) |
| Offline runtime bundle, packages | offline-backend-installer, KBC 31-H | B | payload + licence audit; optional MSU/CAB inventory |
| Missing specs, code-gap audit fixes | `audits/spec-gaps-20261014.md` + area audits | A | per cartographer ranking |
| Windows acceptance, release notes | windows-acceptance-and-milestone-builds | A integrator + USER | manual passes stay with the owner |

## 2. Roles, models, budgets (CLAUDE.md cost rules)
| Role | Model | Use for | Budget | Stop rule |
|---|---|---|---|---|
| Mechanical | Haiku | fixtures from a validator-checked matrix, docs/qa rows, link checks, CI log triage | <= 0.15 M | validator green or escalate once |
| Spec-driven builder / researcher / hunter / test author | Sonnet | pure modules from a frozen contract, primary-source research, diff-scoped bug hunts | <= 0.5 M | owned tests green, report <= 150 words |
| Architecture / safety / Qt / concurrency | Opus | consent + atomicity, state machines, rule engines, Qt wizards, integration | <= 0.7 M | same; one escalation to Fable only for a named hard failing test |
Every worker: owns files exclusively, writes red/green tests first, runs only its owned tests plus ONE full-suite run (the integrator runs the gate twice), reports at 80% budget with partial results, never pushes.

## 3. Instance B roster (26 workers; the B main conversation is the integrator and is not counted)
| # | Worker | Model | Scope (exclusive) | Needs |
|---|---|---|---|---|
| B1 | KBC-A contracts + identity | Sonnet | `kbcorrelation/{contracts,identity}.py`, schemas | frozen spec 31-A |
| B2 | KBC-B MSRC edges + reverse index | Sonnet | `sources/{msrc_index,msrc_edges}.py` | B1 |
| B3 | KBC-C product/update graphs + pair resolver | Sonnet | `product_graph,update_graph,component_hints,pair_resolver` | B1, B2 types |
| B4 | KBC-D acquisition bridge, consent, manual import | Opus | `winbindex_bridge,acquisition_bridge` | B1, B3 |
| B5 | KBC-E workflow, facade, storage | Opus | `workflow,facade,storage` | B1-B4 |
| B6 | KBC-F CLI + view-models + export | Sonnet | `cli,ui_model,export` | B5 |
| B7 | KBC-F Qt wizard | Opus | `ui_kbcorrelation.py` | B5; ui.py seam queued behind A's S4 |
| B8 | KBC-G correlation bridges (capability adapters, staleness, reports) | Opus | `correlate.py` | B5, A's unified read model, track K |
| B9 | INT-30a evidence graph + lineage | Opus | `intelligence/graph.py` | track K, T merged |
| B10 | INT-30b rule engine, fusion, ranking, abstention | Opus | `intelligence/{rules,fusion,quality,ranking}` | B9 |
| B11 | INT-30c CLI/report + Qt pane | Sonnet | `intelligence/{reports,cli}`, `ui_intel.py` | B10; seam queued |
| B12 | DIA Diaphora adapter D0-D5 | Sonnet | `secondary/diaphora/*` | A's S0b adapter seam |
| B13 | PKG read-only bounded MSU/CAB inventory | Sonnet | `kbcorrelation/packages/*` | B4 |
| B14 | BUNDLE offline runtime assembler + licence/NOTICE audit | Sonnet | `offline_bundle.py`, `tools/bundle_*` | none |
| B15 | R-CWE: CWE to patch-motif research for rule packs | Sonnet | `docs/research/intel/*` | none |
| B16 | R-LIVE: CI live-probe workflows for hosts blocked in the sandbox (MSRC, NVD, Winbindex, msdl) + fixture refresh tool | Sonnet | `.github/workflows/live-kbc*.yml`, `tools/kbc_*` | B1 |
| B17 | FIX-KBC fixtures for matrices S01-S10, P01-P14, C01-C15 | Haiku (+validator) | `tests/fixtures/kbc/*` | B1 |
| B18 | FIX-INT fixtures: critical negative tests, paired PE builds from `corpus/ours` | Haiku/Sonnet | `tests/fixtures/intel/*` | B9 |
| B19 | TEST e2e scenarios KB to pair to project to compare to report | Sonnet | `tests/test_kbc_e2e*.py` | B5 |
| B20 | TEST pytest-qt suites, 20x repeat | Sonnet | `tests/test_ui_kbc*.py`, `test_ui_intel*.py` | B7, B11 |
| B21 | TEST property/fuzz for every new parser | Sonnet | `tests/test_*_prop.py` | B2, B13 |
| B22 | BH-kbc diff-scoped hunt | Sonnet | `docs/audits/kbc-*.md` + small fixes | after merges |
| B23 | BH-intel hostile advisories/tool output | Sonnet | `docs/audits/intel-*.md` | B10 |
| B24 | BH-win Windows-only review of everything new | Sonnet | `docs/audits/win-*.md` | after merges |
| B25 | CI-triager (fetch failing logs, <= 30-line diagnosis) | Haiku | none (read-only) | on demand |
| B26 | DOC/QA: `docs/qa.md` evidence rows, module index, help/README, tooltip coverage | Haiku/Sonnet | docs only | rolling |
Peak concurrency is wave dependent (section 5), never above the cap.

## 4. Instance A roster after the current wave (cap 20, or the raised cap)
S0b, S1, S2 (Opus, wave 1); S3, S4, S5 (Opus, wave 2); S6 gates (Sonnet + Opus review); ten read-only area auditors (Sonnet; acquisition, enrichment, UI/preflight, secondary/evidence, nway, calibration, CLI surface, packaging/runtime, reports/AI/diagnostics, test-quality) writing <= 80-line gap reports; spec writers for the cartographer's top missing specs (Sonnet, Opus when hard); fix-slice workers from audit findings (Sonnet); post-merge hunters for unified, S4 UI (Sonnet); one CI-triager (Haiku).

## 5. Waves and gates
| Wave | Instance A | Instance B | Exit gate |
|---|---|---|---|
| W0 (now) | finish K, T, B, G, D, W, S0a, swarm, researchers, hunters; merge; main green | not started | G0: all agents reported, one merged PR per track set, main green on Linux, Windows, native matrix |
| W1 | S0b, S1, S2; audits; missing specs | B1 first (30-45 min) with B14-B17; then B2, B3, B4, B9, B12, B13 | G1: contracts frozen on main (KBC 31-A, `unified` S0a, `intelligence/1`, `tool-evidence/1`); both PRs green |
| W2 | S3, S4, S5; audit fixes | B5, then B6-B8, B10, B11; tests B19-B21 as modules land | G2: unified read model on main (needed by B8/B10); ui.py seam order G, S4, B7, B11 |
| W3 | S6 gates, final hunts, Windows evidence | B22-B26, final hunts, release candidate | G3: all gates, `docs/qa.md` honest (BLOCKED never "done"), beta build published |
Estimated wall clock [inf]: W1 2-4 h, W2 3-5 h, W3 2-3 h after G0.

## 6. Cross-instance protocol
- **Bus = GitHub.** Interfaces in `docs/plans/interfaces.md` (created at G0 and frozen by PR): unified read model (A to B), kbcorrelation facade (B to UI), `intelligence` package ownership (A merges K and T, then B owns it), schema directories (each track owns its own; only A edits `tools/generate_schemas.py`).
- **Ledger = two tracking issues** (A, B) with a checklist per slice, updated at wave boundaries; PR labels `wave-N`, `instance-A|B`. State survives container loss.
- **Shared files** (`cli.py`, `ui.py`, `tooltips.py`, `docs/modules.md`, `tasks/todo.md`, `docs/qa.md`, `enrichment/storage.py`): A edits; B submits hooks of at most 6 lines (12 for ui.py) inside its PR, merged last. Appended doc blocks start with a unique heading `### [A|B:slice]` so keep-both merges never duplicate.
- **Branches:** each instance pushes only its designated branch, one PR per wave, `git fetch` + merge latest `main` before opening it, green Linux + Windows + native matrix before squash merge, then reset its branch to `main`.
- **Messages:** integrator to integrator through `send_message` for blockers; the user is the escalation path. A can start B with `create_session` (it inherits the environment) and watch it with `list_events`.
- **Windows and live truth:** the sandbox cannot reach Microsoft, NVD, Hugging Face, Zenodo or arXiv hosts; live acceptance runs only in CI workflows (B16) or on the owner's machine and is recorded BLOCKED until then.

## 7. Go/no-go checklist and user inputs
1. Every W0 agent reported; their branches merged and pushed; main green on all workflows.
2. Cartographer output reviewed; missing-spec list ranked; ChatGPT's per-slice KBC specs complete and merged (numbering reconciled to SPEC-34 in a docs-only PR).
3. `docs/agents/context-pack.md` (<= 200 lines: repo map, commands, gates, pitfalls such as CRLF, long test ids, 15 ms clock ticks, 32767-char env limit, Qt teardown, Job Objects; the reuse registry of helpers) and one 40-line card per role committed.
4. USER: sets `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS` (>= 26) on the environment(s) before the new session starts, confirms the extra instance's usage is acceptable, and keeps the optional answers (O1 local-only already given; O2, O4 labels; NVD key) pending without blocking.
5. B charter prompt written (this plan + its roster + its designated branch rule + stop rules).

## 8. Token plan and savings levers
- Estimate [inf]: B roster ~26 x 0.4 M = ~10-11 M; A's remaining roster ~24 x 0.45 M = ~11 M; the two main conversations ~2-3 M each. Total ~25-30 M for the whole program; an all-Opus plan would cost ~30-40% more.
- Levers: (1) context pack and role cards instead of every worker re-reading specs; (2) contracts frozen before parallel builders (no rework); (3) Haiku/Sonnet for everything that has a validator or a frozen spec, Opus only where safety, Qt or concurrency demands it; (4) research index `docs/research/INDEX.md` checked before any research task; (5) hunters scoped to `git diff` ranges after merge, never the whole repo; (6) builders run owned tests plus one full run, the integrator runs the gate; (7) Windows verified by CI + the Haiku triager, not by reasoning; (8) wave-level PRs and one batched merge; (9) reports capped at 150-250 words.
- Lean variant (-20%): defer B12 (Diaphora), B13 (packages), B14 (bundle) and B19-B21 until the modules they test exist.

## 9. Risks
Cross-instance conflicts on shared files (mitigated by section 6 ownership); duplicated work (ledger + roster); CI queue saturation (one PR per instance per wave, staggered); blocked hosts (CI live probes); unknown billing (user check before start); container disk/CPU limits (4 CPUs: stagger full-suite runs); invented sources (researchers + hunters verify against primary sources); Windows-only failures (CI triager, BH-win); ChatGPT editing specs mid-build (freeze by commit SHA before builders start).
