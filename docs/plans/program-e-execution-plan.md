# Program E execution plan: feature build phase (owner order 2026-10-14 ~20:30Z; supersedes the hold in `program-e-roadmap.md` section 0 for everything except the bundle)

## 1. Owner order (binding)
- Build ALL remaining features and merge them: unified engine S3-S6, KB-CVE correlator + KB patch search, patch-intent localization, label training (C), search (WB1), call graph (WB2), strings/FLOSS (WB3), quick wins (WBQ), capa, Detect It Easy, YARA-X, CISA KEV, the GUI panel framework (critical path for every panel), anchor fabric. The bundle (C) stays the essential priority and continues in parallel.
- **Deferred by the owner: the guided RE teacher (GDE / E-5).** No GDE slice starts; C does not merge its local G1-G4 yet.
- Capacity: instance A up to **23 workers**, instance B up to **23 workers**, instance C up to 12 (bundle first, then label training). Fill a slot only with a slice whose dependencies are met.
- Same constraints as before: cheapest capable model (Haiku mechanical, Sonnet default; Opus only after two failed Sonnet attempts on one problem, and never while the rate limit status is `allowed_warning`; **Fable never**), token-frugal prompts and reports (workers read `worker-brief.md`; reports at most 250 words), modular best-practice code, patience with running workers (never cancel one that is progressing), autonomous operation (ask the owner only for a real blocker or an owner-only input).
- Builds: a Windows zip + Linux tar.gz prerelease at **every third milestone** (section 2). No final release without an explicit owner instruction.

## 2. Milestones and the release gate
A **milestone** is one code merge to `main` (a squash-merged wave PR from any instance; docs-only merges carry `[skip ci]` and do not count). `.github/workflows/qa-windows.yml` still runs the full Linux + Windows QA and builds both packages on every merge, but its `release` job publishes a prerelease only when `tools/release_gate.py` says so: the third counted merge since the latest published prerelease, a commit message containing `[release]`, a tag, or no earlier prerelease. Until slice RG is on `main` every merge publishes (the old behaviour); A announces the RG merge by message. Instances never add `[release]` themselves unless A asks.

## 3. Governors
- Budget: before launching a batch read `get_session` (no id) `external_metadata.rate_limit_info`. `allowed` or `allowed_warning`: launch (no Opus on warning). Anything else: launch nothing, finish what runs, message A. Workers that fail with HTTP 429 are resumed with `SendMessage` after the reset; never cancel or restart them.
- CPU (4 CPUs per container): workers run only their focused tests, niced; the integrator runs the full suite (twice) per wave PR. Compute-heavy jobs go to GitHub Actions, not agent loops.
- Context: orchestrators keep prompts to ten lines plus the slice id; everything else is in the brief and the plans.

## 4. Shared files in this phase (one owner each)
| Files | Owner | Everyone else |
|---|---|---|
| `ui.py`, `tooltips.py`, `tests/test_tooltips.py`, `gui/**`, `panel_manifest.py` | A (F-slices; F5 is the single seam owner) | Qt panels start after F5 is on `main`; until then pure `panel.py` + view-models only |
| `cli.py`, `tools/frozen_smoke.py`, `tests/test_acceptance_smoke.py`, `cli_commands/__init__.py` | A (F1b) | after F1b a verb is `cli_commands/<verb>.py`; before it, write the Qt-free dispatcher and list the adapter as an integrator ask |
| `pyproject.toml`, `optional_deps.py`, `tools/build_*.py` licence/dependency lists, `enrichment/storage.py` `KINDS` | B (integrator asks from all) | no direct edits |
| `backend.py`, `backend_bundle.py`, `offline_bundle.py`, `tools/*bundle*`, `backend-bundle.yml` | C | no edits |
| `.gitattributes`, `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` | append-only, unique heading per slice | the integrator keeps both sides |

## 5. Merge protocol (each instance, one PR per wave)
Merge worker branches into your integration branch in dependency order (`/tmp/mergeone.sh`-style keep-both for the three append-only docs), run the full suite twice in the foreground (QT_QPA_PLATFORM=offscreen), `ruff check src tests tools`, fetch and merge `origin/main`, push your designated branch, open a draft PR (watch it), mark ready when Windows + Linux QA, native matrix and live workflows are green, squash-merge with `expectedHeadSha`, reset your branch to `main`, message the others in one line (SHA + what unblocked). A merge conflict in a non-doc file means two slices touched the same file: stop, resolve conservatively, note it in the ledger. Pushing only to your own designated branch (A `claude/clever-clarke-s4nhi6`, B `claude/instance-b-features`, C `claude/instance-c-research`).

## 6. Assignments
Worker ids are labels for ledgers. "chain" = one worker, slices in order, commit per slice. Plans are in `docs/specs/program-e/`.

### 6.1 Instance A, wave 1 (18 workers)
| Id | Slice(s) | Tier | Card |
|---|---|---|---|
| A01 | GUI F0 (apply the plan's section 10 doc amendments) | haiku | GUI plan 9, 10 |
| A02 | GUI F1 pure core | sonnet | GUI plan 7, 8, 9 |
| A03 | GUI F1b CLI-extension registry | sonnet | GUI plan 8.12, 9 |
| A04 | RG release gate (`tools/release_gate.py`, workflow job, tests) | sonnet | section 2 |
| A05 | UE S3 (IR channels, operand classifier, DATA-MAP, alignment, proofs) | sonnet | `plans/unified-engine-plan.md` s3 S3; `specs/unified-engine/03,04,05` |
| A06 | UE S5 (residual: blocking, P16-P19, LAP) | sonnet | same, S5 |
| A07 | UE S6a (Tier R recipes, A/A and mutation scripts, bench, workflow) | haiku/sonnet | same, S6 |
| A08 | PIL-T oracle | sonnet | PIL plan 9 wave B |
| A09 | PIL-A2 advisory-side adapters | sonnet | same |
| A10 | PIL-A3 code-side adapters | sonnet | same |
| A11 | PIL-B1 rule table | sonnet | same |
| A12 | FAB-0: write `FAB-integration-plan.md` (research-brief format, at most 250 lines; align with every plan's section 4 anchors and GUI `AnchorRef`), then the pure core `fabric/` (contracts, AnchorSink/AnchorReader, in-memory sink, store kind request) | sonnet | roadmap track FAB |
| A13 | KEV chain K0 -> K1a -> K1b | sonnet (K0 haiku part) | KEV plan 9 |
| A14 | YRX chain R0 -> R2 | sonnet | YRX plan 9 |
| A15 | WBQ chain S1 -> S2 (resources, version info, manifest) | sonnet | WBQ plan 9 |
| A16 | WBQ S4 (exports table, API delta) | sonnet | same |
| A17 | WBQ S7 (codetext core) | sonnet | same |
| A18 | WBQ S10 (symbol decoration) | sonnet (fixture haiku) | same |
Wave 2 (A, as predecessors merge): GUI F2 -> F3/F4 -> F5 -> F6a/F6b/F7/F8 -> F9 (critical path; F2 starts when F1 is merged); UE S4 (after F5), PIL B2 (Opus-flagged, start Sonnet), C1, C2 (after F5), D1, D2; KEV K2-K6; YRX R1, R3-R8; WBQ S5, S6, S8, S9, S13; FAB builder slices; UE S6b gates.

### 6.2 Instance B, wave 1 (14 workers)
| Id | Slice(s) | Tier | Card |
|---|---|---|---|
| B01 | KB K2 store, reducer, recovery (Sonnet first; Opus only on the ladder rule) | sonnet | KB plan 9 |
| B02 | CAP-0 docs | haiku | CAP plan 9 |
| B03 | CAP chain CAP-1 -> CAP-2 -> CAP-3 | sonnet | CAP plan 9 |
| B04 | DIE D1 diec adapter hardening | sonnet | DIE plan 9 |
| B05 | DIE D2 PE build facts, **owns `pe_overview/rich_header.py`** (WBQ S3 is delivered by D2) | sonnet | DIE plan 9 |
| B06 | WB1 chain S0 -> S1 -> S2 | sonnet | WB1 plan 9 |
| B07 | WB2 G0 shape tables | haiku | WB2 plan 9 |
| B08 | WB2 G1 core graph | sonnet | WB2 plan 9 |
| B09 | WB3 S0 contracts + table | sonnet | WB3 plan 9 |
| B10 | WB3 S1 sources + S3 built-in scan | sonnet | WB3 plan 9 |
| B11 | WB3 S2 regions and cues | sonnet (golden tables haiku) | WB3 plan 9 |
| B12 | SPEC-07 derived-cache hit objective (500 ms at 10,000 pairs; measured 3.1 s): profile and fix | sonnet | `tasks/todo.md` SPEC-07, `tools/bench_enrich*` |
| B13 | acquisition/transport audit fixes (C-01 slow-drip High and the other findings) with red tests | sonnet | `docs/audits/20261014-C-acquisition-gui.md` |
| B14 | CAP-4 raw-first cache (after B03's CAP-1 is merged: start it from B's integration branch) | sonnet | CAP plan 9 |
Wave 2 (B, as predecessors merge): KB K3 -> K4a/K5/K6 -> K4b, K7, K8, K9; CAP-5, CAP-7..CAP-11 (CAP-6a/b after F5); DIE D3 -> D4, D6, D7..D10 (D5 after F5); WB1 S3 -> S4 -> S5/S6 -> S7..S10; WB2 G2 -> G3..G9; WB3 S4..S9; the Qt panels after F5. B is free to rebalance inside its tracks and to take A's YRX/KEV/WBQ follow-ups when A is saturated (say so in one line).

### 6.3 Instance C
Finish the bundle first (B9 docs/QA, B10 first live full builds and offline acceptance, then fix what the live runs expose). Then label training: merge the built LBL slices (LBL-00, 01/09/11 evaluator and CLI, 06 mutations, 10 statistics, 14 shard runner, 17 shipped scope), continue LBL-02..05, 07, 08, 12, 13, 15, 16, 18..25, run the Tier R training, produce the honest-scope artifact. GDE stays unmerged and unstarted. At most 12 workers.

## 7. Overlaps decided
- `pe_overview/rich_header.py`: DIE D2 (B05) only; WBQ S3 is dropped, WBQ S5 consumes D2's module.
- `pe_overview/` new modules from WBQ S1/S2/S4, DIE D2, YRX R4 (`tables.py`) are different files; `models.py`, `inspect.py`, `compare.py`, `__init__.py` belong to WBQ S5 (A), later.
- Anchors: GUI F1 owns `gui/anchors.py` (closed kinds); FAB adapts through `AnchorRef.from_fabric`.

## 8. Reporting
Each instance keeps its ledger (`docs/plans/ledger-<A|B|C>.md`) current, messages the others only for a merged PR (SHA and what it unblocks) or a blocker, and messages the owner (through A) only for owner-only inputs. A runs the 12-hour routine and the milestone count.
