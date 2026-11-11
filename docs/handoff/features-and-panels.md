# Handoff: KB/CVE correlator, WB1-WB3, KEV, CAP, DIE, YARA-X, fabric and the Qt panels

Audience: an engineer or a Claude session with no chat history. Written 2026-10-15 against `claude/instance-d-gui` at `da7d2db`. Facts come from the repository, `git`, the workflow files and focused test runs. Anything not confirmed is marked UNVERIFIED. Policy files that override this page: `AGENTS.md`, `CLAUDE.md`, `docs/plans/worker-brief.md`.

Other areas (label training, unified engine, backend, release) are covered by sibling pages the lead requested under `docs/handoff/`; this page does not repeat them. If one is missing, it has not been merged yet.

## 1. Purpose and current state

Purpose: finish the feature tracks listed in the title and put each one in a dock of the single main window. The domain code (Qt-free packages) is mostly built. What is mostly missing is the Qt layer: 9 of the 14 reserved panels do not exist.

### 1.1 Commands that prove the state

Run from the repository root (a worktree is fine). `PYTHONPATH=src` is needed unless the package is installed with `pip install -e .`.

```
git fetch origin
git merge --ff-only claude/instance-d-gui          # integration branch, PR #64; da7d2db when this page was written
export PYTHONPATH=src QT_QPA_PLATFORM=offscreen
python -m patchtrace panels list                   # observed: "panels: 14 listed, 5 built, 9 not built, 0 failed to load"
python -m patchtrace panels check                  # observed: "conflicts: none" plus one warning (see section 5, P-10)
python -m pytest -q -p no:cacheprovider tests/test_kbc_synergy.py tests/test_kb_adapters_k8.py
```

Observed on `ad2f207` (the tip of `claude/instance-d-gui` before the last five QA commits; those commits touch `rules`, `unified`, `enrichment` and `pilot` only):

```
tests/test_gui_core_manifest.py tests/test_kb_adapters_k8.py tests/test_kbc_synergy.py tests/test_kev_synergy.py
tests/test_kev_kb_integration.py tests/test_fabric_adopt.py tests/test_fabric_pins.py tests/test_rules_view.py
tests/test_buildenv_timeline.py tests/test_buildenv_value_gate.py tests/test_capa_setup.py tests/test_capa_extent.py
tests/test_search_sources_unified.py tests/test_search_anchors.py tests/test_callgraph_sources.py
tests/test_ui_strings_run.py tests/test_live_strings.py tests/test_strings_synergy.py
=> 351 passed, 3 skipped, 2 failed      (the live FLOSS tests print "LIVE ACCEPTANCE BLOCKED", they do not fail)
```

Re-run on `da7d2db`: `tests/test_kbc_synergy.py` still gives 20 passed, 2 failed (section 3, item R-01). `tests/test_ui_leads.py::test_loading_the_declaration_imports_no_qt_and_no_feature` also failed here because the test starts `python -I` (isolated mode ignores `PYTHONPATH`) and `patchtrace` was not pip-installed in this sandbox. Run `pip install -e .[dev,search,rules]` first; with the package installed this is UNVERIFIED as green.

Git topology (all SHAs from `git rev-parse --short`):

| Ref | SHA | Meaning |
|---|---|---|
| `origin/claude/instance-d-gui` | `da7d2db` | integration branch, PR #64; the target of all work in this page |
| `origin/main` | `00db4c9` | already contained in the integration branch |
| `origin/claude/instance-b-features` | `6e1e153` | instance B; its tree differs from the integration branch in 8 files (section 1.3) |
| `origin/claude/instance-c-research` | `393d09b` | label training (instance C); not this page's area |
| `origin/chatgpt/panels-1` | `cfd7cff` | ChatGPT panel spec drafts, unreviewed, not merged (section 2.3) |
| `origin/chatgpt/kb-fixtures-1`, `unified-fixtures-1`, `corpus-1`, `help-docs-1`, `deferred-audit-fixes-1` | not read | other ChatGPT drafts, out of scope here |
| local `worktree-agent-*` | 44 not merged into `da7d2db` | LOCAL ONLY: `git branch -r | grep -c worktree` prints 0. Never pushed. See 1.3 |

### 1.2 Panels: what exists (manifest `src/patchtrace/panel_manifest.py`, output of `panels list`)

| Panel id | Dock / tab group / shortcut | Built? | Spec in repo | Spec draft (unreviewed) | Qt-free view model | Qt layer |
|---|---|---|---|---|---|---|
| `evidence` | right / - / Ctrl+Shift+E | yes (`secondary/evidence_panel.py`) | `docs/specs/multi-engine-evidence-panel.md` | - | yes | `ui_evidence.py` |
| `unified` | right / evidence / Ctrl+Shift+U | yes (`unified/panel.py`) | `docs/specs/unified-engine/07-ui-and-cli.md` | - | `unified/read_model.py` | `ui_unified.py` |
| `leads` | left / - / Ctrl+Shift+L | yes (`pilot/panel.py`) | PIL plan s8 | - | `pilot/read_model.py` | `ui_leads.py` |
| `files` | bottom / - / none | yes (`pe_overview/panel.py`) | `docs/specs/gui-preflight-inspection.md` | - | `pe_overview/*` | `ui_inspection.py`, `ui_pemeta.py` |
| `series` | bottom / - / none | yes (`nway/panel.py`) | `docs/specs/series-window.md` | - | `nway/view_model.py` | `ui_series.py` |
| `kb` | right / - / Ctrl+Shift+K | NO on the integration branch. Built on local branch `worktree-agent-ae1ddf7ace07cf49d`, commit `72605cd` | KB plan s8 | `panels/kb.md` | `kbcorrelation/view_model.py` (on the branch also `gui_model.py`, `gui_backend.py`) | `ui_kb.py`, `ui_kb_online.py` only on that commit |
| `kev` | right / kb / Ctrl+Shift+X | no | KEV plan s8 | `panels/kev.md` | `kev/view_model.py`, `kev/teach.py`, `kev/tooltip_entries.py` | missing (`ui_kev.py`, `kev/panel.py`) |
| `search` | bottom / - / Ctrl+Shift+F | no | WB1 plan s8 | `panels/search.md` | `search/view_model.py`, `search/tooltip_data.py` | missing (`ui_search.py`, `search/panel.py`) |
| `graph` | bottom / - / Ctrl+Shift+G | no | WB2 plan s8 | `panels/graph.md` | `callgraph/view_model.py`; `gui/qt/canvas.py` (generic canvas) | missing (`ui_calls.py`, `callgraph/panel.py`) |
| `strings` | bottom / graph / Ctrl+Shift+T | no | WB3 plan s8 | `panels/strings.md` | `strings/view_model.py`, `strings/copy.py`, `strings/tooltip_entries.py` | only the run dialog `ui_strings_run.py`; missing `ui_strings.py`, `strings/panel.py` |
| `capabilities` | bottom / graph / Ctrl+Shift+A | no | CAP plan s8 | `panels/capabilities.md` | `intelligence/tools/capa_view.py` | missing (`ui_capabilities.py`, a `PANEL` module) |
| `build_env` | right / evidence / Ctrl+Shift+B | no | DIE plan s8 | `panels/build_env.md` | `buildenv/view_model.py`, `buildenv/copy.py`, `buildenv/overlay.py`, `buildenv/timeline.py` | missing (`ui_build_env.py`, `buildenv/panel.py`) |
| `rules` | right / - / Ctrl+Shift+R | no | YRX plan s8 | `panels/rules.md` | `rules/view.py`, `rules/panel_service.py` (R6a) | missing (`ui_rules.py`, `rules/panel.py`) |
| `guide` | left / - / Ctrl+Shift+H | no | none | `panels/guide.md` (deferred stub) | none | none |
| `related` (not in the manifest) | planned bottom / leads / Ctrl+Shift+J | no | FAB plan s8, `docs/specs/panels/related.md` (created with this page) | none | none | none |

Manifest placement is binding. Older plans that say "right, tabbed with evidence" for CAP and WB3 are superseded: CAP and WB3 are `bottom` / tabbed with `graph`. A built `PanelSpec` is linted against its manifest slot by `panels check`.

### 1.3 In-flight work you must know about

- `worktree-agent-ae1ddf7ace07cf49d` (local only): commit `72605cd` "KB K4b dock and K7 online pages". Adds `src/patchtrace/ui_kb.py` (712 lines), `ui_kb_online.py`, `kbcorrelation/{panel,gui_model,gui_backend,tooltips_kb,tooltips_kb_online}.py`, `tests/{test_ui_kb,test_ui_kb_online,test_kb_gui_model,kb_gui_support}.py`, and one-line edits to `tests/test_gui_host_seam.py` and `tests/test_tooltips.py`. It is NOT in the integration branch. If the machine holding it is lost, K4b and K7 UI must be redone (item R-02 first checks `git cat-file -t 72605cd`).
- `origin/claude/instance-b-features` (`6e1e153`): net difference to the integration branch is 8 files: `callgraph/layout.py` (WB2 G6 pure ego layout, minimap, keyboard neighbours), `callgraph/limits.py` (+5 lines), `search/saved.py` (WB1 S7 pure saved searches), `intelligence/tools/runner.py` (+25), `intelligence/tools/capa.py` (+1), `tests/test_callgraph_layout.py`, `tests/test_search_saved.py`, `tests/test_intel_tools_runner_cache.py`. (`git diff --stat HEAD...origin/claude/instance-b-features`.) `git log HEAD..origin/claude/instance-b-features` lists 103 commits; the small tree difference suggests they are mostly squash-merge duplicates (inference, not checked commit by commit). Do not merge the whole branch; take these files.
- Other local `worktree-agent-*` branches not merged into `da7d2db` (44): most are audit docs and research notes; others are older copies of GUI slices (`F4`, `F6a`, `F6b`, `F7`, `F8`, `F9`) whose content is already in the integration branch under other commits (the host files exist in `src/patchtrace/gui/qt/`). UNVERIFIED which of them carry a change the integration branch lacks, except the two above. List them with `git for-each-ref --no-merged=HEAD --format='%(refname:short) | %(subject)' 'refs/heads/worktree-agent-*'`.

## 2. What is DONE

### 2.1 Domain features (Qt-free), by track

Evidence column: files exist at `da7d2db` and the named tests passed in the run of 1.1, unless stated. "CLI" means a verb listed by `python -m patchtrace <verb> --help`.

| Item | Where | Evidence / test |
|---|---|---|
| KB K0 contracts, K0f fixtures | `kbcorrelation/{contracts,limits,ids,errors,ports}.py`, `tests/fixtures/kbcorrelation/`, `tools/generate_kbc_schemas.py` | `tests/test_kbc_{contracts,ids,schemas,fixtures}.py` |
| KB K1 CVRF/CSAF edges, scope, index | `kbcorrelation/sources/`, `products.py`, `alias_catalog.py`, `index.py` | `tests/test_kbc_{cvrf,csaf_bridge,scope,index,products,net_plan}.py`; CLI `kb index` |
| KB K2 store, reducer, recovery | `kbcorrelation/{store,workflow,recovery}.py` | `tests/test_kbc_{store,workflow,recovery}.py` |
| KB K3 pairs, components, context, service, CLI | `kbcorrelation/{components,pairs,plan,context,export,service,wiring,cli,cli_pairs}.py`, `cli_commands/kb.py` | `tests/test_kbc_{components,pairs,context,service,cli,e0_e2e}.py`; CLI `kb search|attach|explain|export|products|components|pairs|import-pair|plan|leads|acquire` |
| KB K4a leads and view model | `kbcorrelation/{leads,cli_leads,view_model}.py` | `tests/test_kbc_{leads,view_model}.py`; `tests/test_kbc_synergy.py` is RED (R-01) |
| KB K5 lineage, resolver | `kbcorrelation/{lineage,resolver}.py`, `acquisition/winbindex.py::parse_rows` | `tests/test_kbc_{lineage,resolver,pairs_index}.py` |
| KB K6 consented CVRF sync | `kbcorrelation/sources/cvrf_fetch.py`, `cli_online.py` | `tests/test_kbc_cvrf_fetch.py` |
| KB K7 non-UI acquire workflow | `kbcorrelation/acquire.py`, `cli_acquire.py`, `acquisition/workflow.py` | `tests/test_acquisition_workflow.py`, `tests/test_kbc_acquire_cli.py` |
| KB K8 adapters (KEV, FAB anchors, WB1 search, unified/secondary engine) | `kbcorrelation/adapters/{engine,kev,search,anchors}.py` (commit `51b3db3`) | `tests/test_kb_adapters_k8.py` passed. The plan's names `tests/test_kbc_adapters.py` and `tests/test_kbc_synergy_full.py` do not exist; K8 is tested under the other name |
| KEV K0 fixtures, K1a core, K1b store | `kev/{contracts,limits,parse,join,view_model,ports,teach,tooltip_entries,store}.py`, `tests/fixtures/kev/`, `docs/schemas/kev/` | `tests/test_kev_{contracts,parse,join,view_model,boundaries,schemas,store}.py` |
| KEV K2 transport, service, CLI | `kev/{transport,service,cli}.py`, `cli_commands/kev.py` | `tests/test_kev_{transport,service,cli}.py`; CLI `kev status|plan|fetch|import|lookup|diff|prune` |
| KEV K4 KB adapter and synergy | `kev/kb_adapter.py` | `tests/test_kev_synergy.py`, `tests/test_kev_kb_integration.py` passed |
| KEV K5 project row, drift, report | `kev/{project_context,report}.py` | `tests/test_kev_{project_context,report}.py` |
| KEV K6 live probe and workflow | `tools/live_kev_probe.py`, `.github/workflows/live-kev.yml` | `tests/test_live_kev_probe.py`; the workflow has NOT been recorded as run (see R-12) |
| CAP-1 parser v2, CAP-2 pair delta, CAP-3 view, CAP-4 cache, CAP-5 CLI, CAP-7 hints | `intelligence/tools/{capa,capa_pairs,capa_view,capa_cache,capa_hints,cli}.py` | `tests/test_capa_{parser_v2,pairs,synergy,view,cache,cli,hints}.py` |
| CAP-8 live test and workflow | `tests/test_live_capa_pairs.py`, `.github/workflows/live-capa.yml` (dispatch only) | written, not run: UNVERIFIED |
| CAP-9 extent attribution | `intelligence/tools/capa_extent.py` | `tests/test_capa_extent.py` passed |
| CAP-11 consented capa download (service only) | `ui_capabilities_setup.py` is a pure service despite the `ui_` name | `tests/test_capa_setup.py` passed |
| T0 tools core (runner, store, pins, provisioning) | `intelligence/tools/{runner,store,pins}.py`, `tools/provision_intel_tools.py`, `tools/intel_tools_pin.json`, `.github/workflows/live-intel-tools.yml` | `tests/test_live_intel_tools.py` (live legs not run here) |
| DIE D1 diec hardening, D2 PE build facts, D3 core, D4 store/CLI/report | `intelligence/tools/{diec,diec_types}.py`, `pe_overview/{rich_header,build_facts,clr_header,debug_entries}.py`, `buildenv/*` | `tests/test_buildenv_*.py`; CLI `build-env show|delta|timeline` |
| DIE D6 overlay (pure only), D7 timeline (pure), D9 value-gate counter | `buildenv/{overlay,timeline}.py`, `tools/buildenv_value_gate.py` | `tests/test_buildenv_{overlay,timeline,value_gate}.py` passed |
| DIE D8 live test + dispatch-only job `live-buildenv` | `tests/test_live_buildenv.py`, job in `.github/workflows/live-intel-tools.yml` | written, not run: UNVERIFIED |
| YRX R0 contracts, R1 synth, R2 engine/worker/runner, R3 candidates, R4 bytes/masks, R5 matrix/store/export/CLI | `rules/*.py`, `docs/schemas/rules/` | `tests/test_rules_{contracts,synth,engine,worker,candidates,masks,synergy,matrix,store,export,cli}.py`; CLI `rules probe|propose|show|decide|test|export|history` |
| YRX R6a pure view model and panel service | `rules/{view,panel_service}.py` | `tests/test_rules_view.py` passed |
| FAB-0 core, FAB-1 store, FAB-2 converters, FAB-3 adoption by PIL, FAB-4 pins, FAB-5 CLI | `fabric/*`, `pilot/origins.py` re-exports the fabric, `cli_commands/fabric.py` | `tests/test_fabric_{contracts,ids,memory,origins,store,convert,adopt,pins,cli,plan,schemas,synergy}.py`; CLI `fabric list|show|resolve|stats`. FAB-3 is built although the FAB plan header still says open |
| WB1 S0-S5 (capability, normalize, query, segment, sources, build, service, rank, expand, fuzzy, CLI) | `search/*.py`, `search/sources/*.py` | `tests/test_search_*.py`; CLI `search` |
| WB1 S6 pure view model | `search/view_model.py` (`panel_state`, `row_view`, `ResultsBuffer`, `detail_sections`, `copy_text`, `suggestion_rows`) | `tests/test_search_view_model.py` |
| WB1 S8 tool/advisory sources, S9 unified IR source, S10 PIL anchor bridge | `search/sources/{tools,advisory,unified}.py`, `search/anchors.py` (commits `7b10533`, `03bc5ee`) | `tests/test_search_{sources_tools,sources_unified,anchors}.py` passed |
| WB2 G0-G4, G7 (evolution), G8 (whole-program sources) | `callgraph/*.py` (no `layout.py`) | `tests/test_callgraph_*.py`; CLI `graph neighbours|delta|leads|paths|export|series` |
| WB2 G5 pure view model | `callgraph/view_model.py` (`changes_view`, `neighbour_rows`, `TreeIndex`, `change_detail`, `node_detail`, `copy_text`) | `tests/test_callgraph_view_model.py` |
| WB3 S0-S7a, S8 run orchestration, S9 goldens and live test | `strings/*.py`, `ui_strings_run.py`, `tests/fixtures/strings/goldens/` | `tests/test_strings_*.py`, `tests/test_ui_strings_run.py`; CLI `strings list|delta|explain|scan|export`. `tests/test_live_strings.py` is in NO workflow (R-12) |
| WBQ S1-S4 modules, `ui_pemeta.py` (S6; whether the S5 integration into `inspect`/`compare` is complete is UNVERIFIED), S7-S8 codetext, S9 codetext UI, S10 symbols decoration | `pe_overview/{resources,version_info,manifest,rich_header,exports_table,api_delta}.py`, `ui_pemeta.py`, `codetext/*`, `ui_codetext.py`, `symbols/*` | `tests/test_pe_*.py`, `tests/test_ui_pemeta.py`, `tests/test_codetext_*.py`, `tests/test_ui_codetext.py`, `tests/test_symbols_decoration.py` |
| GUI framework: registry, anchors, projection, host, docks, table, canvas, codediff, theme, tasks | `src/patchtrace/gui/`, `gui/qt/` | `tests/test_gui_*.py`; `python tools/qt_gate.py --repeat 20` |
| 5 built panels | see 1.2 | `tests/test_ui_{leads,unified,series,evidence}.py`, `tests/test_ui_m3_docks.py`, `tests/test_gui_host_seam.py` |

### 2.2 CI workflows that exist (`.github/workflows/`)

| Workflow | Triggers | What it proves for this area |
|---|---|---|
| `qa-windows.yml` | push to `main` and tags `v*`, every pull request, `workflow_dispatch` (no inputs) | job `qa` (Linux and Windows full suite), `qt-gate` (Linux `--repeat 20`, Windows `--repeat 5`, installs `.[dev,search,rules]`), `linux-package`, `linux-smoke`, `release-gate`, `release`. This is the gate for every panel |
| `live-intel-tools.yml` | dispatch, weekly cron `41 4 * * 2`, pull requests touching tool paths | real capa 9.4.0, FLOSS 3.1.1, DiE 3.21 on synthetic pairs (`tests/test_live_intel_tools.py`); job `live-buildenv` (dispatch only) runs `tests/test_live_buildenv.py` |
| `live-capa.yml` | dispatch only, no inputs | `tests/test_live_capa_pairs.py`; Linux strict, Windows advisory |
| `live-kev.yml` | dispatch (input `sources`: `both` or `mirror`), weekly cron `23 6 * * 3` | `tools/live_kev_probe.py` against CISA and the GitHub mirror; advisory |
| `live-unified.yml`, `unified-live-gates.yml`, `corpus-tier-r.yml`, `pilot-eval.yml` | see the unified-engine handoff | not this area |
| `optional-deps.yml` | see file | installs `.[search,rules]` wheels-only |

No workflow exists for `live_kbc` (KB probes) or for `tests/test_live_strings.py`.

### 2.3 Specs and drafts

- Program E plans (authoritative for the slice tables): `docs/specs/program-e/{KB,KEV,CAP,DIE,YRX,FAB,WB1,WB2,WB3,WBQ,GUI,PIL}-integration-plan.md`. Their status headers lag behind the code (example: the FAB header lists FAB-3 as open, the code shows it built). Trust the code and this page.
- GUI contract: `docs/specs/gui-framework.md` (its status line still says the Qt host is planned; the host exists in `gui/qt/`).
- ChatGPT drafts on `origin/chatgpt/panels-1` (`cfd7cff`): `docs/plans/panels-build-plan.md` and `docs/specs/panels/{build_env,capabilities,graph,guide,kb,kev,rules,search,strings}.md`, 15 sections each (purpose, identity, data contract, layout, states, interactions, navigation, threads, settings, tooltips with exact four-line text, accessibility, budgets, security, test plan, open questions). They are NOT merged and NOT reviewed. Read them with `git show origin/chatgpt/panels-1:docs/specs/panels/<id>.md`. The build plan's section 2 lists binding corrections to the older plans (exact anchor error copy, KEV enum spellings, transaction-boundary wording, KB pair-reason copy); apply them when building. Proposed function names in the drafts (for example `ui_guide.create_panel`, `deferred_view`) are marked UNVERIFIED by the drafts themselves; reconcile with existing code before use. The repo's real convention is `ui_<feature>.py` with a `<Feature>Controller(ControllerBase)` class and `PANEL.tips`, not `create_panel`.
- Created with this page: `docs/specs/panels/related.md` (FAB-6; no draft and no panel spec existed) and `docs/specs/panels/README.md` (index and merge note, so the draft directory on `origin/chatgpt/panels-1` and this one do not collide silently).

## 3. What REMAINS

How to read the cards: "Tier" is the cheapest model that can do it reliably (CLAUDE.md cost rule); opus appears only with a named blocker. "Gate" is the acceptance condition. Every Qt panel item (P-xx) follows the recipe in 3.0 and only lists its differences.

### 3.0 The panel recipe (verified against `pilot/panel.py`, `ui_leads.py`, `gui/qt/docks.py`, `tools/qt_gate.py`, `tests/qt_support.py`)

1. Pure declaration `src/patchtrace/<pkg>/panel.py`. Copy `src/patchtrace/pilot/panel.py`: a `TIPS` dict of `TooltipEntry` (`_tip(what, why, effect, source=..., availability='')`), optional `TEMPLATES`, a `_factory(ctx)` that imports the controller INSIDE its body (`from ..ui_<x> import <X>Controller`), and `PANEL = PanelSpec(id=, title=, factory=_factory, area=, tabify_with=, shortcut=, requires=, claims=, tips=TIPS, tip_templates=TEMPLATES, minimum_em=, anchors_in=frozenset({...}), anchors_out=frozenset({...}))`. `id`, `area`, `tabify_with` and `shortcut` must equal the manifest slot (section 1.2); never edit `panel_manifest.py`. Tooltip ids start with `<id>.`; `<id>.dock` and `<id>.action` are required for a docked panel; each entry needs non-empty What/Why/Effect with no `<` or `>`. There is no `tooltips_<x>.py` and no edit of `tooltips.py`: tips travel in `PANEL.tips` (the GUI plan F5 replaced the old tooltip-module rule; the KB commit `72605cd` keeps `tooltips_kb.py` files but merges them into `PANEL.tips`).
2. Qt module `src/patchtrace/ui_<feature>.py`: `class <X>Controller(ControllerBase)` from `gui/qt/docks.py`. Override only the hooks needed (`project_changed`, `selection_changed`, `busy_changed`, `capabilities_changed`, `theme_changed`, `show_anchor`, `shutdown`). Build widgets from `gui/qt/{table.VirtualTable,state_view,chips.ChipLabel,labels.PlainLabel,SafeTextView}`, `gui/table_spec.{ColumnSpec,TableSpec,prepare_table}`, `gui/tips.{apply_tip,register_tips,escaped_tip}`, `gui/text.sanitize_text`. Work goes through `ctx.tasks` (`TaskRunner.submit(channel, fn, on_result, on_error, on_progress)` or a named lane stored on the controller). Workers never touch widgets, never hold the project database connection (it is thread-bound). The factory builds widgets only: no thread, no disk read, no tool probe. The Qt module is the ONLY module that imports PySide6.
3. Tests, Qt-free first: `tests/test_<pkg>_panel.py` asserting `PANEL` equals the manifest slot and that importing `<pkg>.panel` imports no Qt and no feature (copy `tests/test_ui_leads.py::test_loading_the_declaration_imports_no_qt_and_no_feature`; it needs the package installed because it uses `python -I`). Then `tests/test_ui_<feature>.py` on `tests/qt_support.py` (`main_window`, `settings`, `RecordingAnnouncer`, `slot_timer`, `a11y_audit`, `assert_lazy_model` at 10,000 and 100,000 rows, `top_level_windows`, `join_gui_threads`): one test per state of the panel's state table, hostile text rendered as text, every control has a registry tooltip, late worker result discarded after a project switch, no new top-level window.
4. Two shared test edits that the integrator owns and the KB commit shows are required for every new panel: add the id to `built = {...}` in `tests/test_gui_host_seam.py` (line 115 at `da7d2db`) and to the dock tuple at `tests/test_tooltips.py:218`. Do them in the same commit and list them under "Integrator asks".
5. Local commands (use the plan's file names):
   `PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider tests/test_<pkg>_panel.py tests/test_ui_<feature>.py tests/test_gui_host_seam.py tests/test_tooltips.py`
   `python -m patchtrace panels check` (must print `conflicts: none` and the panel as `built`)
   `python tools/qt_gate.py --repeat 20 tests/test_ui_<feature>.py` (the gate lists each file N times in one pytest session with `PYTHONFAULTHANDLER=1`; `--print-command` shows the command)
   `ruff check src/patchtrace/<pkg> src/patchtrace/ui_<feature>.py tests/test_<...>.py`
6. CI proof: workflow `qa-windows.yml`, jobs `qa` and `qt-gate` on a pull request (no dispatch inputs). Windows runs `--repeat 5`.
7. Docs: append `### [<slice>:<name>]` blocks to `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` (append-only). Manual gates (NVDA/Narrator, 125/150/200 percent DPI, keyboard-only walk, high contrast) stay listed as open; no Linux or offscreen run closes them.
8. Never: edit `ui.py` for a panel, add a second main window, import another feature's Qt controller, show a number as vulnerability confidence, execute a target, fetch without exact-host consent.

### 3.1 Ordered checklist

Order: R-01, R-02, R-03 first (they unblock or protect work); then panels in value order P-01..P-09; then domain tails and CI; then owner gates. Items without a dependency can run in parallel when they touch different files.

---

**R-01 Fix the red K4a synergy test**
- Goal: `tests/test_kbc_synergy.py` green (2 failures at `da7d2db`).
- Cause (read in code): `enrichment/cve.py` lines 175-178 (commit `8093589`, "fix(ACQ-10): imported CVE snapshots are checked for identity and timestamp") reject a snapshot whose `snapshot_id` is not `identity.domain_id('cve-snapshot', 1, {cve_id, normalization_version, response_digests})`. The helper `snapshot_file` in `tests/kbc_k4a_golden.py` writes `snapshot_id: f'{index:064x}'`. `correlate` therefore exits 1 with `PT-ENRICH-INPUT: snapshot 0 snapshot_id does not match its provider digests`.
- Files: `tests/kbc_k4a_golden.py` only (test helper). Do not weaken the production check.
- How: (1) in `snapshot_file`, compute the id with the same rule: import `identity` from `patchtrace.enrichment` and call `identity.domain_id('cve-snapshot', 1, {'cve_id': cve, 'normalization_version': 1, 'response_digests': {'msrc': '0' * 64}})` (the production function `_snapshot_id` is private; do not import it, reproduce the call). (2) Re-run; if `tests/fixtures/kbcorrelation/expected/synergy-leads.json` contains the old ids, regenerate it with the same helper and review the diff. (3) Check `grep -rn "snapshot_id" tests/` for other helpers that fake ids.
- Tests first: the failing tests themselves are the red step (`test_synergy_golden_shape_and_baseline`, `test_each_channel_alone_is_incomplete_and_the_bulletin_wide_cve_list_misleads`).
- Command: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_kbc_synergy.py tests/test_kev_synergy.py tests/test_kb_adapters_k8.py`
- CI: `qa-windows.yml` job `qa`.
- Acceptance: 3 files green; no change under `src/`.
- Size S. Tier haiku (mechanical, one helper). Depends on: nothing.

**R-02 Land the KB dock and online pages (K4b, K7 UI) on the integration branch**
- Goal: panel `kb` becomes `built`; the plan's states KB0-KB17 are testable.
- Files: everything in commit `72605cd` (list in 1.3).
- How: (1) `git cat-file -t 72605cd`; if it says "missing" the work is lost, rebuild from `docs/specs/program-e/KB-integration-plan.md` s8 and `origin/chatgpt/panels-1:docs/specs/panels/kb.md` using recipe 3.0. (2) `git cherry-pick 72605cd` onto a branch from `claude/instance-d-gui`; resolve doc conflicts append-only (`docs/modules.md`, `tasks/todo.md`, `docs/qa.md`, `docs/plans/ledger-D.md`). (3) The commit already edits `tests/test_gui_host_seam.py` and `tests/test_tooltips.py`; check they still apply to the current line numbers (recipe step 4). (4) Review against `panels-1` `kb.md` section 2.4 (complete pair-reason copy) and `panels-build-plan.md` s2.3 (CONTEXT_PENDING keeps the project when attach fails after project creation); fix deviations as a follow-up commit, not in the cherry-pick.
- Tests first: the commit's own `tests/test_ui_kb.py`, `tests/test_ui_kb_online.py`, `tests/test_kb_gui_model.py`. Add `test_kb_panel_spec_equals_manifest_slot`.
- Commands: recipe step 5 with `kb`; plus `python -m pytest -q -p no:cacheprovider tests/test_kbc_*.py tests/test_kb_*.py`.
- CI: `qa-windows.yml` jobs `qa`, `qt-gate`.
- Acceptance: `panels list` shows `kb  built`; 20x gate green on Linux; manual Windows gates (NVDA, DPI, keyboard walk of the six pages) recorded as OPEN.
- Size S-M (integration only). Tier sonnet. Depends on: R-01 (so the suite is clean).

**R-03 Bring over the instance-B files**
- Goal: `callgraph/layout.py` (G6 pure), `search/saved.py` (S7 pure), CAP-4 runner glue.
- Files: the 8 paths in 1.3.
- How: `git checkout origin/claude/instance-b-features -- <the 8 paths>` on a work branch, then run the new tests. Resolve `callgraph/limits.py`, `intelligence/tools/{runner,capa}.py` by hand if the integration branch changed them. Do not merge the branch.
- Tests: `tests/test_callgraph_layout.py`, `tests/test_search_saved.py`, `tests/test_intel_tools_runner_cache.py` plus `tests/test_capa_*.py`, `tests/test_intel_tools_*.py`.
- CI: `qa-windows.yml` job `qa`. Acceptance: the three new test files green with the existing suites unchanged.
- Size S. Tier haiku. Depends on: nothing. Note `search/saved.py` needs the enrichment kind `search-saved`, which already exists in `enrichment/storage.py` `KINDS`.

---

**P-01 KEV panel (K3)** - the most self-contained panel: all pure pieces exist.
- Goal: dock `kev` (right, tab group `kb`, Ctrl+Shift+X): projectless catalog lookup, snapshot context, local import, consented update.
- Files to create: `src/patchtrace/kev/panel.py` (`PANEL`; tips from the existing `kev/tooltip_entries.py` `KEV_TOOLTIPS`, do not duplicate), `src/patchtrace/ui_kev.py` (`KevController`), `tests/test_kev_panel.py`, `tests/test_kev_ui.py`, `tests/test_kev_perf.py`.
- Pure API to call (names verified in `kev/view_model.py`, `kev/service.py`): `KevService.fetch(source, hosts, surface='gui', accept_shrink=False, cancel=..., announce=...)`, `KevService.import_file(path, accept_shrink=False)`, `KevService.read_catalog(path)`, `KevService.diff(from_id=None, to_id=None)`, `plan_for(source)` (from `kev/contracts.py`), `KevColumnProvider(catalog, now).cell(cve)`, `filter_indices(cells, mode)`, `order_indices(cells, mode, indices=None)`, `detail_text(row, meta)`, `changes_lines(delta, new, previous_version)`, `consent_lines(plan)`, `status_line`, `banner_text`, `age_phrase`, `error_text`, `kept_text`, `mirror_older_text`. Use these enum spellings where settings reach the pure functions: filter `all|listed-ransomware|no-catalog-or-invalid` and sort `input|kev-first` (the draft `kev.md` suggests other aliases; `panels-build-plan.md` s2.2 says use these or a non-persisted mapping).
- How: (1) factory builds a lookup box, a table (VirtualTable, columns from the KB plan's KEV column meanings in `kev/view_model.py`), a detail pane, a status line and a banner. (2) Lookup is projectless: do NOT route it through `AnchorRouter` (its `is_stale` is true without a project). (3) Anchors: `anchors_in=frozenset()`, `anchors_out={'cve'}` for "Go to context" (opens the existing Leads handler); disabled without a project (`panels-build-plan.md` s2.1). (4) Fetch and import run on a lane; `import_file` has no cancel parameter and installs a global pointer, so a cancel after commit must say "installed" truthfully (s2.3 of the build plan); serialise installs. (5) Consent text is exactly `consent_lines(plan)`; the user approves the host shown; no environment proxies. (6) States K0-K9 of the KEV plan s8; copy from `kev/view_model.py`, no new banned words (`test_copy_has_no_banned_claims` exists in `tests/test_kev_view_model.py`).
- Tests to write first (KEV plan s9 names): `test_states_k0_to_k9`, `test_hostile_strings_render_as_text`, `test_late_worker_result_is_discarded`, `test_every_kev_control_has_registry_tooltip`, `test_hundred_thousand_cell_gate`; plus `test_kev_panel_spec_equals_manifest_slot`, `test_install_after_cancel_reports_installed`, `test_projectless_lookup_works_without_router`.
- Commands: recipe step 5 with `kev`; `python -m pytest -q -p no:cacheprovider tests/test_kev_*.py`.
- CI: `qa-windows.yml` `qa` + `qt-gate`; the live probe is separate (R-12).
- Acceptance: states K0-K9, 20x gate, `panels list` shows `kev built`. Open after: canonical CISA URL stays unverified until `live-kev.yml` has run on GitHub (the sandbox reaches only the GitHub mirror).
- Size L. Tier sonnet. Depends on: R-02 is advisable (KEV is tabbed with `kb`; the manifest lint only checks that the target slot exists, but a tab group with one built member is untested: UNVERIFIED).

**P-02 Search panel (WB1 S6 Qt + S7 seam)**
- Goal: dock `search` (bottom, Ctrl+Shift+F): paged search over the segment index, coverage line, structured completion, saved searches.
- Files: `src/patchtrace/search/panel.py`, `src/patchtrace/ui_search.py`, `tests/test_search_panel.py`, `tests/test_ui_search.py`, `tests/test_search_perf.py`; `search/saved.py` from R-03. The WB1 plan's `ui.py` seam (S7: `reveal_lines` extraction) is replaced by the host: use `ctx.nav.reveal_lines` / `ctx.nav.select_match` (NavigationPort), do not edit `ui.py`.
- Pure API: `search/service.py::SearchService`, `search/view_model.py` (`panel_state`, `coverage_text`, `row_view`, `ResultsBuffer`, `detail_sections`, `copy_text`, `suggestion_rows`), `search/query.py::parse_query`, `search/capability.py`, `search/paths.py` (cache root is never inside a project), `search/saved.py`.
- How: query box with `QCompleter` fed by `suggestion_rows`; result table is a paged model over `ResultsBuffer` (cursor generation guard: a late page of an old query is dropped); "Rebuild index" runs the build on a lane with cancel; coverage line always visible (WB1 states "unchanged functions: not indexed" until a real golden confirms raw names); RapidFuzz absent => "similar" reports unavailable, never zero. Esc cancels, Enter opens the hit via `reveal_lines`. Anchors: `anchors_in` empty (do not add `function`), `anchors_out` the kinds a hit can carry. Search recents may contain sensitive text: store only the query, never snippets.
- Tests first: `test_ui_search_states` (all `PanelState` ids), `test_stale_page_dropped_after_new_query`, `test_completer_uses_suggestion_rows`, `test_hit_opens_exact_lines`, `test_no_rapidfuzz_reports_unavailable`, `test_hundred_thousand_rows_lazy`.
- Commands: recipe 5 with `search`; `python -m pytest -q -p no:cacheprovider tests/test_search_*.py`.
- CI: `qt-gate` installs `.[dev,search,rules]`, so RapidFuzz is present there.
- Acceptance: states, keyboard (Esc, completer), 20x, budgets of the WB1 plan s10 (first paint 200 ms class; check the plan's numbers, they are not repeated here).
- Size L. Tier sonnet. Depends on: R-03.

**P-03 Call graph panel (WB2 G5 Qt, G6 canvas, G7 tab, G9 glue)**
- Goal: dock `graph` (bottom, Ctrl+Shift+G) with Changes / Neighbours / Tree tabs, a bounded diagram, and the series tab.
- Files: `callgraph/panel.py`, `ui_calls.py` (tables and tabs), `ui_calls_canvas.py` (diagram, lazy import), `ui_calls_evolution.py`, tests `tests/test_callgraph_panel.py`, `tests/test_ui_calls.py`. Pure layout from R-03. The tooltip table travels in `PANEL.tips` (not a local `ui_calls_tips.py`).
- Pure API: `callgraph/view_model.py` (`changes_view`, `neighbour_rows`, `TreeIndex`, `change_detail`, `node_detail`, `copy_text`), `callgraph/{snapshot,query,delta,leads,evolution}.py`, `gui/qt/canvas.py` (`GraphCanvas`, caps 500/2,000 nodes/edges default, 2,000/8,000 maximum), `callgraph/layout.py`.
- How: tables first (Changes then Neighbours then Tree), diagram after table parity; the domain query limits apply before the canvas caps; the diagram setting is off by default until Windows DPI acceptance (WB2 Q4); text alternative always present. Go to code uses `ctx.nav`. `anchors_in` empty; do not add `function`.
- Tests first: states E0-E12 (WB2 plan s8), `test_hostile_function_names_render_as_text`, perf gates 10k/100k, `test_diagram_text_parity`, `test_minimap_sync`, `test_no_extra_top_level_window`.
- Commands: recipe 5 with `graph`; `python -m pytest -q -p no:cacheprovider tests/test_callgraph_*.py`.
- Acceptance: as the WB2 plan s9 G5/G6 gates; G9's `pyproject.toml`/`.gitattributes` edits are integrator items (NetworkX stays a dev oracle only). Screen-reader acceptance of the diagram is a manual Windows gate and stays OPEN.
- Size L (G5) + M (G6) + M (G7). Tier sonnet; opus only after a Qt lifetime abort or accessibility defect that the 20x gate shows (WB2 plan). Depends on: R-03 (layout), P-04 not required.

**P-04 Strings panel (WB3 S7b)**
- Goal: dock `strings` (bottom, tab group `graph`, Ctrl+Shift+T).
- Files: `strings/panel.py`, `ui_strings.py`, `tests/test_strings_panel.py`, `tests/test_ui_strings.py`. `ui_strings_run.py` and `strings/run_service.py` already exist (run dialog); embed them, do not rewrite.
- Pure API: `strings/view_model.py` (`build_rows`, `apply_filter`, `differing`, `delta_state`, `state_text`, `copy_escaped`, `reselect`), `strings/copy.py`, `strings/tooltip_entries.py`, `strings/table.py`, `strings/export.py`.
- How: table prepared by `build_rows` (shared table cap 100,000 rows; WB3's 200,000 source rows need an explicit filter, `panels-build-plan.md` s2 "Tables"); filters from `StringsFilter`; copy is exact-or-escaped, never decoded silently; privacy: strings may be secrets, redact per the plan. Source basis (Built-in scan vs FLOSS) always labelled; never call the built-in scan "FLOSS".
- Tests first: all states, `test_copy_is_escaped_not_raw`, `test_filter_changes_rows_not_store`, 100k gate, `test_run_dialog_records_consent_hash` (reuse `tests/test_ui_strings_run.py` fake runner).
- Acceptance: WB3 plan s9 S7b gates. Size L. Tier sonnet. Depends on: nothing hard (prefer after P-03 so the `graph` tab group exists).

**P-05 Capabilities panel (CAP-6a, CAP-6b)**
- Goal: dock `capabilities` (bottom, tab group `graph`, Ctrl+Shift+A): Changes tab from stored data (6a), Setup and run tab (6b).
- Files: `intelligence/tools/capa_panel.py` (the manifest module is `patchtrace.intelligence.tools.capa_panel`, NOT `capabilities/panel.py`), `ui_capabilities.py`, `tests/test_capabilities_panel.py`, `tests/test_capabilities_ui.py`, `tests/test_capabilities_run.py`; `runtime_discovery.py` gains `capa_executables` for 6b.
- Pure API: `capa_view.py` (view model; read `cell_text`, filters, grouping), `capa_pairs.py::groups_from_project`, `capa_hints.py`, `capa_cache.py`, `capa_extent.py`, `intelligence/tools/runner.py`, `ui_capabilities_setup.py` (consented download service, CAP-11; wire its dialog in 6b), CLI `intel-tools pairs`.
- How: 6a reads stored `tool-evidence` rows only (no tool run). Two-level capability tree with stable group keys. Anchors emitted: rule/import/string with ORIGINAL identity; a capa rule identity is not a YARA rule (`not found`, no coercion). 6b: the run goes through the T0 runner with the exact-input preview and the memory cap; capa emulation disclosure line in the preview (CAP Q6 default: no consent gate, disclosure only; owner decision O-3). Setup tab shows the pinned URL, size and SHA-256 from `tools/intel_tools_pin.json`; download only through `ConsentToken`.
- Tests first: states C0-C13 (CAP plan s8), `test_capa_panel_spec_equals_manifest_slot`, `test_run_requires_exact_preview`, `test_no_widget_in_worker`, `test_unsupported_rule_identity_is_not_found`, 100k data-cost gate.
- Acceptance: CAP plan s9 CAP-6a/6b gates; live capa on Windows stays BLOCKED/advisory.
- Size L + M. Tier sonnet. Depends on: nothing hard. Same builder for 6a and 6b (one file, sequential).

**P-06 Build environment card (DIE D5, D6 wiring, D7 strip)**
- Goal: dock `build_env` (right, tab group `evidence`, Ctrl+Shift+B) as one card plus a pre-flight notice contribution (one `PANEL`, not two).
- Files: `buildenv/panel.py`, `ui_build_env.py`, `tests/test_buildenv_panel.py`, `tests/test_ui_build_env.py`.
- Pure API: `buildenv/view_model.py` (`build_view`, `banner_views`, `fact_rows`, `provenance_block`, `technical_lines`, `reading_view`), `buildenv/{copy,preflight,store,report}.py`; CLI `build-env`.
- How: card shows facts and the delta with explicit older/newer; diec is optional and never auto-runs (DIE Q4 default: `buildenv/auto_diec` off until gate G-DIE-1); a run needs the exact tool path and the T0 runner. D6 wiring: `unified/read_model.py` and `ui_unified.py` do not import `buildenv` yet (`grep -rn buildenv src/patchtrace/unified src/patchtrace/ui_unified.py` is empty); the overlay is `buildenv/overlay.py`; wire it only together with unified engine slice S4 (see the unified handoff). D7: strip goes in the `series` dock via `nway/pair_access.py`, `nway/view_model.py`, `ui_series.py` (recorded exception in the DIE plan).
- Tests first: states B0-B9, tooltip audit, thread tests, `test_card_without_tool_still_shows_pe_facts`, overlay 100k rows.
- Acceptance: DIE plan s9 D5 gate; value gate G-DIE-1 is a separate item (R-10).
- Size L (D5) + M (D6) + M (D7). Tier sonnet. Depends on: none for D5; D6 depends on unified S4.

**P-07 Rules panel (YRX R6b)**
- Goal: dock `rules` (right, Ctrl+Shift+R): candidates, decide/version, test grid, saved rules, local export.
- Files: `rules/panel.py`, `ui_rules.py`, `tests/test_rules_panel.py`, `tests/test_rules_ui.py`.
- Pure API: `rules/view.py` (`candidate_row`, `feature_rows`, `check_rows`, `GridView`, `saved_rows`, `status`), `rules/panel_service.py` (`PanelService`, `Session`), `rules/{matrix,store,export,runner}.py`; CLI `rules`.
- How: read-only list and grid first (YRX fallback), then decide/version, then test, then export. Accept and export are SEPARATE actions; hard gates cannot be bypassed; export preview is exact and local, names off by default, secret gate on; no silent git writes. The worker runs out of process (`runner.worker_argv()`); the parent never imports `yara_x`.
- Tests first: states R0-R8, `test_accept_and_export_are_separate_actions`, `test_parent_never_imports_yara_x` (exists for the core; add it for `ui_rules`), `test_export_preview_equals_file`, hostile text.
- Acceptance: YRX plan s9 R6b gate. Size L. Tier sonnet. Depends on: R-11 (frozen worker) only for the packaged build, not for tests.

**P-08 Related-evidence panel (FAB-6)**
- Goal: dock `related`. There is no manifest slot; the integrator must add one (`ManifestEntry('related', 'patchtrace.fabric.panel', _related, 'bottom', 'leads', 'Ctrl+Shift+J')`) - a one-line integrator edit that must precede the build, otherwise `panels check` reports an unknown panel. `panels check` arbitrates the shortcut.
- Files: `fabric/panel.py`, `ui_related.py`, `AnchorRef.from_fabric` in `gui/anchors.py` (does not exist: `grep -rn from_fabric src` is empty), tests. Full contract: `docs/specs/panels/related.md`.
- Size M. Tier sonnet. Depends on: P-01 not needed; needs the manifest edit.

**P-09 Guide stub**
- Goal: reserved slot `guide` shows "Contextual guide is deferred in this build. Use the existing help and control tooltips." (`origin/chatgpt/panels-1:docs/specs/panels/guide.md`).
- Files: `src/patchtrace/guide/{__init__,panel,view_model}.py` (package does not exist), `ui_guide.py`, tests. `view_model.deferred_view()` returns a frozen static view; `show_anchor` returns `NavResult.blocked('Guide', 'contextual lessons are deferred')`.
- Size S. Tier haiku. Depends on: nothing. Do it last; it is optional for the alpha.

---

**R-04 KB K9: performance, live probes, frozen smoke**
- Goal: probe pack L1-L6 of the KB plan s10.2 exists as code and as an advisory workflow.
- Files to create: `tests/test_kbc_perf.py`, `tools/live_kbc_probe.py`, `.github/workflows/live-kbc.yml`; edits (integrator): `pyproject.toml` marker `live_kbc` (today only `live_bindiff` is registered), `tools/frozen_smoke.py` (import `kbcorrelation`; it imports none of the new packages today: `grep -nE "kbcorrelation|kev|rules" tools/frozen_smoke.py` is empty), `.gitattributes` LF lines for `tests/fixtures/kbcorrelation/**` and `docs/schemas/kbcorrelation/**`.
- How: copy `tools/live_kev_probe.py` and `.github/workflows/live-kev.yml` (status files per `tools/check_live_status.py`; BLOCKED/FAILED/PASSED; advisory; dispatch + weekly cron; never a required check). Probes: L1 pin the MSRC CVRF dialect, sizes, `Description.Value`, `FixedBuild`; L2 parse real Winbindex newest builds; L3 symbol-server pair through the existing path (owner machine); L4 CSAF provider metadata; L5 and L6 are manual/owner.
- Tests first: `test_probe_classifies_blocked_vs_failed`, `test_probe_detects_schema_drift` (mirror the KEV tests), perf test with the plan's budgets (read them in KB plan s8/s10, not repeated here).
- Commands: `python -m pytest -q -p no:cacheprovider tests/test_kbc_perf.py tests/test_live_kbc_probe.py`; CI `gh workflow run live-kbc.yml` after merge (no inputs unless you add one).
- Acceptance: probes recorded PASS/FAIL/BLOCKED honestly; BLOCKED is not done. Size M. Tier sonnet (+haiku for lint). Depends on: R-02.

**R-05 KB E1 follow-ups**
- Goal: finish what the todo block `[K7:acquire-workflow]` lists: refactor `AcquisitionDialog` onto `acquisition/workflow.py` AFTER E1 merges with `tests/test_ui_acquisition.py` untouched; `ContextBundle` JSON schema; CSAF applicability report in the context; `kb attach` to a foreign project; run id in the stale fingerprint; A-6 (`persistence.py` `backup()` also copies `kb` and `intelligence`; check whether done: `grep -n "kb" src/patchtrace/persistence.py`); A-10 `intelligence/anchors.py` `text_anchors()`.
- How: each as its own small PR with a failing test first. Size M total. Tier sonnet. Depends on: R-02.

**R-06 CAP leftovers**
- CAP-10 BinExport2 backend for capa (experimental): `grep -n binexport src/patchtrace/intelligence/tools/capa.py` is empty, so not built. Add the backend token, live parity with vivisect on the synthetic pair. Needs live validation (C3). Size M, sonnet, deferred.
- CAP-6 depends on nothing here. Series hop counts (W5) after CAP-8 ran.
- CAP-8 and DIE-D8 live jobs: dispatch them and record results (R-12).

**R-07 DIE leftovers**
- D10 `buildenv/support_callees.py` (explain F10 edit groups by compiler-support callees): not built; names must be measured on Tier R builds first (needs the corpus). Size S, sonnet, last.
- D9 run: `tools/buildenv_value_gate.py` exists; running it needs the Tier R M4 pairs (label-training/corpus handoff).

**R-08 YRX leftovers**
- R7 integrator packaging: `tools/pyinstaller_hooks/hook-patchtrace.rules.engine.py` does not exist (`ls tools/pyinstaller_hooks`); the YRX plan s10 gives its content (`hiddenimports = ['yara_x', 'iced_x86', 'json', 'datetime', 'io']`, `datas = copy_metadata('yara-x') + copy_metadata('iced-x86')`). Frozen worker: `rules/runner.py::worker_argv()` already returns `[sys.executable, 'rules', '_rules-worker']` when frozen and `rules/cli.py` defines `WORKER_VERB = '_rules-worker'`; add the check to `tools/frozen_smoke.py` (rules probe versions equal pins; worker scan of a built-in sample exits 0 with one JSON document). Windows frozen run is the proof (UNVERIFIED until a Windows build runs it). `pyproject.toml` has `rules = ["yara-x==1.21.0", "iced-x86==1.21.0"]` as an optional extra; the plan's default is base dependencies (owner decision O-5).
- R8 benchmark `tools/rules/stability.py` and `tests/test_rules_tier_r.py` (BLOCKED, never skipped, without tools): not built (`tools/rules/` does not exist). Needs Tier R builds and clang. Size M, sonnet. Depends on: label-training corpus.

**R-09 FAB leftovers**
- FAB-6 is P-08. FAB plan open question 3: `capa` keeps PIL's single origin tag until CAP-7's lineage is wired; change it in one data PR (`fabric/origins.py`) with its digest test. Size S, haiku.

**R-10 WB leftovers**
- WB1: S7 `KINDS` line is already present (`search-saved`); S7 `ui.py` seam is replaced by the host; remaining is `search/saved.py` wiring in P-02.
- WB2: G9 glue is mostly done through `cli_commands/graph.py`; remaining integrator edits are `.gitattributes` for `docs/schemas/callgraph` and frozen smoke import (check with `grep -n callgraph tools/frozen_smoke.py`).
- WB3: S10 (`floss-results/2`) and S11 (series lifelines) optional; S9 CI job is R-12.
- WBQ (listed because it feeds panels): S9b `codetext/align.py` (needs owner decision U-WBQ-1), S11 `symbols/{backend,worker,cache}.py` + hook (optional), S12 `symbols/backends_win.py` (optional), S13 `cli_pe_meta.py` + `cli_commands/pe_meta.py` + `tests/test_wbq_synergy.py` (not built: `cli_pe_meta.py` absent). Size S each, sonnet.

**R-11 Frozen and packaging checks for the new packages**
- Goal: the Windows exe contains and starts every panel and verb.
- How: PyInstaller sees imports inside function bodies, so lazy `_factory` imports are collected; `hook-patchtrace.cli_commands.py` collects verb modules. What is NOT covered: the hidden rules worker (R-08), `iced_x86`/`yara_x` metadata, `rapidfuzz` (extra `search`; `optional-deps.yml` installs it), any package imported only by name through `importlib`. For each new `ui_*.py` add a name to the frozen smoke import list. Proof: `qa-windows.yml` job `qa` Windows leg builds and runs `tools/frozen_smoke.py` (read the job to confirm which leg builds the exe; UNVERIFIED here).
- Size M. Tier sonnet. Depends on: P-xx as they land.

**R-12 CI additions and live runs**
- Add `tests/test_live_strings.py` to a workflow: it is in none (`grep -rn test_live_strings .github` is empty). Cheapest: add a step to the Linux leg of `live-intel-tools.yml` running `python -m pytest -rA tests/test_live_strings.py` after provisioning (the FLOSS pin is already provisioned there via `PATCHTRACE_FLOSS`). Size S, haiku.
- Dispatch and record, then write the result in `docs/qa.md`: `live-kev.yml` (inputs: `sources=both`), `live-capa.yml`, `live-intel-tools.yml` (job `live-buildenv` runs only on dispatch). Command: `gh workflow run <file> --ref claude/instance-d-gui` (add `-f sources=mirror` for KEV). Which branch the workflow files must exist on: GitHub runs a dispatch from the ref you pass; the file must exist on that ref. Results: BLOCKED is reported separately from PASSED.
- Owner gate: the canonical KEV URL becomes the GUI default only after `live-kev.yml` passes on GitHub.

**R-13 Windows manual acceptance (owner)**
- NVDA/Narrator output, Accessibility Insights roles, 125/150/200 percent DPI, high contrast, reduced motion, dock layout recovery, EDR/Defender behaviour with `yara_x.pyd`, DiE Windows trust API calls, real servicing pairs. Instructions: `docs/windows.md`, `docs/runbooks/tier-w-local-run.md`, `docs/research/qt-accessibility-windows.md`. Nothing in this page can close them.

## 4. Decisions only the owner can make (with a recommendation)

| # | Decision | Recommendation |
|---|---|---|
| O-1 | Adopt the ChatGPT panel specs (`origin/chatgpt/panels-1`) as in-repo specs? | Yes after a human skim of each file's section 5 (states) and section 10 (tooltips), merging them as `docs/specs/panels/*.md` with the build plan's section 2 corrections applied. Until then builders read them via `git show` and treat them as input, not law |
| O-2 | KEV default source in the GUI | Mirror pre-selected until `live-kev.yml` passes on GitHub, then `cisa-site` (KEV plan Q1) |
| O-3 | CAP: consent gate before capa runs (vivisect emulates instructions)? In-app capa download (CAP-11 service exists)? | Disclosure line only, no gate (CAP Q6); ship the download dialog behind the exact-plan consent (CAP Q3 said not v1; the service is built and verified, so enabling it is cheap but is a policy change: decide) |
| O-4 | DiE: `buildenv/auto_diec` | Off until G-DIE-1 passes (DIE Q4) |
| O-5 | `yara-x` and `iced-x86` as base dependencies or optional extra `rules` | Base dependencies (the feature is part of the standalone alpha; YRX default). Today they are an extra: UNVERIFIED that the Windows release build installs it |
| O-6 | Shortcut and tab group for `related` | Ctrl+Shift+J tabbed with `leads` (FAB Q6) |
| O-7 | Graph diagram on by default? | Off until a Windows DPI and screen-reader pass (WB2 Q4) |
| O-8 | Search recents persistence | Query text only, local, with an opt-out later |
| O-9 | Ship real MSRC captures as fixtures (KB Q5) | No; hash-only provenance until the terms are read |
| O-10 | Curated title-to-file catalog (KB Q6) | None shipped until reviewed, cited data exists |
| O-11 | WBQ `align` (U-WBQ-1) | Omit for the alpha |
| O-12 | Split the work order: Windows alpha first | Do R-01..R-03, then P-02 (search), P-01 (KEV) and P-07 (rules) for usefulness, then P-03..P-06. The alpha can ship with `kb`, existing panels and the CLI for the rest, because every feature has a CLI verb |

## 5. Pitfalls and lessons

P-01 Shared files are frozen for feature builders (`ui.py`, `tooltips.py`, `panel_manifest.py`, `cli.py`, `tools/frozen_smoke.py`, `pyproject.toml`, `enrichment/storage.py` `KINDS`, `.gitattributes`, `tools/build_*.py`). Each new panel still forces two integrator test edits (recipe step 4). The KB commit did both; forgetting them leaves `test_gui_host_seam` or `test_tooltips` red.
P-02 The `tabify` lint rule (`docs/specs/gui-framework.md` 1.8) checks that the target exists in the manifest, is not itself tabbed and shares the area. Whether the host copes with a tab group whose partner is not built yet is UNVERIFIED; prefer building `kb` before `kev` and `graph` before `strings`/`capabilities`.
P-03 Old plans disagree with the manifest (CAP/WB3 "right, evidence"; DIE `area='none'`; KEV tab group `evidence`). The manifest wins.
P-04 Tooltips: the worker brief says `tooltips.py` is frozen; the framework answers with `PANEL.tips`. Do not register tips at import time or edit `REGISTRY`.
P-05 Threads: a project connection is thread-bound; read the project on the GUI thread, hand workers immutable snapshots; free Qt objects only on the GUI thread (a fix `abf0219` "free Qt objects on the GUI thread only in TaskRunner and Lane (T15)" exists on a local worker branch; whether the integration branch already has it is UNVERIFIED, check `gui/qt/tasks.py`). Run the 20x gate; teardown aborts only show up when files repeat in one session.
P-06 Never create a lane with a name used before; store lanes on the controller (`TaskRunner.lane(name, init, close=None)` allows a name once per runner).
P-07 Anchors: `AnchorRouter` has one handler per kind; Leads owns `cve` and `match`. KEV must not register `cve`. `panels check` currently warns: "leads emits advisory_phrase, build_fact, capability, import, rule, string anchors that no built panel handles". It goes away as P-02..P-07 land. Use the exact `NavResult` copy from `gui/anchors.py` (build plan s2.1), not the draft's examples.
P-08 Cancel semantics: `KevService.import_file` has no cancel and commits a global pointer; never print "nothing changed" after a commit. Same for export (file saved, ExportRecord failed) and KB project creation followed by attach failure (`CONTEXT_PENDING`).
P-09 Windows: the Windows full suite takes 20+ minutes; use short `parametrize(ids=[...])`, `>=` on timings, LF fixtures, `os.replace` retries, close SQLite handles before deleting. Instance B raised the QA job timeout to 60 minutes (commit `e3216cb`, on that branch; check `qa-windows.yml` `timeout-minutes` on yours).
P-10 `python -I` subprocess tests need `pip install -e .`; `PYTHONPATH` is ignored. Seen here as a false red.
P-11 Frozen executables cannot run `python -m module` workers. The pattern is a hidden CLI verb (`unified _worker`, `rules _rules-worker`, `_binexport-worker`). Any new worker follows it and gets a frozen smoke check. PyInstaller `collect_submodules` returns `[]` silently when it resolves another tree; the repo hooks assert the files they expect.
P-12 Test fixtures that bypass a production check go red when the check is hardened (R-01). When you harden a validator, grep `tests/` for helpers that build the input by hand.
P-13 Status headers in plans and `docs/specs/REGISTRY.md` lag; the `docs/specs/program-e/OUTSTANDING-specs-ledger.md` lists known stale rows. Verify with `ls`, `grep` and `panels list` before trusting a header.
P-14 Local `worktree-agent-*` branches are the only copy of some work (the KB dock). Push or cherry-pick finished work; do not rely on the sandbox disk.
P-15 The sandbox reached only `pypi.org` and `raw.githubusercontent.com` (per KB/KEV/WB plans). Every live fact (KEV canonical URL, MSRC CVRF dialect, Winbindex shape on a real record, capa/FLOSS/diec on Windows) is UNVERIFIED until a CI or owner run records it.
P-16 Do not show a number as vulnerability confidence; KEV never reorders Leads; unknown is not a negative vote; shared-origin evidence counts once. These are acceptance tests in the synergy suites; keep them green when wiring panels.

## 6. Verification checklist before calling the area finished

1. `git fetch origin && git merge --ff-only claude/instance-d-gui` is clean; no local-only commit holds product code (`git branch --no-merged HEAD`, section 1.3).
2. `PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m patchtrace panels list` shows 13 or 14 built (14 only if the stub `guide` is built; `related` is extra) and `panels check` prints `conflicts: none` with no unhandled-anchor warning for a kind that a built panel emits.
3. Full suite green on Linux and Windows through `qa-windows.yml` on the pull request: jobs `qa` (both OSes), `qt-gate` (Linux 20x, Windows 5x), `linux-package`, `linux-smoke`.
4. Each panel has: pure `panel.py` test, UI state tests, tooltip audit, `a11y_audit` clean, 100k-row lazy gate where it has a table, hostile-text test, late-result-discard test, no new top-level window.
5. Each CLI verb of the area still answers `--help` and returns the `enrichment-cli/1` envelope (exit codes 0/2/3/4/5): `kb`, `kev`, `search`, `graph`, `strings`, `build-env`, `rules`, `fabric`, `pilot`, `intel-tools`.
6. Frozen exe: `tools/frozen_smoke.py` imports every new package and runs the rules worker; the Windows leg is green.
7. Live evidence recorded in `docs/qa.md` as PASSED / FAILED / BLOCKED, separately from automated tests: `live-kev.yml`, `live-capa.yml`, `live-intel-tools.yml` (incl. `live-buildenv`), `tests/test_live_strings.py`, `live-kbc.yml`.
8. Manual Windows gates (R-13) are listed as open or closed by the owner, never inferred.
9. `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` have one block per slice; plan status headers updated; stale rows from section 5 P-13 fixed or noted.
10. No Microsoft binary, PDB or Winbindex-derived label committed; no GPL/AGPL code copied; no network call without per-operation consent.
