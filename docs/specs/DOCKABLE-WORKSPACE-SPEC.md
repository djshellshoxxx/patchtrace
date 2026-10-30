# PatchTrace — dockable, modular workspace

**Status: PROPOSED / SPECIFICATION ONLY — NOT IMPLEMENTED.**

Repository: `djshellshoxxx/patchtrace`. Verified `main` baseline: **`a04f5a299a8d4afef023261e52e08d14678cf1e7`**, checked through GitHub's branch endpoint on 2026-10-30 UTC. All source observations below refer to that exact commit, not an unverified checkout. Intended repository location: `docs/specs/DOCKABLE-WORKSPACE-SPEC.md`. No spec number is allocated here; the integrator must register an available identifier before implementation.

## 1. User outcome and scope

The user wants to pull functional sections around the screen and choose which sections are visible because the current workspace displays too much information at once. The outcome is **the same PatchTrace functionality, with a simpler starting layout and independently movable, dockable, tabbed, floating and hideable work areas**.

This is a presentation and lifecycle refactor, not a new analysis engine, provider, security policy, project format or reduced-feature edition. Hiding a section never disables its feature. Presets change arrangement, not capabilities, permissions, analysis settings, selected engine, evidence, filters or project data.

“Section” means a coherent task surface, not every button or label. Filters stay with their result list; source/provenance and stale-state warnings stay with the data they qualify. The core sections enumerated in §3 must move independently. Existing feature docks remain independent modules. Ordinary transient workflows such as New Project, file choosers, Setup, correction, exact context/Send preview, export preview and consent remain dialogs; this spec does not indiscriminately turn dialogs into permanent docks.

**Completion boundary:** all enumerated core sections and all currently registered feature panels use the same workspace controls; layout recovery, preservation and acceptance gates pass. An implementation that only adds presets to the existing fixed three-column workspace is incomplete.

## 2. Actual baseline: reuse, do not rebuild

### 2.1 Shipped structure

`src/patchtrace/ui.py:MainWindow` is a PySide6 `QMainWindow`. `_build_workspace()` currently creates a fixed horizontal splitter containing `_build_navigator()`, `_build_code()` and `_build_findings()`, plus diagnostics in a vertical splitter. It starts at 1440×900, with a nominal 960×640 minimum. The Project and analysis toolbar is currently non-movable.

The existing framework already supplies:

| Existing seam | Verified role | Required treatment |
|---|---|---|
| `gui/registry.py`, `panel_manifest.py` | Pure `PanelSpec`, 14 reserved slots, stable IDs, lint, four ports | Extend; do not create a competing registry |
| `gui/qt/docks.py` | `PanelDock(QDockWidget)`, close/move/float flags, `<id>.dock`, default placement/tabification | Reuse for extracted sections |
| `gui/qt/host.py` | Shell creation before restore, lazy controllers, availability, anchor navigation, theme, tasks, lifecycle | Keep one owning host |
| `gui/qt/commands.py`, `palette.py` | View toggles; Show/Hide, Focus, Float/Dock, Move; F6; Ctrl+Shift+P | Extend with presets, split/tab commands, recovery |
| `gui/qt/layout.py` | `layout/schema=1`, `layout/state`, SHA-256, 64-KiB state limit, fallback/reset | Evolve compatibly; retain bounds and validation |
| `ui.py:restore_preferences/closeEvent` | `desktop/geometry`, workspace/vertical/code splitter settings, sync/font; main-screen clamp | Migrate obsolete outer splitters; extend floating-window recovery |
| `gui/qt/tasks.py` | GUI-thread delivery, task cancellation/shutdown, channels/lanes | Preserve job ownership independent of visibility |
| `gui/qt/state_view.py`, `announce.py`, `metrics.py`, `theme.py` | State explanation, notices, accessibility, font-based metrics/themes | Apply to new surfaces |

The manifest registers 13 implemented feature declarations and a reserved, absent Guide module. Engine evidence is eager; the others are generally lazy. Files and Series are already hosted docks: do not redo their earlier dialog/window conversion. Related evidence has a declaration in `fabric/panel.py` but is **not in the manifest**; its existence is not proof of a reachable shipped panel. Do not silently activate it or advertise it in presets as part of this change.

Historical prose is stale: `docs/specs/gui-framework.md` calls the Qt host and panel implementations unbuilt, while the baseline contains them. `docs/specs/non-goals.md` also retains older Series/theme statements. Source and current tests govern the baseline; reconcile these documents narrowly during implementation instead of using stale prose to remove working functionality.

### 2.2 Native Qt decision

Use the existing single `QMainWindow` and `QDockWidget` framework. Enable nested and tabbed docking, use native splitting/tabification and state restoration. Do not add a web layout engine, third-party docking dependency, new independent application windows, or a custom drag/drop framework. Owned floating docks are still modules of the same application/session, not separate project windows. Qt provides these native primitives. [QMainWindow](https://doc.qt.io/qt-6/qmainwindow.html), [QDockWidget](https://doc.qt.io/qt-6/qdockwidget.html).

The former central workspace must not remain an immovable code island: code surfaces themselves are docks. Replace the fixed central splitter with a minimal, collapsible welcome/recovery surface; when working docks exist it must not reserve a large blank rectangle. Keep the compact project/run identity and global notices in the main-window chrome, outside the dock graph. Prove native dock-only sizing on the supported Qt build in the first slice; if central-widget constraints require an adapter, constrain it to placement/ownership, not a second docking system.

## 3. Module inventory and stable identities

### 3.1 Extract the overloaded core

These are proposed IDs, checked against the current manifest. All use `<id>.dock`, `<id>.action`, scoped settings and semantic tooltip prefixes. Register them centrally; titles can change, IDs cannot. Use thin adapters during extraction so existing callbacks and widget references keep working until ports are migrated.

| New ID / title | Existing source surface | Contents and boundary |
|---|---|---|
| `matches` / Function matches | `ui.py:_build_navigator` | Search, category/review/order filters, profile/count, manual/findings filters, navigator, match-review status and Correct match action |
| `change_signals` / Change signals | Same builder | Selected match's `signal_list`; context label and empty state; not a duplicate ranking engine |
| `compare_controls` / Comparison controls | `_build_code` | Mode, raw scope/page/offset, sync scroll, previous/next difference, hunk selector and match identity |
| `code_older` / Older artifact | `_build_code` | Older read-only view, side identity/provenance and Copy |
| `code_newer` / Newer artifact | `_build_code` | Newer read-only view, side identity/provenance and Copy |
| `findings` / Findings | `_build_findings` | Search/review/staleness filters and findings list |
| `finding_detail` / Finding evidence | Same builder | Finding detail, evidence references, bookmark action and interpretation-response inspection action |
| `finding_review` / Finding review | Same builder | Finding review status, analyst conclusion and Save finding review |
| `analyst_notes` / Analyst notes | Same builder | Note target, note text, Save note; explicit target identity |
| `diagnostics` / Job details and log | `_build_workspace` | Existing job detail/progress/log; retain 2,000-block log bound |
| `engine_controls` / Engine controls | `ui_evidence.py:EvidencePanel._build_engines_tab` | Engine selection/status, parallelism, timeout, Run/Cancel/Probe/Import, BinDiff setup section, preview/status/log. One controller with `evidence`, not a second runner |
| `unified_detail` / Unified row details | `ui_unified.py:UnifiedPanel` lower region | Row detail, Go to match, Correct, Copy provenance, Explain |
| `unified_code` / Unified code comparison | `ui_unified.py:UnifiedCodeView` | Existing paired unified code view, mode/hunk controls and provenance; remains distinct from baseline Ghidriff code |

The engine-controls extraction boundary is the existing `EvidencePanel._build_engines_tab()` and its `tabs.addTab(page, 'Engines')` surface; preserve its controller and setup ownership.

There are 27 reserved slots after these 13 additions, including the existing Guide reservation; this stays within the registry's existing 32-panel limit. Do not raise that limit merely to add a dock for every control. Each section can be shown alone; showing dependent details constructs its shared controller once even when its main table is hidden. Host lifecycle delivery must be deduplicated for shared controllers.

### 3.2 Preserve all registered feature surfaces

| Existing ID / display title | Main implementation | Contract retained |
|---|---|---|
| `evidence` / Engine evidence | `secondary/evidence_panel.py`, `ui_evidence.py` | Evidence table/filter/detail, engine provenance; Engines surface moves to `engine_controls` with an “Open Engine controls” action |
| `unified` / Unified | `unified/panel.py`, `ui_unified.py` | Run/enable/cancel/retry, filters, table, summary and notices; links reveal new row-detail/code modules |
| `search` / Search | `search/{panel,qt_panel}.py` | Queries, scope/index controls, results, detail and navigation |
| `graph` / Calls | `callgraph/{panel,panel_qt}.py` | Existing calls inspection/table/diagram functionality |
| `strings` / Strings | `strings/{panel,qt_panel}.py` | Current scans, filters, results/detail and function/hex navigation |
| `capabilities` / Capabilities | `intelligence/tools/{capa_panel,capa_qt}.py` | Stored capabilities and existing explicit run workflow |
| `build_env` / Build environment | `buildenv/{panel,qt_panel}.py` | Read/status, facts and detail |
| `rules` / Detection rules | `rules/{panel,qt_panel}.py` | Existing rule workflow and results |
| `kb` / KB and CVE | `kbcorrelation/{panel,panel_qt}.py` | Existing KB/CVE leads and navigation; do not conflate with unrelated unregistered workflows |
| `kev` / Exploitation context | `kev/panel.py`, `ui_kev.py` | Catalog context, import/fetch controls and existing consent |
| `leads` / Leads | `pilot/panel.py`, `ui_leads.py` | Stored ranked leads and explanation/context controls |
| `series` / Series | `nway/panel.py`, `ui_series.py` | Multiple opened series tabs; hide preserves tabs |
| `files` / Files | `pe_overview/panel.py`, `ui_inspection.py` | Recorded and parsed PE/artifact comparison |
| `guide` / Guide | Reserved manifest slot | Remains reserved/unavailable; do not fabricate a Guide implementation |

Within these coherent feature modules, filters and result/detail controls can remain grouped. They must resize without clipping and may have local collapse controls; a local collapse is not advertised as independent docking. Additional subsection extraction is a future explicit registry change, not a condition for hiding or moving the entire feature.

## 4. Default workspace and presets

**New installations start in Beginner**, not “show everything.” Existing users first receive a migrated layout (§7), never a surprise reset on every launch. Presets specify an exact set of shown docks; omitted modules are hidden, not unloaded. Tabbed-but-not-frontmost panels count as open but do not add simultaneous visual content.

| Preset ID / label | Shown sections and intended arrangement |
|---|---|
| `beginner` / Beginner | Matches left; Older/Newer side by side in largest region; Comparison controls as a compact top strip. No findings, secondary engines or logs shown by default. Welcome text directs to New/Open/Sample and View > Panels. |
| `analysis` / Analysis | Beginner plus Change signals tabbed with Matches; Findings on right, Finding evidence tabbed with Finding review; Analyst notes available in the same right-side tab group. Findings initially frontmost, not all review surfaces expanded. |
| `compare` / Compare engines | Matches left; baseline Older/Newer main region; Engine evidence and Unified tabbed on right; Engine controls bottom, tabbed with Job details. Unified row details/code initially hidden, revealed explicitly from Unified. |
| `reverse_engineering` / Reverse engineering | Matches left; Older/Newer main region; Files and Build environment tabbed right; Calls, Strings, Capabilities and Search tabbed bottom, Calls initially frontmost. Does not start scans or select an analysis engine. |
| `review` / Findings review | Findings left; Finding evidence main region; Finding review and Analyst notes right tab group; baseline code available hidden via View/navigation. |

Presets use named areas, split relationships and proportional sizing, never absolute screen coordinates. Beginner at 1440×900 targets roughly 22% width for Matches and equal shares of the remaining code width. At 960×640 logical pixels, Older/Newer may be tabified by the **explicit compact variant** of the chosen preset, with a visible “Show both sides” command. Do not silently re-tab a manually arranged workspace merely because a window resizes. Reflow control rows/wrap labels first; scroll panel content when necessary.

The global chrome remains compact: project and orientation identity, current run/stale context, active-job count/status and a reveal-job-details action. The toolbar may be moved or hidden through View > Toolbars; every existing action remains in menus/palette. Do not put all advanced actions back into the default toolbar. A hidden log must not conceal that a job is running or remove its cancel route.

User layouts: Save layout as, Rename, Delete, Restore saved layout. Built-ins are immutable; editing one changes the current layout and may be saved as a user layout. Switching preset first retains a previous-layout snapshot and offers Undo layout change. Reset workspace layout restores Beginner only; it never clears application configuration or project data. Include “Bring floating panels onto this screen” and “Show panel…” recovery commands. No “show all” overload as the primary recovery path.

## 5. Dock interactions, navigation and accessibility

Each dock supports title-bar drag, native edge splitting, tab stacking/reorder, resize, float and re-dock, and close-to-hide. Closing a floating dock hides that section, not PatchTrace. No dock content uses delete-on-close. Double-click behavior follows the platform's native dock title bar. A visible dock title identifies its purpose; both code sides always retain Older/Newer identity even when moved to another monitor.

View > Panels groups Core comparison, Findings/review, Engines/evidence, Investigation and Utilities, with checked actions reflecting logical open state, not whether a tab is currently frontmost. Showing a panel raises its tab, restores its last location when valid, and focuses a meaningful control. Focus a blocked panel's explanation rather than disabling all ways to reach it.

Extend the existing palette with deterministic commands: Tab with [panel], Split beside/below [panel], Float/Dock, Move to [area], Focus, Show/Hide, Restore preset and Bring on screen. Destination choosers exclude self and unavailable modules and operate on IDs, not titles. Define split operations on tab groups explicitly: split the target group and place the selected panel adjacent; do not duplicate or silently un-tab unrelated panels. Preserve existing shortcut assignments; new sections initially have no fixed Ctrl+Shift chord. Registry lint must reject conflicts.

F6/Shift+F6 cycles visible logical regions once each, including floating docks; hidden and background tabs are skipped. Do not retain the old fixed `_PAIR_FOCUS` cycle and add duplicate registry entries for the same widgets. After hiding the focused section, focus the next shown section or the main menu. After a layout change announce the new layout once, not each individual hide/show. Supply accessible names/descriptions to extracted controls, readable tab titles, visible focus and keyboard access to every arrangement action. Retain theme, high-contrast and reduced-motion behavior.

Successful function/match/line/hex navigation reveals the required destination code dock(s), even if hidden, and activates the proper tab/floating window. A side-specific anchor reveals that side; a comparison action reveals both. Navigation should not also force unrelated Findings or Diagnostics open. Preserve stale, missing, ambiguous and blocked anchor results; none may reveal plausible but wrong data. `@code`, `select_match`, `reveal_lines`, `show_raw_offset`, `show_external_pair`, Unified's Go to match and evidence links all require regression coverage.

## 6. Content, drafts, jobs and resources

### Presentation is not state ownership

ProjectService, analysis controllers and task channels continue to own work. The dock manager owns placement only. Reparent existing widgets without destroying them; do not rebuild a model or reconnect its signals on each show. No analysis run, provider request, probe, import, export or project mutation is triggered by moving, tabbing, restoring or switching a preset. Existing bounded asynchronous reads needed to hydrate a newly revealed view remain allowed; reuse current results where possible and do not perform those reads synchronously in layout handlers.

Hide preserves selected match/finding, filters, sort, current code representation/page/scroll, expanded details, Series tabs, notes and conclusion drafts. Sync-scrolling remains functional across floated/tabbed/hidden code sides without recursive signal loops. A hidden side catches up to the selected context when shown. Record code side and run identity in each viewer so independent movement never makes two different contexts look like a pair.

Drafts need an explicit in-memory model keyed by project identity plus target finding/match, not “whatever is currently selected.” Extracting review/notes must not introduce a save or discard on dock close. When selection or project changes, keep the draft attached to its original target and show that target when restored; provide explicit Save/Discard/Switch actions. Never save an old draft to a newly selected finding. Project close/application exit must resolve dirty drafts through an explicit decision before existing teardown. Draft text is **not layout persistence**, and this specification does not silently enable disk autosave for it.

### Busy-state invariants

Hiding/tabbing/floating a job surface does not cancel a job, release its service/store, destroy a worker or discard its eventual result. Explicit Cancel keeps its current semantics; window exit keeps the actual shutdown/cancellation contract. Completed background work updates the owning model once and posts a compact global status; it must not steal focus or reopen hidden panels. If a project's revision/run changes while hidden, mark stale and refresh with the current key on reveal. Late replies for previous keys/generations cannot replace current content.

Keep the existing TaskRunner and generation checks. Share EvidenceController between Evidence and Engine controls and UnifiedController between its three views; initialize, deliver project/busy/selection notifications and shut down each controller once. Visibility optimization considers all views owned by that controller. A hidden owner with an active task still receives completion/lifecycle events; only expensive rendering is deferred. Do not use `visibilityChanged(false)` as a shutdown or cancellation signal: tab occlusion is not user closure.

Factories run on the GUI thread and remain bounded; file parsing, database scans and tool work stay on existing worker seams. Cheap shells exist before restore; heavy feature content remains lazy except already-eager evidence and necessary core adapters. No eager build-all on every layout restore. Hidden data may mark its view dirty and skip painting, but edits and active job state are retained. Preserve existing row/text/clipboard/log limits. Measure shell creation and show/hide separately from backend timing; performance acceptance is in §9.

## 7. Persistence, migration and recovery

### 7.1 Storage contract

Continue `QSettings('PatchTrace', 'PatchTrace')`. Add a versioned workspace envelope under `workspace_layout/`, separate from project files and feature settings. Proposed envelope format version is `1`; this is distinct from Qt dock-state version. Keep Qt `LAYOUT_SCHEMA=1` while adding IDs; only an incompatible ID rename/removal requires its existing bump rule.

Envelope fields: format version; generation; active preset or user-layout ID; Qt dock-state version and bounded byte blob plus digest; main-window geometry plus digest; ordered known panel IDs; logical open IDs; active tab per group where needed for deterministic restoration; floating-dock logical rectangles and screen hints; toolbar visibility; bounded section-layout options; last focused panel; app/Qt version as diagnostic metadata. User layout display name is bounded plain text, with an opaque ID, never a settings path. Store no project paths, artifact bytes, credentials, notes, conclusions or query results in the envelope. Initial bounds: 64 KiB per Qt state blob (existing bound), 128 KiB per serialized envelope, 20 named user layouts, one previous-layout snapshot and two autosave generations. Reject oversize writes visibly without losing the last valid save.

Use two generation slots plus an active-generation pointer: write the inactive complete envelope, sync/check status, validate readback, then switch the pointer and sync/check status. On startup try the pointed valid generation, then the other valid generation, then legacy state, then Beginner. A digest detects corruption, not trust/authentication. `QSettings` is not assumed to provide a transaction across arbitrary keys; test interrupted publication and write failure. [QSettings](https://doc.qt.io/qt-6/qsettings.html).

Debounce layout-only changes after interaction settles (proposed 750 ms); save after successful preset/user-layout changes and clean close. Suppress saving during startup restore/migration and while minimizing. Keep normal/maximized state separately; never restore minimized. A settings write error reports “Layout could not be saved; this session is unchanged,” preserves prior generations, and does not prevent shutdown of workers. Two app instances must use generation conflict detection: do not silently overwrite a newer layout saved by another window; keep the current arrangement in memory and offer Save as.

### 7.2 Restore order and migration

1. Register/lint panel declarations, create all available cheap shells and assign stable names before any Qt restore.
2. Establish a valid Beginner placement baseline and compact chrome; no heavy feature construction merely for restore.
3. Read and validate envelope types, versions, lengths, digests and IDs. Do not hand-edit opaque Qt state bytes.
4. Restore main-window geometry, then dock state; check return values. Restore logical visibility and active tabs only for known available IDs. Missing optional panels are skipped with a non-modal explanation; newly added panels stay hidden unless required core recovery surfaces.
5. Sanitize all floating and main-window geometry against current displays; then reconcile lifecycle once and restore focus if available.
6. Only after successful validation/reconciliation enable debounced saves. On failure reapply the whole baseline, not a partially restored layout, and announce `PT-GUI-LAYOUT` recovery.

For an existing schema-1 installation: preserve `layout/*` and `desktop/geometry` as read-only migration inputs/rollback copy. Restore existing feature docks by unchanged IDs. Convert legacy `desktop/workspace` and `desktop/vertical` proportions into reasonable initial core dock proportions when readable; if conversion is unreliable use the equivalent three-column-plus-log **Legacy arrangement** migration, without claiming pixel-exact conversion. Migrate `desktop/code` to older/newer proportions. Preserve font, sync, theme and all feature settings. Removed splitter keys must no longer override new layout on later launches. Publish the migrated envelope only after success and mark migration done. A failed attempt leaves old inputs intact.

Unknown future envelope versions are retained, not overwritten with defaults automatically; use Beginner in memory and explain that the saved layout belongs to a newer build. Known older envelope versions use explicit tested migrations. Append-only panel IDs preserve old layouts; retired IDs remain reserved and are ignored safely. Any actual ID replacement needs an alias/migration table, version decision and fixture. Reset layout affects this workspace namespace only, not general QSettings or project state.

### 7.3 Monitor, DPI and invalid geometry

Validate finite, positive bounded logical dimensions. Display identifiers are hints, not stable authority. Choose the saved screen when available, otherwise the screen containing the main window, otherwise the primary screen. Clamp floating docks to available work area so the entire title bar and close/dock controls are reachable, reduce oversized windows to fit, and respect negative-coordinate screens. Keep panel contents scrollable when their preferred minimum exceeds the work area; hard minimum sizes must not force windows offscreen.

On screen removal, DPI/font/style changes and restore from a disconnected monitor, re-evaluate geometry after Qt has updated screen information. Use logical coordinates; do not multiply a restored logical rectangle by device-pixel ratio again. Bring inaccessible floats onto a visible screen without reordering valid docked groups. A user-invoked recovery command also repositions floats that technically intersect a screen by only a few pixels. Test mixed 100/150/200% scaling, portrait displays, negative origins and unplug/replug, including minimized/maximized main window. The existing main-window-only clamp is not sufficient evidence of floating-dock safety.

## 8. Implementation slices and file ownership

No code is authorized by this artifact. If implementation is later approved, use small reviewable slices, each retaining all workflows.

| Slice | Work and likely files | Exit evidence |
|---|---|---|
| D0 — contract/index | Register spec in `docs/specs/{INDEX,REGISTRY}.md`, index new modules in `docs/modules.md`; reconcile relevant GUI/UI/settings/non-goals/guide wording | Source-to-panel inventory and regression checklist reviewed; no duplicate feature promises |
| D1 — native shell/layout | Extend `gui/qt/{host,docks,layout,commands}.py`; proposed `gui/qt/workspaces.py` for presets/geometry helpers | Empty/fake modules demonstrate dock-only center, split/tab/float/restore and keyboard recovery |
| D2 — core extraction | `ui.py` builders; proposed `gui/core_panels.py` pure declarations and `gui/qt/core_panels.py` adapters; `panel_manifest.py` | All ten core sections move independently; callbacks/selection/render behavior unchanged; Legacy migration works |
| D3 — heavy surface decomposition | `ui_evidence.py`, `secondary/evidence_panel.py`, `ui_unified.py`, `unified/panel.py`, manifest and pure declarations | Engine controls and Unified detail/code independent, one shared controller/job owner each, existing setup/run workflows intact |
| D4 — durable layouts | `gui/qt/layout.py`, workspace helper, `ui.py:restore_preferences/closeEvent` | Generation recovery, migration, monitor/DPI and settings-failure fixtures; named layouts/presets/undo |
| D5 — navigation/drafts/lifecycle | `gui/qt/{host,commands}.py`, `gui/ports.py` only if necessary, core adapters and draft model | Hidden-target navigation; no draft loss/misattribution; no hide-cancel; no duplicate lifecycle callbacks |
| D6 — acceptance/help | Existing tests below plus proposed `tests/test_dockable_workspace.py`, `test_workspace_presets.py`, `test_workspace_migration.py`, `test_workspace_drafts.py`; docs/help and guide | Offline automated suite plus explicit Windows/manual gates, feature parity matrix and known limitations |

Keep declarations Qt-free and preserve import-lint/frozen packaging discovery. MainWindow compatibility attributes (`navigator`, `views`, `findings_list`, etc.) may temporarily reference adapter-owned widgets; do not maintain two widgets or two sources of truth. Remove compatibility indirection only with caller and test updates. Do not change backend/provider/schema contracts merely to make UI extraction convenient.

## 9. Objective acceptance and fixtures

The following are **future acceptance requirements, not results claimed by this document**. Use synthetic/offline inputs and stub workers; no paid provider or live tool/network call is needed to validate docking.

| ID | Fixture/action | Required observable result |
|---|---|---|
| DW-01 | New empty settings; open window | Beginner has exactly `{matches, compare_controls, code_older, code_newer}` open (four dock IDs), compact chrome and no advanced feature dock; no provider/probe/tool job starts |
| DW-02 | Enumerate all 27 manifest slots | 26 expected built slots after implementation plus absent Guide; unique stable names, all present feature actions remain reachable; no Related activation implied |
| DW-03 | For every built dock: show, split, tab, float, hide, show | Same widget/controller/model identity and selection; one toggle action; no duplicate signal delivery; close-to-hide never closes app |
| DW-04 | Move code sides to separate displays; select match and navigate hunks/raw offset | Correct Older/Newer labels, paired selection, sync and raw modes retained; no reentrant scroll loop |
| DW-05 | Save layout containing split/tab/float/hidden docks; restart | Open set, areas, tab groups/order, active tabs, proportions within rounding tolerance, float state and valid geometry restore |
| DW-06 | Legacy QSettings fixtures with current blobs/splitters; corrupt and partial variants | Valid legacy features preserved, core migration reasonable, old keys not reapplied; corrupt case yields complete usable default and one explanation |
| DW-07 | Oversize/bad-digest/truncated/wrong-type/future-version blobs; crash between each generation write | No crash or partial mixed layout; previous valid state or defaults selected; future state not destroyed |
| DW-08 | Missing panel/new panel/retired-ID fixture | Known panels recover, new optional panel remains discoverable/hidden, unsupported IDs do not prevent opening |
| DW-09 | Settings denied/full-disk simulation and generation conflict | Current session works, previous valid save survives, warning shown; newer second-instance layout not silently overwritten |
| DW-10 | Fake long comparison, engine run and feature task; hide owner and switch preset; complete | Work continues, result committed once to correct key, global job indicator remains reachable, hidden panel stays hidden; explicit cancel still works |
| DW-11 | Type note/conclusion; hide/float/tab/reset/preset; change selection and project | Draft text/target retained; no implicit save/discard and no save to wrong target; exit has explicit dirty-draft resolution |
| DW-12 | Hide all destinations; activate code/evidence/hex/Unified links | Only required valid target docks reveal; stale/ambiguous/not-found links preserve existing semantics |
| DW-13 | Keyboard only, including empty/all-hidden workspace | View/palette recovers any panel; tab/split/move/float available without drag; F6 no duplicate/hidden stops, focus survives hide |
| DW-14 | 960×640 and 1440×900; 100/150/200% DPI; monitor removal/negative origin | Title-bar controls reachable, content not permanently clipped, active code readable/scrollable; recovered floats visible; no forced reset of manual arrangement |
| DW-15 | Apply each preset twice and undo | Deterministic topology/open set, no accumulated duplicates; content/filters/drafts/jobs unchanged; previous layout recoverable |
| DW-16 | Fifty show/hide/float/dock cycles with seeded results | Controller/task/thread counts return to initial steady counts; no retained duplicate widgets/subscriptions; heavy factories called once per controller |
| DW-17 | Seeded synthetic project, 100k-row bounded models and large bounded code/log | Layout handlers do not perform synchronous disk work or any network/tool work; p95 show/hide of already-built panels ≤100 ms on recorded reference Windows hardware, no GUI stall >250 ms caused by layout management; report cold factory time separately |
| DW-18 | Frozen Windows build, NVDA/Narrator, high contrast and reduced motion | Panel names/actions/tabs and announcements usable; no hidden docking dependency/import failure; record manual evidence, not inferred pass |

Reuse/extend `tests/test_gui_host.py`, `test_gui_host_layout.py`, `test_gui_host_palette.py`, `test_gui_host_seam.py`, `test_gui_core_{manifest,registry,lint,isolation,shortcuts}.py`, `test_ui.py`, `test_ui_m3_docks.py`, `test_ui_m4_selections.py`, `test_ui_unified*.py`, `test_ui_engine_setup.py`, `test_ui_series.py`, `test_ui_pemeta.py` and relevant feature-panel tests. Stress seams already exist in `tests/stress/test_gui_stress_{docks,project,state,tasks,teardown}.py`. New tests must assert semantics/state, not exact platform-dependent pixel screenshots alone.

Before claiming implementation complete, run the repository-required offscreen Qt suite and Ruff, then record Windows-specific/manual results separately. This specification task did **not** execute those tests, start PatchTrace, invoke CI, run analysis tools, call paid providers, or change GitHub state.

## 10. Source coverage and handoff

Directly inspected at the pinned baseline: `AGENTS.md`; module index; main window actions/builders/preferences/close lifecycle; registry/manifest; host/dock/layout/command implementations; all registered feature declaration files present in the tree; Files/Series adapters' declarations; Evidence and Unified view composition; Search/Strings/Build environment implementation excerpts; KB panel composition; task-runner structure; existing layout tests; current panel/layout user guide; GUI-framework and non-goals specifications. Recursive tree confirmed relevant implementation/test paths and the absent Guide declaration. This is a focused static specification review, not an exhaustive runtime or backend audit.

Primary source entry points: [MainWindow](https://github.com/djshellshoxxx/patchtrace/blob/a04f5a299a8d4afef023261e52e08d14678cf1e7/src/patchtrace/ui.py), [manifest](https://github.com/djshellshoxxx/patchtrace/blob/a04f5a299a8d4afef023261e52e08d14678cf1e7/src/patchtrace/panel_manifest.py), [host](https://github.com/djshellshoxxx/patchtrace/blob/a04f5a299a8d4afef023261e52e08d14678cf1e7/src/patchtrace/gui/qt/host.py), [layout persistence](https://github.com/djshellshoxxx/patchtrace/blob/a04f5a299a8d4afef023261e52e08d14678cf1e7/src/patchtrace/gui/qt/layout.py), [existing layout tests](https://github.com/djshellshoxxx/patchtrace/blob/a04f5a299a8d4afef023261e52e08d14678cf1e7/tests/test_gui_host_layout.py).

Recommended decision: adopt native docking throughout, preserve the framework and features already built, and ship the four-surface Beginner arrangement as the new-install default. This artifact specifies the requested design; runtime implementation is outside this documentation change.
