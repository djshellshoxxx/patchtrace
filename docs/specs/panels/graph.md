# Calls and graph panel (WB2 G5 and G6)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

Deepen WB2 G5/G6. Analyst question: "Which direct calls changed around this function, and how far does the stored evidence actually reach?" Source WB2-integration-plan.md. Changes, adjacency, lazy tree and diagram share one pure snapshot. Across-build evolution remains G7 and is not invented as a working tab. No missing unchanged-function lists are fabricated.

## 2 Identity

callgraph/panel.py PANEL; factory ui_calls.create_panel(ctx), adapter signature UNVERIFIED. id graph,title Calls,bottom,no tab group,Ctrl+Shift+G,focus_order130,default_visibleFalse,requires('project',),CLAIMS_PAIRING. Full PanelController hooks; selection_changed follows only when follow is enabled and no explicit seed is pinned. GraphCanvas is shared; graph layout remains feature-owned.

## 3 Data contract

Pure names from WB2: GraphNode,GraphEdge,GraphView(workbench-graph/1),Pairing,CallDelta,GraphLead,GraphSignal,CallSource,PairMapPort,ApiHintPort,EntryPort. GraphNode kind function/paired-unchanged/external/label-only/ambiguous; tier record/pairing/label; stored label512,shown120. Edges src=caller,dst=callee,side explicit; correspondence is a separate list, never a call edge. Completeness changed-set-lists/whole-program/unknown.

callgraph/view_model.py owns prepared tables/detail, callgraph/layout.py owns deterministic layout. Exact callable signatures UNVERIFIED; required pure entry points build_changes_view, build_neighbours_view, build_detail and layout_graph are proposed adapter names only. Frozen prepared view carries ProjectKey, source identity, seed id, side,direction,depth,node/edge ids, rows, positions, omissions,limitations and provenance. Table<=100000rows; neighbourhood query defaults100nodes/250edges, normal cap500nodes/2000edges, table expansion<=2000nodes. GraphCanvas hard2000nodes/8000edges is a widget ceiling, not permission to exceed domain query limits. Resolve through the WB2 ladder; keep every engine's conflicting pairing, no first-candidate fallback. Direct calls are sets, not multiplicity. Graph cache optional derived stage callgraph, never a new persisted analysis row.

Partial raw-read services reuse injected RawMatchesReader with verified path/hash, not a second loader. Call-site reveal may find an exact identifier token in stored decompiled text; it is a textual match, not a machine instruction address. Paths are observed-only,<=5 paths,length<=12,visit budget200000.

## 4 Layout

Tabs Changes,Neighbours,Tree,Diagram; common side,direction,depth,unresolved,changed-only,hide-noise,follow controls; status and detail; Open/Call site/Focus/Back/Copy/Export. Changes columns Newer function26em,Meaning36,Added10,Removed10,API hints24,Direct callers12,Ghidriff says24,State18. Neighbours columns Side10,Function30,Direction14,Call change20,Pairing24,Basis24. Unknown empty cell "Unknown: {reason}"; no call list "No stored list"; missing numeric value "Unknown", never0. Default Changes signal rank then newerRVA then match id; Neighbours side,direction,casefold label,node id. Sort keys stay ordinal, never combined into a score.

Use VirtualTable with ColumnSpec/TableSpec/PreparedTable for flat views. Tree feature-owned lazy model depth<=4,64children then "+{n} more"; that remainder expands only within query budgets. GraphCanvas uses supplied immutable node/edge views. Deterministic signed-hop layers,cycle handling,at most8sweeps,stable(label,id)ties; no randomness or external renderer. Diagram side-by-side older/newer, dotted correspondence cannot be mistaken for a call. LOD:marks below0.15,boxes below0.5,labels at0.5;zoom0.05..8. Diagram and Neighbours have the same query limits/completeness.

Detail headings Identity;Pairing;Call evidence;Limits;Provenance. Footer: "Call lists are the distinct direct calls recorded by Ghidra's analysis. Jumps, calls through registers or tables, and the lists of unchanged functions are not included. Missing is unknown, not removed." If an alternate whole-program source exists, show its recorded coverage separately rather than falsely applying the Ghidriff limitation to it.

## 5 States

Announce exact copy once; bounds and missing counts remain in the persistent status. E11 blocks the diagram only, not the textual evidence.

| State | Trigger | Exact on-screen copy | Remedy | Screen-reader announcement |
|---|---|---|---|---|
| E0/no-project | No project | Open a project to explore calls. | Host Open | Open a project to explore calls. |
| E1/empty | No completed run | No completed comparison yet. Run a comparison to see call relationships. | Host Run | No completed comparison yet. Run a comparison to see call relationships. |
| E2/loading | Reading | Reading call lists... | Cancel | Reading call lists... |
| E4/empty | Seed not indexed | This function is not in the stored change set, so no call lists are stored for it. Unchanged functions have no stored call lists. | Choose another seed | This function is not in the stored change set, so no call lists are stored for it. Unchanged functions have no stored call lists. |
| E5/empty | Empty stored lists | No caller or callee names are stored for this function. | Back | No caller or callee names are stored for this function. |
| E6/partial | Raw output invalid/missing | The preserved Ghidriff output is missing or does not match its recorded hash, so names of unchanged functions cannot be paired. Call changes are shown only where both names appear in stored lists. | Reload | The preserved Ghidriff output is missing or does not match its recorded hash, so names of unchanged functions cannot be paired. Call changes are shown only where both names appear in stored lists. |
| E7/partial | Neighbour cap | Showing {n} of {m} neighbours. Narrow the depth or the filters to see the rest. | Depth | Showing {n} of {m} neighbours. Narrow the depth or the filters to see the rest. |
| E8/cancelled | Cancelled | Cancelled. Earlier results are unchanged. | Reload | Cancelled. Earlier results are unchanged. |
| E9/error | Read failed | Calls could not be read: {code}: {message} | Retry; Copy error | Calls could not be read: {code}: {message} |
| E10/stale | Key changed | The call view is stale: {reason}. Reload to refresh. | Reload | The call view is stale: {reason}. Reload to refresh. |
| E11/too-large | Diagram over cap | Too large to draw ({n} nodes). Use the Neighbours table or narrow the depth. | Neighbours | Too large to draw ({n} nodes). Use the Neighbours table or narrow the depth. |
| E12/partial | Whole-program data absent | Whole-program paths need extracted instruction data (unified analysis), which this project does not have. Paths shown use stored call lists only. | Neighbours | Whole-program paths need extracted instruction data (unified analysis), which this project does not have. Paths shown use stored call lists only. |
| ready | Current snapshot | Showing {nodes} nodes and {edges} observed call relationships; coverage {coverage}. | Copy | Showing {nodes} nodes and {edges} observed call relationships; coverage {coverage}. |

Exact call change labels Added/Removed/Same/Not comparable/Hub, not compared. Pairing Paired/New in newer build/Deleted from older build/No pairing data/Ambiguous ({n}). Entry copy: "Reachable from export {name} in at most {k} calls (observed path)." or "No observed path from an export or the entry point; stored call lists are partial." No observed path is never unreachable.

## 6 Interactions

graph.action toggles. side/direction/depth/show_unresolved/changed_only/hide_noise/follow change bounded view requests. Changes table Enter/Open opens exact function; Neighbours Enter opens selected resolved node,Ctrl+Enter/graph.focus reseeds; Space focuses detail. graph.back/Backspace returns prior explicit seed (local history<=50), distinct from host Alt+Left/Right. graph.callsite reveals only an exact current identifier token and labels "text match in decompiled code"; failure "Call site not found in the decompiled text (it may be inlined or renamed)." No search in unrelated code.

graph.copy/Ctrl+C/context Copy details copies both hashes,run/revision,seed,node/edge source ids,side,coverage,pairing opinions,omitted counts and limits. graph.export_dot previews bounded UTF-8 LF text,path and provenance then explicit save; existing file requires overwrite decision. No Graphviz execution. graph.cancel/Escape cancels layout/load only when panel owns that action. graph.reload/graph.retry reread stored data, never analysis. graph.copy_error copies sanitized code/source identity.

Diagram arrows choose nearest node deterministically,Enter opens,Space selects,+/- invoke zoom_in/zoom_out,0 fit,M toggles minimap. Mouse wheel zoom is equivalent; minimap clicks centre viewport. These commands remain keyboard reachable without graphics; no node-only fact exists. Context menu Open,Show call site,Focus here,Copy details,Export DOT uses identical guards. Node selection never changes pairing or creates a review decision.

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; key at most 256 characters, label sanitized to 200. Pin run and revision from the row's ProjectKey. Use NavigationPort, not another panel's controller. function and match resolve through MatchIndex. More than one candidate returns ambiguous with at most 20 candidates; never choose the first. Side mismatch is a miss.

Use existing NavResult constructors and exact copy from gui/anchors.py: stale "The project changed after this link was created. Open it again from the source panel."; missing "Not found in run {run_id}: {label}." (omit the run phrase when absent); ambiguous "{n} candidates match {label}. Choose one."; blocked "{title} is unavailable: {reason}". A failed destination changes no selection or focus; only shown enters the 50-entry host history. Alt+Left/Right stay host navigation. A missing project makes any project anchor stale; projectless catalog operations use their local identity and do not enter project navigation history. Never guess an opposite side or same address in another run.


anchors_in empty (function belongs to code host); anchors_out={function}. Explicit graph focus commands accept a current seed from navigator through typed local state; do not claim canonical function ownership. A diagram label-only/external unresolved node may have no valid function anchor; return blocked with its stored resolution reason. function anchors pin exact side/function id; duplicate labels are not identity. Selection follows current match via ProjectPort, no direct MainWindow import.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Channels graph-load,graph-query,graph-layout,graph-detail,graph-export. graph-reader lane holds snapshot readers; layout takes immutable subgraph, returns positions only. Scene/items created/swapped/deferred-deleted on GUI thread, never retain item wrappers after old scene disposal. Capture seed/options digest per generation. Cancel every200claims or4096queue pops; layout checkpoints between sweeps. Progress "Preparing call diagram..." indeterminate; do not invent exploration percentages. No timers while hidden.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| graph/side |enum|both|older,newer,both|
| graph/direction|enum|both|callers,callees,both|
| graph/depth|int|1|1..4|
| graph/show_unresolved|bool|true|true,false|
| graph/changed_only|bool|false|true,false|
| graph/hide_noise|bool|false|true,false|
| graph/follow|bool|true|true,false|
| graph/diagram|bool|false|true,false|

No persisted node selection, coordinates, query history, paths or geometry. Bad values use defaults. Session zoom defaults1,clamp0.05..8.

## 10 Tooltips

### `graph.dock`

Accessible name: "Calls panel".

What: Explore stored direct call relationships on both sides.

Why: Follow changed calls while keeping incomplete coverage visible.

Effect: Opening runs no analysis.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.action`

Accessible name: "Show Calls".

What: Show or hide the Calls panel.

Why: Access call exploration from the keyboard.

Effect: Toggles the dock; Ctrl+Shift+G.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.tabs`

Accessible name: "Calls views".

What: Choose Changes, Neighbours, Tree or Diagram.

Why: Use equivalent textual and visual views of the same snapshot.

Effect: Switching views starts only required local view work.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.side`

Accessible name: "Call side".

What: Choose older, newer or both call lists.

Why: Keep orientation explicit.

Effect: Requeries the current snapshot.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.direction`

Accessible name: "Call direction".

What: Choose callers, callees or both.

Why: Separate incoming relationships from outgoing calls.

Effect: Requeries the bounded neighbourhood.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.depth`

Accessible name: "Call depth".

What: Set the number of observed call hops.

Why: Bound a neighbourhood without implying whole-program coverage.

Effect: Default1; range1 to4.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.show_unresolved`

Accessible name: "Show unresolved calls".

What: Include names without a supported function identity.

Why: Keep missing resolution visible.

Effect: Default on; unresolved never means absent.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.changed_only`

Accessible name: "Changed calls only".

What: Show only compared call changes.

Why: Focus on changed relationships.

Effect: Unknown changes remain explicit; view filter only.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.hide_noise`

Accessible name: "Hide hub-only call rows".

What: Hide rows containing only identified build-plumbing hubs.

Why: Reduce repetitive context when the analyst chooses.

Effect: Default off; hidden count remains visible.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.follow`

Accessible name: "Follow navigator selection".

What: Use the navigator's current function pair as the call seed.

Why: Move through functions without selecting a new seed manually.

Effect: Default on; explicit Focus here can pin a seed.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.changes_table`

Accessible name: "Changed calls table".

What: Read changed pairs with call deltas and limits.

Why: Choose a useful neighbourhood from explained changes.

Effect: Enter opens its exact pair.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.table`

Accessible name: "Neighbours of the selected function".

What: Read the textual adjacency equivalent of the diagram.

Why: Access every relationship without relying on graphics.

Effect: Enter opens; Ctrl+Enter focuses here.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.tree`

Accessible name: "Call tree of the selected function".

What: Expand stored caller and callee lists lazily.

Why: Inspect paths without materializing the entire graph.

Effect: Depth4 maximum;64 children then a remainder row.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.diagram`

Accessible name: "Call diagram".

What: Read a visual call neighbourhood; use Neighbours for its text equivalent.

Why: See structure while retaining an accessible alternative.

Effect: Arrow keys move node focus; no hidden graph facts.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.minimap`

Accessible name: "Call diagram overview".

What: Move the diagram viewport using its overview.

Why: Keep spatial context when zoomed in.

Effect: Local visual navigation only.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.detail`

Accessible name: "Selected call details".

What: Read identity, pairing, evidence, limitations and provenance.

Why: Distinguish observed calls from unknown relationships.

Effect: Plain text, no target execution.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.open`

Accessible name: "Open selected function".

What: Show the selected current function in code.

Why: Inspect the function behind an observed relationship.

Effect: Disabled for unresolved, ambiguous or stale nodes.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.callsite`

Accessible name: "Show call site".

What: Locate an exact callee identifier in stored decompiled text.

Why: Read the available textual context.

Effect: A text match is labelled as such, never claimed as an instruction address.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.focus`

Accessible name: "Focus call exploration here".

What: Make the selected resolved node the neighbourhood seed.

Why: Continue exploring a chosen branch.

Effect: Stores only local navigation history; no analysis.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.back`

Accessible name: "Previous call seed".

What: Return to the previous explicit call seed.

Why: Retrace neighbourhood exploration.

Effect: At most50 local seeds; stale entries are refused.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.copy`

Accessible name: "Copy call details".

What: Copy selected call evidence and snapshot provenance.

Why: Retain side, completeness and pairing limitations.

Effect: Clipboard only, at most16KiB.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.export_dot`

Accessible name: "Export call graph as DOT".

What: Preview and save a bounded textual DOT graph.

Why: Use the observed graph in an external workflow.

Effect: Local file only; Graphviz is never executed.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.status`

Accessible name: "Call exploration status".

What: Read coverage, limits and current task state.

Why: Know whether the result is partial or stale.

Effect: Status changes are announced once.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.cancel`

Accessible name: "Cancel call exploration".

What: Cancel loading or layout for this panel.

Why: Keep the interface responsive during bounded work.

Effect: Cancels owned token only.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.reload`

Accessible name: "Reload call evidence".

What: Read the current stored call snapshot again.

Why: Refresh after project changes.

Effect: No comparison engine runs.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.retry`

Accessible name: "Retry call read".

What: Retry the failed stored-data load.

Why: Recover without changing evidence.

Effect: Starts a fresh local read generation.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.copy_error`

Accessible name: "Copy call error".

What: Copy the bounded call error and source identity.

Why: Share diagnostic context without raw file contents.

Effect: Clipboard only.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.zoom_in`

Accessible name: "Zoom call diagram in".

What: Increase the diagram scale.

Why: Read local node labels.

Effect: Clamped to scale8.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.zoom_out`

Accessible name: "Zoom call diagram out".

What: Decrease the diagram scale.

Why: See a wider observed neighbourhood.

Effect: Clamped to scale0.05.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.fit`

Accessible name: "Fit call diagram".

What: Fit the prepared neighbourhood in the viewport.

Why: Recover a useful diagram view.

Effect: No graph query or layout algorithm change.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.row`

Accessible name: "Call row".

What: Read {label}, side {side}, call change {change}, pairing {pairing}.

Why: Keep relationship meaning independent of colour.

Effect: Escaped read-only template.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.cell`

Accessible name: "Call cell".

What: Read {column}: {value}, basis {basis}.

Why: Hear the column meaning and source.

Effect: Escaped read-only template.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

### `graph.node`

Accessible name: "Call node".

What: Read node {label}, side {side}, resolution {resolution}.

Why: Distinguish a function from an unresolved label.

Effect: Escaped read-only template.

Source: Stored callgraph snapshot, current pairing and recorded source completeness.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order side,direction,depth,show_unresolved,changed_only,hide_noise,follow,tabs,current table/tree/diagram,detail,Open,Call site,Focus,Back,Copy,Export. Diagram name includes "visual only; Neighbours has the same information"; scene item focus sends a polite label/side/resolution announcement because UIA may not expose individual items (Windows behaviour UNVERIFIED). Minimap is optional visual navigation, no exclusive content. Reduced motion makes zoom/recentre immediate. Tree remainder row has a spoken count and clear unavailable reason at limits.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


Graph layout<=400ms at500nodes with<=20000dummy nodes. Domain snapshot<=250000claims (IR source ceiling150000nodes/600000edges, never all drawn). Scene default500/2000; maximum2000/8000; avoid Python paint above500nodes; antialiasing off above200items per shared GraphCanvas policy. Domain export<=2000nodes AND<=2000edges and<=2MiB, stricter than canvas. Flat first paint<=200ms; at100000rows lazy-model exact call ceiling. Omissions never become hidden evidence.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts:none. DOT export is data only: fixed node ids,box shapes,whitelisted attributes,no URL/href/image/fontpath/HTML label. Sanitize then escape backslash before quote; no function name becomes a path. Text export never invokes Graphviz. API hints and hub names retain source/revision; unverified CFG helper spellings from WB2 are not asserted as known facts. Inferred label equality is flagged and never promoted to exact identity.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests: test_graph_e0_e12; test_graph_missing_lists_not_removed; test_graph_duplicate_label_ambiguous; test_graph_renamed_callee_same_link; test_graph_contested_pairing_kept; test_graph_import_new_function_distinction; test_graph_changed_only_keeps_unknown; test_graph_callsite_text_match_label; test_graph_query_cap_stricter_than_canvas; test_graph_canvas_text_equivalence; test_graph_deterministic_layout; test_graph_cycle_and_dummy_limit; test_graph_dot_hostile_labels; test_graph_late_layout_cannot_swap_scene; test_graph_back_stale_seed; test_graph_100k_lazy_calls. Manual extra: canvas keyboard/node announcement, table alternative under Narrator, frozen view performance and exact source provenance on real local inputs.

## 15 Open questions

1. Across builds tab now? Default deferred to G7; no empty active tab pretending it works.
2. Full program paths from changed lists? Default never; retain completeness and unknown frontier.
3. Canvas vs domain caps? Default domain query limits first, shared widget maximum second; no UI option silently raises a domain limit.
4. Hub inference? Default source-reviewed registry plus documented threshold; unverified helper spellings remain unverified.
5. Function anchor ownership? Default code host; graph receives seeds via explicit typed local commands and emits function anchors only.
