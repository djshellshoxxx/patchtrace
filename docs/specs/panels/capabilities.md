# Capabilities panel (CAP-6a and CAP-6b)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

CAP-6a displays stored capa capability changes by matched function group. CAP-6b supplies explicit local setup, probe and run. Analyst question: "Which recognized behaviours differ between these function pairs, and is that a gain, loss, possible move, detection difference or missing observation?"

Source: `docs/specs/program-e/CAP-integration-plan.md`, sections 1–11. No capability-count severity, vulnerability verdict, automatic tool download, dynamic execution or guessed instruction-to-function attribution is introduced. A moved behaviour remains a candidate. Missing coverage never means absence.

## 2 Identity

`PANEL` belongs in `intelligence/tools/capa_panel.py`; its lazy factory imports `ui_capabilities.create_panel(ctx)`. Identity: id `capabilities`, title "Capabilities", area `bottom`, tabify_with `graph`, shortcut `Ctrl+Shift+A`, focus_order `150`, default_visible `False`, requires `('project',)`, claims `CLAIMS_NEUTRAL`. These are exact manifest placement values. Claims supplement: forbid probability or severity claims about capabilities; preserve the domain footer's neutral limitations. Tool availability gates Run, never reading stored rows.

Conflict: CAP section 8 places the dock on the right with evidence. The actual manifest wins because registry placement lint otherwise fails. The older QThread recipe is replaced by TaskRunner. Register tips and commands through PANEL; never edit tooltips.py or ui.py. Controller implements widget, focus_target, project_changed, selection_changed, busy_changed, capabilities_changed, theme_changed, show_anchor and shutdown.

## 3 Data contract

Pure persisted/domain inputs keep their names from CAP section 7: PairCapabilityDelta (contract capa-pairs/1; derived only), PairChange, PairCell, Unattributed, CoverageSummary, FeatureRef, TaxonomyLabel. PairCell.state is present/absent/not-evaluated/no-function. PairChange.change is gained/lost/moved/unchanged/not-compared; noise is none/detection-difference. Changes and unattributed evidence retain separate lists.

CAP-3 owns `intelligence/tools/capa_view.py`. Proposed, UNVERIFIED runtime API: `build_view(delta, options, key) -> CapabilityView`, `filter_rows(view, options) -> CapabilityView`, `provenance_block(change, manifests, key) -> str`. Add these functions only if the actual equivalent is absent. Frozen slotted in-process fields: key: ProjectKey; state: str; rows: tuple[CapabilityRow,...] at most 100000; groups: tuple[CapabilityGroup,...]; selected_id: str|None; summary: str at most 200; detail: str at most 4000; truncated: bool; warnings: tuple[str,...] at most 16, each 200. CapabilityRow carries change_id, group_id, match_id|None, rule_id, namespace, scope, change, noise, older_text, newer_text, pair_text, search_text and stable order keys; displayed values at most 200. Feature refs at most 16 per side; labels at most 32; evidence links at most four per cell. No Qt object enters these values.

Services: read stored evidence and hash-checked sidecars; groups_from_project supplies n:m pair groups, never nearest-address joins. Refresh reparses raw output in memory; unavailable coverage is C13. Local run uses the existing tool runner, one side at a time. Identical tool/rules/backend basis is required; ambiguity produces no guessed change row. No new enrichment kind; pair deltas stay in an LRU of four keyed by evidence ids, pairing digest and contract.

## 4 Layout

Regions: tabs "Changes" and "Setup and run"; state strip; filters; summary; two-level feature-owned CapabilityTreeModel; detail SafeTextView; persistent footer. Use StateView, chips and ThemeTokens. Flat mode may use VirtualTable/ColumnSpec/TableSpec/PreparedTable; grouped mode remains feature-owned, passes identical lazy-model gates, uses uniform row heights and creates no cell widgets.

| Column key | Header | Width em | Empty cell |
|---|---|---:|---|
| capability | Capability | 30 | Unnamed rule |
| older | Older | 22 | Not evaluated: reason unavailable |
| newer | Newer | 22 | Not evaluated: reason unavailable |
| change | Change | 18 | Not compared |
| pair | Function pair (older to newer) | 34 | Not attributed to a function |

Default sort: namespace then rule name then change_id, ascending. Groups: namespace first two components, function pair, ATT&CK tactic, MBC objective, none. Filters: Changes/gained/lost/moved/unchanged/not-compared/all; text; show detection differences off; unattributed off; building-block rules off. Unchanged rows materialize on request, counts remain available. Groups auto-expand only with at most 20 shown rows. Exact cell forms: "present, 1 match", "present, {n} matches", "absent", "not evaluated: library function", "not evaluated: function not found by capa", "no function". Chips: + Gained, - Lost, ~ Moved (candidate), = Same, ? Not compared, each with distinct shape.

Detail headers: Change; Where; Older; Newer; Why capa matched; Rule; Rule labels; Cautions; Next steps; Provenance. Footer: "Capabilities are behaviours that capa rules recognise in code. A change means a recognised behaviour appeared, disappeared or moved between functions. It does not say what the change is for, and it says nothing about defects or about the intent of the code. capa does not follow calls, so a behaviour may only have moved." Setup shows absolute path, Browse, Probe, backend, rules identity, timeout, Run, Cancel, preview and bounded log. Pin facts come from the verified installed manifest, never hard-coded abbreviated digests.

## 5 States

The screen-reader announcement on entry is the exact displayed text below, with the same bounded substitutions. Ready announces the summary once. Buttons remain visible but disabled with a reason when unavailable. Error wins over stale, partial and ready; no-project wins over all project content.

| State | Trigger | Exact on-screen copy | Remedy | Announcement |
|---|---|---|---|---|
| C0/no-project | No key | Open a project to compare capabilities. | Host Open | Open a project to compare capabilities. |
| C1/blocked | No configured capa | capa is not set up. Choose an installed capa on the Setup and run tab. PatchTrace never downloads it by itself. | Setup and run | capa is not set up. Choose an installed capa on the Setup and run tab. PatchTrace never downloads it by itself. |
| C2/empty | No stored evidence | No capability results for this project yet. Run capa on the Setup and run tab to compare the behaviours capa recognises in the older and the newer file. | Setup and run | No capability results for this project yet. Run capa on the Setup and run tab to compare the behaviours capa recognises in the older and the newer file. |
| C3/loading | Run active | Running capa on the {side} file ({n} of 2). This can take several minutes per file. | Cancel | Running capa on the {side} file ({n} of 2). This can take several minutes per file. |
| C4/ready | Current comparable result | {g} gained; {l} lost; {m} moved; {u} unchanged; {x} not compared. capa evaluated both sides of {b} of {t} matched pairs. | Copy; Go to pair | {g} gained; {l} lost; {m} moved; {u} unchanged; {x} not compared. capa evaluated both sides of {b} of {t} matched pairs. |
| C5/partial | One side incomplete | capa did not finish for the {side} file ({reason}). A missing result is unknown, not 'no capabilities'. No comparison is shown. | Setup and run | capa did not finish for the {side} file ({reason}). A missing result is unknown, not 'no capabilities'. No comparison is shown. |
| C6/error | Assembly failed | Capability results could not be assembled: {code}: {message}. Stored capa results are unchanged. | Retry; Copy details | Capability results could not be assembled: {code}: {message}. Stored capa results are unchanged. |
| C7/stale | Key or basis changed | These results describe a different file pair, capa setup or analysis than the one on screen. Values are kept for reference only. Run capa again to refresh. | Refresh; Setup and run | These results describe a different file pair, capa setup or analysis than the one on screen. Values are kept for reference only. Run capa again to refresh. |
| C8/partial | No pairing | Function pairs are not available for this project (no completed comparison), so changes cannot be tied to functions. Totals per side are shown without pairs. | Host Run comparison | Function pairs are not available for this project (no completed comparison), so changes cannot be tied to functions. Totals per side are shown without pairs. |
| C9/empty | Complete, no changes | capa recognises the same behaviours in the matched functions of both files. This does not mean the code is the same: capa only recognises behaviours its rules describe. | All filter | capa recognises the same behaviours in the matched functions of both files. This does not mean the code is the same: capa only recognises behaviours its rules describe. |
| C10/blocked | Probe unusable | The configured capa cannot be used: {reason}. | Browse; Probe | The configured capa cannot be used: {reason}. |
| C11/too-large | Rows exceed cap | Too many rows to display ({n}). Narrow the filter. | Filter | Too many rows to display ({n}). Narrow the filter. |
| C12/partial | Truncated source | capa reported {m} matches; PatchTrace kept {n}. The list is incomplete. | Setup and run | capa reported {m} matches; PatchTrace kept {n}. The list is incomplete. |
| C13/stale | Coverage predates parser | Stored capa results predate this panel's coverage data. Refresh re-reads the saved capa output; capa is not run again. | Refresh | Stored capa results predate this panel's coverage data. Refresh re-reads the saved capa output; capa is not run again. |
| refreshing | Stored reload active | Refreshing capability observations... | Cancel | Refreshing capability observations... |
| cancelled | Token cancelled | Cancelled. Earlier results are unchanged. | Refresh | Cancelled. Earlier results are unchanged. |

Conflict: the earlier C1 copy and example setup steps embed an upstream version, size and truncated hash. Render validated pin values at runtime; their present correctness is UNVERIFIED. Never invite users to compare an abbreviated hash.

## 6 Interactions

All ids below are command ids and use the matching tooltip id. Showing/hiding is capabilities.action. capabilities.filter, group_by, search, show_noise, show_unattributed and show_library update only view options. capabilities.tabs changes tabs. capabilities.goto is Enter/double-click/context "Go to pair" and is disabled without a unique current match. capabilities.copy is Ctrl+C/context "Copy provenance"; deterministic LF block includes project/run, STALE if applicable, group/match/category, older to newer function ids and hashes, rule/scope/namespace, both cell states, executable and rules identities, backend/options, evidence run ids and cautions. No raw feature secrets. Space focuses detail; arrows/Home/End/Page keys stay within the tree.

capabilities.refresh reparses saved output. capabilities.retry retries only the failed read. capabilities.copy_error copies sanitized failure data. capabilities.browse selects a local absolute executable; capabilities.path edits the pending choice without executing; capabilities.probe explicitly probes version/help and hashes. capabilities.backend, rules and timeout update pending options and invalidate any preview. capabilities.run creates the preview. capabilities.confirm_run starts only that exact local operation after identity checks; capabilities.cancel_preview closes it. capabilities.cancel cancels the owned run/read token only. Escape in the preview cancels preview; it cannot cancel an unrelated main comparison.

The preview lists both sides' basenames and full SHA-256 values, tool absolute path and full digest, actual version, rules label/digest, backend, argv semantics, per-file timeout, memory and output caps, private scratch use, and no-network disposition. It discloses instruction emulation used by the backend without native target execution. Confirm is disabled if the preview is incomplete. Browse, probe and all run controls are disabled while their lane is occupied; reading retained evidence remains available. No Accept/Reject or evidence mutation is added.

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; keys are opaque, at most 256 characters, labels sanitized to 200. Pin run and revision from the same `ProjectKey` used to build the row. Use `NavigationPort.navigate`, not another panel's controller. `function` and `match` references resolve against `ProjectPort.match_index`. More than one candidate returns `ambiguous` with at most 20 candidates; never choose the first. A side mismatch is a miss.

Exact failure copy: stale: "This location belongs to an earlier project revision. Reload before opening it."; missing: "This location is not present in the current run."; ambiguous: "Several locations match. Choose one to continue."; blocked: "This location is unavailable in the current project." A stale or missing target keeps focus and selection where they were; show the reason beside the action. Only a shown result enters the host's 50-entry history. Alt+Left and Alt+Right remain host navigation. No fallback to another function, the same address in another run, or the opposite side.


anchors_in = {capability}; anchors_out = {function, match, rule, import, string}. A capability key resolves change_id or observation_key only within the current evidence pair. Rule ids carry rules identity in provenance and route only if a registered handler can resolve that identity; a generic same-name rule is not a substitute. Unattributed observations provide no function anchor. Selection_changed highlights a matching current group without changing filters silently.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Named channels: capabilities-load (stored evidence and view preparation), capabilities-detail (on-demand feature/provenance formatting), capabilities-probe (explicit tool probe), capabilities-run (both sides sequentially). Use a capabilities-reader lane for thread-owned sidecar readers. Local tool execution uses the supervised runner and 1800-second default per side, stdout 64 MiB, stderr 256 KiB, max parallel 1; proposed memory default 8 GiB is UNVERIFIED on Windows and must follow the actual supported runner policy. Progress uses C3 side/n; no invented percentage. After both sides commit under the current guard, enqueue a new stored-data load.

## 9 Settings

Use PanelSettings typed getters; invalid or overlong values fall back to defaults. No geometry, run results or secrets here.

| Key | Type | Default | Allowed |
|---|---|---|---|
| capabilities/filter | enum | changes | changes,gained,lost,moved,unchanged,not-compared,all |
| capabilities/group_by | enum | namespace | namespace,function,attack,mbc,none |
| capabilities/show_noise | bool | false | true,false |
| capabilities/show_unattributed | bool | false | true,false |
| capabilities/show_library | bool | false | true,false |
| capabilities/tool/path | str | empty | absolute path, at most 256 characters; save only after successful probe |
| capabilities/backend | enum | vivisect | vivisect,ghidra when probed usable |
| capabilities/timeout | int seconds | 1800 | 10..86400 |
| capabilities/tab | enum | changes | changes,setup |

Search and selection are session-only. A custom folder remains a session choice until a separate profile contract explicitly supports it. Never truncate a path into a different usable path; reject overlong input with an actionable message.

## 10 Tooltips

### `capabilities.dock`

Accessible name: "Capabilities panel".

What: Compare behaviours recognized by capa in the older and newer functions.

Why: Behaviour changes help choose code to inspect.

Effect: Read-only; showing this panel runs nothing.

Source: Stored capa evidence and current function pairing.

### `capabilities.action`

Accessible name: "Show Capabilities".

What: Show or hide the Capabilities panel.

Why: Keep behaviour context beside the comparison.

Effect: Toggles this dock; Ctrl+Shift+A.

Source: Panel registry.

### `capabilities.tabs`

Accessible name: "Capability views".

What: Choose Changes or Setup and run.

Why: Separate stored observations from an explicit tool operation.

Effect: Changes the local view; nothing runs on tab selection.

Source: Capabilities panel.

### `capabilities.filter`

Accessible name: "Filter capability changes".

What: Choose which capability change states to show.

Why: Separate gains, losses, moves and unavailable comparisons.

Effect: Filters stored rows without changing evidence.

Source: PairCapabilityDelta.

### `capabilities.group_by`

Accessible name: "Group capability changes by".

What: Group by namespace, function pair, taxonomy label or no group.

Why: Read related observations together without ranking them.

Effect: Rebuilds group indexes and preserves row selection by key.

Source: PairChange and TaxonomyLabel.

### `capabilities.search`

Accessible name: "Search capabilities by rule, namespace or function".

What: Filter capability rows by rule, namespace or function text.

Why: Find a named behaviour without scanning every group.

Effect: Changes the visible rows after a 120 ms debounce.

Source: Precomputed capability search text.

### `capabilities.show_noise`

Accessible name: "Show detection differences".

What: Include differing capa observations on unchanged function pairs.

Why: Distinguish analysis differences from source changes.

Effect: Adds detection-difference rows; default off.

Source: PairChange.noise.

### `capabilities.show_unattributed`

Accessible name: "Show unattributed capabilities".

What: Show rule observations without a supported function attribution.

Why: Keep file and instruction evidence visible without guessing an owner.

Effect: Adds an unattributed group; default off.

Source: PairCapabilityDelta.unattributed.

### `capabilities.show_library`

Accessible name: "Show building-block rules".

What: Include capa building-block rules in the view.

Why: Inspect supporting rule structure when needed.

Effect: Changes filtering only; default off.

Source: Stored rule library flag.

### `capabilities.table`

Accessible name: "Capability changes by function pair".

What: Read capability, older state, newer state, change and function pair.

Why: Keep both sides and comparison coverage visible.

Effect: Enter opens the selected pair; Space focuses details.

Source: PairCapabilityDelta.

### `capabilities.detail`

Accessible name: "Selected capability change details".

What: Read the selected row's basis, feature references, cautions and provenance.

Why: Judge why a rule matched and what was not evaluated.

Effect: Plain text; selection alone runs no tool.

Source: PairChange, coverage and tool manifests.

### `capabilities.goto`

Accessible name: "Go to selected function pair in the navigator".

What: Open the exact function pair attached to this observation.

Why: Inspect the code behind a behaviour change.

Effect: Disabled for unattributed, stale or ambiguous rows.

Source: Current MatchIndex and row EvidenceLink.

### `capabilities.copy`

Accessible name: "Copy provenance of selected capability change".

What: Copy the selected change with both sides and its tool provenance.

Why: Carry the limitations along with the observation.

Effect: Clipboard only, at most 16 KiB; disabled without a selection.

Source: Selected PairChange and tool manifests.

### `capabilities.refresh`

Accessible name: "Refresh stored capability coverage".

What: Re-read saved capa output and rebuild coverage and pairs.

Why: Use improved parsing without repeating analysis.

Effect: No capa process starts; hash-invalid raw output is refused.

Source: Hash-checked raw capa sidecars.

### `capabilities.retry`

Accessible name: "Retry loading Capabilities".

What: Retry the last failed stored-data load.

Why: Recover from a transient read failure.

Effect: Starts a new read generation; never repeats a tool run.

Source: Capabilities load request.

### `capabilities.copy_error`

Accessible name: "Copy capability error details".

What: Copy the bounded capability error code and context.

Why: Share a diagnosable error without raw tool output.

Effect: Clipboard only; paths and credentials are excluded.

Source: Sanitized task failure.

### `capabilities.stale_banner`

Accessible name: "Earlier capability results".

What: Explain why retained results no longer describe the active pair.

Why: Prevent navigation using a different run or setup.

Effect: Reference only; Run or Refresh creates current results.

Source: ProjectKey and tool identity comparison.

### `capabilities.footer`

Accessible name: "Capability interpretation limits".

What: Explain what a recognized behaviour change can establish.

Why: Avoid treating behaviour labels as an explanation of intent.

Effect: Read-only explanatory text.

Source: CAP integration plan, behaviour semantics.

### `capabilities.run`

Accessible name: "Run capa on both files".

What: Preview a capa run on private older and newer project copies.

Why: Make the tool inputs and cost explicit before starting.

Effect: Opens the local-run preview; disabled while busy or without a usable probe.

Source: Pinned tool manifest, selected backend and verified artifact hashes.

### `capabilities.cancel`

Accessible name: "Cancel capa run".

What: Request cancellation of the active capa operation.

Why: Stop a costly analysis while preserving prior evidence.

Effect: Cancels this operation's token and supervised child; no partial pair is promoted.

Source: TaskRunner and tool runner.

### `capabilities.probe`

Accessible name: "Probe capa".

What: Check the chosen capa executable and its declared capabilities.

Why: Know which tool identity would process the files.

Effect: Explicit version/help probe only; never runs either target.

Source: Tool probe adapter.

### `capabilities.path`

Accessible name: "capa executable path".

What: Choose the absolute path to a separate capa executable.

Why: Keep tool choice explicit and reproducible.

Effect: Stored only after a successful explicit probe; never resolved from PATH.

Source: Runtime discovery candidates and analyst choice.

### `capabilities.browse`

Accessible name: "Browse for capa".

What: Select an installed capa executable.

Why: Use a locally provisioned tool without downloading it.

Effect: Opens an injected local file chooser; starts no executable.

Source: Analyst-selected path.

### `capabilities.backend`

Accessible name: "capa backend".

What: Choose the configured static capa backend.

Why: Different recovery backends can produce different observations.

Effect: Defaults to vivisect; Ghidra requires an explicit usable setup.

Source: Tool manifest and probe results.

### `capabilities.rules`

Accessible name: "capa rule set".

What: Review the embedded rule identity or choose an advanced custom folder.

Why: Both sides need the same rule basis for comparison.

Effect: Custom rules are copied and digested; nothing is downloaded.

Source: ToolManifest.rules_identity and rules digest.

### `capabilities.timeout`

Accessible name: "capa time limit per file".

What: Set the maximum analysis time for each file in seconds.

Why: Bound a long operation before it starts.

Effect: Default 1800; accepted range 10 to 86400.

Source: Tool runner options.

### `capabilities.preview`

Accessible name: "capa run preview".

What: Review exact local inputs, executable, backend, rules and limits.

Why: Decide whether to run the displayed operation.

Effect: No network; the preview alone starts nothing.

Source: Immutable capa run request.

### `capabilities.log`

Accessible name: "capa operation log".

What: Read the bounded, sanitized status of the active operation.

Why: Distinguish running, cancellation and failure.

Effect: At most 200 lines; never displays raw target contents.

Source: Tool runner events.

### `capabilities.confirm_run`

Accessible name: "Confirm capa run".

What: Start exactly the local capa operation shown in the preview.

Why: Authorize this run with its displayed inputs.

Effect: Rechecks hashes and probe identity; an altered request needs a new preview.

Source: Immutable preview digest.

### `capabilities.cancel_preview`

Accessible name: "Cancel capa preview".

What: Close the capa preview without running analysis.

Why: Leave the stored observations unchanged.

Effect: Starts no process and sends nothing.

Source: Local preview controller.

### `capabilities.row`

Accessible name: "Capability row".

What: Read {rule}, {change}, older {older}, newer {newer}.

Why: Understand the row without relying on colour.

Effect: Read-only template; values are bounded and escaped.

Source: Selected PairChange.

### `capabilities.cell`

Accessible name: "Capability cell".

What: Read {column}: {value}.

Why: Hear the column meaning with the current value.

Effect: Read-only template; missing values retain their reason.

Source: Selected PairCell.

### `capabilities.group`

Accessible name: "Capability group".

What: Read group {label} with {count} visible changes.

Why: Know which rows belong to this group.

Effect: Expand or collapse locally without loading new evidence.

Source: Precomputed group index.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order, Changes: filter, group_by, search, show_noise, show_unattributed, show_library, copy, table, detail, goto, tabs. Setup: path, browse, probe, backend, rules, timeout, run, cancel, preview, log, tabs. Preview: read-only request, Cancel, Confirm. Row spoken form: "Capability {rule}, {change}, older {older}, newer {newer}, function pair {pair}". Group spoken form: "{group kind} {label}, {count} changes". Preserve expansion by group key after reset.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


First paint at most 200 ms, filter 100 ms, sort 150 ms (5x wall-time slack in shared CI, exact call ceilings unchanged). View preparation of 100000 rows at most 2 seconds; delta of 20000 observations at most 5 seconds; parser of 20000 matches at most 15 seconds and 1.5 GiB. Model memory at most 64 MiB per 10000 rows. Never expandAll. Detail at most 4000 characters; unmatched truncation remains visible.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts: none for CAP-6a/6b. No in-app tool or rules download; CAP-11 is deferred. Manual setup may show source addresses from a validated pin record, with their current reachability/licence UNVERIFIED here. A local-run confirmation is scoped to the displayed executable and inputs and never authorizes later uploads. Custom rules are unreviewed local data/code handled only by the supervised tool; never load a custom pickle cache into the GUI. Redact secret-looking features in display and copy by default.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named automated tests: test_capabilities_state_c0_to_c13; test_capabilities_missing_coverage_is_unknown; test_capabilities_moved_is_candidate; test_capabilities_unchanged_pair_difference_is_noise; test_capabilities_n_to_m_union; test_capabilities_orientation_swap; test_capabilities_manifest_bottom_graph; test_capabilities_tree_selection_expansion_survive_reset; test_capabilities_data_calls_10k_100k; test_capabilities_preview_identity_change_requires_new_confirm; test_capabilities_open_does_not_probe_or_run; test_capabilities_refresh_does_not_spawn; test_capabilities_late_run_cannot_publish; test_capabilities_clipboard_keeps_both_hashes; test_capabilities_custom_rules_mismatch_blocks; test_capabilities_unattributed_never_jumps. Each test asserts its named invariant rather than snapshotting implementation internals. Manual extra: installed capa probe, sequential run, cancel and EDR interaction; upstream tool licence and pin provenance review.

## 15 Open questions

1. Should CAP-11 downloads be included? Default no, manual provisioning only; any later addition needs its own exact consent flow and licence review.
2. Which placement wins? Default actual manifest bottom/graph; no shared-file edits in this task.
3. Must the tool gate the entire panel? Default no, requires project only; stale stored evidence remains readable and clearly labelled.
4. Which view functions already exist? UNVERIFIED against runtime code. Default adapt the actual CAP-3 functions behind the stated pure view contract; do not create a second model when one already satisfies it.
5. How to show instruction scope without verified extents? Default unattributed; CAP-9 remains deferred.
6. Does the memory cap work on every supported Windows package? UNVERIFIED. Default enforce the actual runner's supported cap and report unsupported isolation before Run.
7. Do taxonomy labels imply intent? Default no; optional grouping and provenance only.
