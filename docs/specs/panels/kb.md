# KB / CVE investigation panel (additional panel implied by Program E)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

Additional panel justified by PROMPT1 item9:the manifest reserves kb,and KB integration plan explicitly composes KEV,Search,Leads and pair acquisition. Analyst question:"Which locally documented update/product relationship supports this proposed older/newer comparison,and what remains unverified?" Use one investigation,not separate KBC and KPS applications. E0 offline/manual is the first delivery;E1 network acquisition is separately gated.

## 2 Identity

kbcorrelation/panel.py PANEL;lazy ui_kb.create_panel(ctx) proposed adapter UNVERIFIED. id kb,title "KB / CVE investigation",right,no tab group,Ctrl+Shift+K,focus_order180,default_visibleFalse,requires(),CLAIMS_NEUTRAL with no numeric documentary strength or vulnerability probability. Works without a project;project_changed selects attached investigation. All lifecycle hooks apply. Existing manifest placement wins over older modal workflow descriptions;results stay docked.

## 3 Data contract

Use KB integration plan§7.2 exact pure names SourceDoc,SourceRef,SearchScope,Coverage,ProductScope,KbCveEdge,ComponentHint,BuildRow,BinaryRef,PairProposal,PairPlan,Attempt,AnalystDecision,InvestigationRevision,ProjectLink,ContextReport,LeadRow,OperationResult,KbcIssue. Stored contract kbcorrelation/1 additive only. reduce(snapshot,event)->snapshot|KbcIssue in kbcorrelation/workflow.py is the sole transition authority. Side effects return revision/generation-bound events;Qt never improvises state transitions.

Pure kbcorrelation/view_model.py (plan path;callable names UNVERIFIED) must provide build_find_view,build_updates_view,build_files_view,build_builds_view,build_project_view,build_leads_view,provenance_block or adapters to equivalents. Prepared frozen row strings<=200,detail<=4000,issue<=500,lead raw<=200,analyst reason<=500,scope months<=24. Each table<=100000visible rows under framework cap;larger source uses narrower scope or paging. Complete-in-scope requires nonempty requested=inspected and no failures;exhaustive_for_history staysFalse. Product mapping derived from text is not verified.

Pair gradeA/B/X,lineage state,bytes state and fix_boundary remain separate. Both final hashes+AMD64 parse required before BYTES_VERIFIED;both sides before project creation. Context attach after project creation is recoverable CONTEXT_PENDING,never project rollback. Project attachment to an existing comparison never silently reorients it. Source services and ProjectService called through typed composition,not Qt SQL. Exact source field shapes and sizes not explicitly listed here remain the KB§7 contract,not guessed duplicates.

## 4 Layout

Six eager pages Find,Updates,Files,Builds,Project,Leads,filled lazily. Top lead/Search/Import/Plan,coverage strip,step selector;bottom status and Cancel. VirtualTable ColumnSpec/TableSpec/PreparedTable per flat table;no proxy or ResizeToContents.

| Table | Headers with width em | Default order | Empty text |
|---|---|---|---|
| Documents | Document30,Kind16,Release16,State20,Basis32 | release descending,doc_id | Not inspected: reason |
| Updates | KB16,CVE22,Product32,Arch12,Relation34,Fixed build20,Source24,KEV22 | source scope order,edge_id | Unknown: reason |
| Files | Name24,Tier12,Changed in KB18,Basis44 | tier,name,hint_id | Unknown |
| Older/Newer builds | Version24,Release18,KB16,Hash24,Availability20,Basis30 | explicit source order then full hash | Not listed |
| Leads | Subject32,Group22,Channel states40,Reading basis40 | pure lead ordering,lead_id | Unknown: reason |

Updates product/relation/text filters,CVE detail;Files name/Add;Builds older/newer choice or local pickers,Swap,pair strip;Project name,destination,Create,plan approval;Leads group filter/detail/Go/Copy/Refresh. No extra scores or functions automatically associated from advisory wording. KEV column uses KevColumnProvider,its source freshness and neutral absence semantics. No duplicate KEV fetch controls here.

## 5 States

Exact copy from KB plan§8.2 except KB15 is narrowed to avoid claiming nothing changed after an already created project. Announce the exact displayed copy once;KB11 progress counts actual known bytes only. Disable later steps with adjacent prerequisite text,not silent absence.

| State | Trigger | Exact on-screen copy | Remedy | Screen-reader announcement |
|---|---|---|---|---|
| KB0 | no lead | Type a KB number (KB5012345) or a CVE ID (CVE-2024-12345). Searching uses only advisory files already on this computer. | Lead | Type a KB number (KB5012345) or a CVE ID (CVE-2024-12345). Searching uses only advisory files already on this computer. |
| KB1 | no documents | No advisory documents are loaded, so nothing was searched. Import a saved CVRF or CSAF JSON file, or review a network plan. | Import;Plan | No advisory documents are loaded, so nothing was searched. Import a saved CVRF or CSAF JSON file, or review a network plan. |
| KB2 | searching | Searching the local advisory index..." (indeterminate bar, Cancel) | Cancel | Searching the local advisory index..." (indeterminate bar, Cancel) |
| KB3 | found | coverage strip: "Checked {n} advisory documents ({first} to {last}); {f} unreadable. Nothing outside these documents was checked. | Updates | coverage strip: "Checked {n} advisory documents ({first} to {last}); {f} unreadable. Nothing outside these documents was checked. |
| KB4 | not found, complete | {lead} was not found in the {n} documents checked ({first} to {last}). That does not mean it has no security updates; these documents do not list it. | Widen document scope | {lead} was not found in the {n} documents checked ({first} to {last}). That does not mean it has no security updates; these documents do not list it. |
| KB5 | not found, partial | {lead} was not found, but {f} of {n} requested documents could not be read, so this result may be incomplete. | Coverage | {lead} was not found, but {f} of {n} requested documents could not be read, so this result may be incomplete. |
| KB6 | several products | This update applies to several products. Choose the product and architecture of the files you are analyzing. | Product | This update applies to several products. Choose the product and architecture of the files you are analyzing. |
| KB7 | no filename | The advisory does not name the changed file. Enter a file name such as clfs.sys, or choose two files you already have. | Add file;Choose files | The advisory does not name the changed file. Enter a file name such as clfs.sys, or choose two files you already have. |
| KB8 | CVE not applicable | Microsoft lists this CVE for other products only. It is left out of the leads for {product}. | Product | Microsoft lists this CVE for other products only. It is left out of the leads for {product}. |
| KB9 | pair blocked | Pair creation is blocked: {reason}. | Pair selection | Pair creation is blocked: {reason}. |
| KB10 | review plan (E1) | Review before anything is downloaded: {n} requests to {hosts}. Files are checked against the expected SHA-256 and size and are never run. | Approve;Cancel | Review before anything is downloaded: {n} requests to {hosts}. Files are checked against the expected SHA-256 and size and are never run. |
| KB11 | acquiring (E1) | Downloading {side}: {done} of {total}." Cancel: "Cancelling. The current request must finish; nothing is kept. | Cancel | Downloading {side}: {done} of {total}." Cancel: "Cancelling. The current request must finish; nothing is kept. |
| KB12 | context pending | The comparison project was created, but the advisory context could not be attached. Retry attach; the project is unaffected. | Retry attach | The comparison project was created, but the advisory context could not be attached. Retry attach; the project is unaffected. |
| KB13 | context ready | Advisory context is attached. It records what the vendor states and which checks could not be made; it does not show that any changed function addresses a vulnerability. | Leads | Advisory context is attached. It records what the vendor states and which checks could not be made; it does not show that any changed function addresses a vulnerability. |
| KB14 | stale | This context was prepared for a different file pair, analysis run or advisory revision. It is shown for reference; navigation is off. | Refresh | This context was prepared for a different file pair, analysis run or advisory revision. It is shown for reference; navigation is off. |
| KB15 | error | {code}: {message} Earlier committed investigation results were retained; inspect the attempt record for any created project or file. | Retry read;Copy error | {code}: {message} Earlier committed investigation results were retained; inspect the attempt record for any created project or file. |
| KB16 | unsupported | {feature} is not available in this build or on this system. Metadata and manual import still work. | Manual import | {feature} is not available in this build or on this system. Metadata and manual import still work. |
| KB17 | project open, no investigation | This project has no advisory context. Search a KB or CVE to attach one; applicability to these two files stays unverified until you confirm it. | Lead | This project has no advisory context. Search a KB or CVE to attach one; applicability to these two files stays unverified until you confirm it. |
| cancelled | Owned token cancelled | Investigation operation cancelled. Earlier committed results are retained. | Refresh | Investigation operation cancelled. Earlier committed results are retained. |

KB9 reason copy is the full KB§8.2 pair-reason table:IDENTICAL_CONTENT byte-identical;DELTA_ONLY completePErequired;ARCH AMD64required;CROSS_PRODUCT differentproducts;ORDER_UNVERIFIED analystorientation;DIGEST_MISMATCH no projectcreated;NO_OLDER no earlierbuild;WINDOW_CONFOUNDED other updates;SERVER_NOT_COVERED clientindexonly;NAME_MISMATCH confirmcomponent. Add source-contract NO_NEWER "No newer build of this file is listed for this product." and INDEX_GAP "The available file index has a gap around this pair. The update boundary is unverified." These are copy completions,not new facts. Every reason retains its code and raw source pointer.

## 6 Interactions

Command ids kb.* from section10. lead/search parse then local scoped lookup. import local picker+strict parse+source digest. plan_network creates finite request plan without network;copy_plan copies it. approve only E1,binds plan_sha+exact host set+requestlist+caps;cancel_plan no network. steps only visit satisfied reducer states. product_filter appends analyst choice and invalidates dependent approval;relation_filter/filter/group_filter are view-only. file_name/add_file validate basename. builds_older/builds_newer or older_file/newer_file select explicit sides;swap invalidates approvals and plan. pair_summary shows all block/confounding reasons.

create requires approved verified complete inputs and validated empty destination;it creates project then attaches context,never runs comparison automatically. retry_attach targets the already created project's exact pair,does not recreate it. refresh/retry local reads only. goto/Enter on function lead navigates current exact match;component-only lead has no code jump. copy/Ctrl+C includes scope,requested/inspected failures,source digests/pointers,relation,productmapping,both hashes,orientation,lineage/fix-boundary labels,code-run id and limitations. cve_detail source text read-only. Cancel sets only KB task token;already created project retained. Ctrl+PageUp/Down visits available steps;no global Escape override stealing main cancel.

Context menu Copy provenance,Open source details,Go to code,Refresh uses same guards. No scraped historical completeness,no silent downloads,no auto-accept product mapping or binary pair.

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; key at most 256 characters, label sanitized to 200. Pin run and revision from the row's ProjectKey. Use NavigationPort, not another panel's controller. function and match resolve through MatchIndex. More than one candidate returns ambiguous with at most 20 candidates; never choose the first. Side mismatch is a miss.

Use existing NavResult constructors and exact copy from gui/anchors.py: stale "The project changed after this link was created. Open it again from the source panel."; missing "Not found in run {run_id}: {label}." (omit the run phrase when absent); ambiguous "{n} candidates match {label}. Choose one."; blocked "{title} is unavailable: {reason}". A failed destination changes no selection or focus; only shown enters the 50-entry host history. Alt+Left/Right stay host navigation. A missing project makes any project anchor stale; projectless catalog operations use their local identity and do not enter project navigation history. Never guess an opposite side or same address in another run.


anchors_in={kb};anchors_out={function,cve,cwe,advisory_phrase}. Existing Leads owns cve and match in pilot/panel.py;KB must not add duplicate canonical cve ownership. A CVE entered into the KB field remains a local query,not a router registration. Code navigation emits function when unique;Leads view may receive cve via existing host router. SourceRef doc_id+pointer is evidence provenance,never a callback or automatic URL fetch. Stale investigation revisions disable code navigation.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Lanes kb-workspace-reader and kb-workspace-writer own their own SQLiteconnections;requests carry investigation_id/revision and optionalProjectKey. Channels kb-import,kb-search,kb-plan,kb-acquire,kb-attach,kb-leads. Import and workspace writes occur on their single writer lane;ProjectService create/attach/publish occur on project owner thread. Long file parsing/hashing outside owner callback,publication bounded and guarded. No network while building a plan. On interruption reducer records an Attempt and never resumes fetch automatically. Progress actual document/request/file counts;unknown download total staysindeterminate. Cancellation wording must match actual transport:do not promise immediate abort or deletion of committed results.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| kb/step|enum|find|find,updates,files,builds,project,leads;fallbackfind when unmet|
| kb/relation_filter|enum|all|all,vendor-remediation,vendor-association,mention-only,package-contains,analyst-asserted,disputed|

No remembered consent,lead/project contents,product assertion or targetpaths in settings. Investigation revisions hold analyst choices under existing store contract. Filter/query/sessionselection ephemeral. No geometry.

## 10 Tooltips

### `kb.dock`

Accessible name: "KB / CVE investigation panel".

What: Investigate a KB or CVE using explicitly scoped advisory evidence.

Why: Keep update,product,file,pair and code context connected.

Effect: Opening uses local saved data only.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.action`

Accessible name: "Show KB / CVE investigation".

What: Show or hide the KB/CVE investigation dock.

Why: Reach the investigation without another application window.

Effect: Toggles dock;Ctrl+Shift+K.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.lead`

Accessible name: "Investigation lead".

What: Enter a KB number or ASCII CVE identifier.

Why: Start from a specific update or advisory.

Effect: Search covers only the selected local document scope.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.search`

Accessible name: "Search local advisories".

What: Search imported advisory records for this lead.

Why: State exactly what was and was not checked.

Effect: Local query only;no network.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.import`

Accessible name: "Import advisory document".

What: Choose a saved CVRF or CSAF JSON document.

Why: Support offline investigations.

Effect: Validates and records source digest and local-file authenticity.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.plan_network`

Accessible name: "Plan advisory requests".

What: Build an exact request list for a finite advisory scope.

Why: Inspect destinations before any download.

Effect: Planning performs no DNS or network.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.steps`

Accessible name: "Investigation steps".

What: Choose Find,Updates,Files,Builds,Project or Leads.

Why: Keep prerequisite-dependent work ordered.

Effect: Unavailable steps retain a visible reason.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.docs_table`

Accessible name: "Advisory documents".

What: Read requested,inspected and unreadable advisory documents.

Why: Judge coverage before interpreting an absent result.

Effect: Read-only scope table.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.edges_table`

Accessible name: "Security updates for the lead".

What: Read KB/CVE/product relations and their source pointers.

Why: Distinguish remediation from association or a text mention.

Effect: Selection changes context only.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.product_filter`

Accessible name: "Investigation product".

What: Choose the product and architecture for this investigation.

Why: Avoid joining unrelated product records.

Effect: Appends a product-selection decision;invalidates dependent pair plans.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.relation_filter`

Accessible name: "Advisory relation filter".

What: Choose which documented relation kinds to show.

Why: Keep mention-only evidence separate from vendor remediation.

Effect: View-only filter.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.cve_detail`

Accessible name: "Advisory context details".

What: Read vendor statements,hypotheses,unknowns and provenance.

Why: Keep vendor claims distinct from observed code changes.

Effect: Plain text;no model or code execution.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.hints_table`

Accessible name: "Candidate files".

What: Read file-name hints with tier and supporting source.

Why: Choose a component without pretending the CVE names a binary.

Effect: Hints remain contextual,not a confirmed fix boundary.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.file_name`

Accessible name: "Candidate file name".

What: Enter a basename validated by the acquisition contract.

Why: Scope build lookup to one component.

Effect: No paths,shell fragments or arbitrary URLs.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.add_file`

Accessible name: "Add candidate file name".

What: Record the entered component name for this investigation.

Why: Preserve the analyst's component choice.

Effect: Appends an analyst decision;does not download.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.builds_older`

Accessible name: "Older build candidates".

What: Choose the intended older build row.

Why: Keep release orientation explicit.

Effect: Does not infer order from table position.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.builds_newer`

Accessible name: "Newer build candidates".

What: Choose the intended newer build row.

Why: Keep both identities distinct before acquisition.

Effect: Selection alone fetches nothing.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.older_file`

Accessible name: "Choose local older PE".

What: Select a complete local older PE file.

Why: Use files already held on an offline machine.

Effect: File is hashed and parsed as data,never run.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.newer_file`

Accessible name: "Choose local newer PE".

What: Select a complete local newer PE file.

Why: Complete a manually supplied comparison pair.

Effect: File is hashed and parsed as data,never run.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.swap`

Accessible name: "Swap proposed pair orientation".

What: Reverse older and newer before project creation.

Why: Correct an explicit orientation choice.

Effect: Invalidates pair approval and any download plan.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.pair_summary`

Accessible name: "Proposed pair basis".

What: Read grade,lineage,fix boundary,servicing window and reasons.

Why: Keep pairing quality separate from vulnerability claims.

Effect: GradeA/B/X is a workflow category,not probability.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.project_name`

Accessible name: "Comparison project name".

What: Name the project to be created from the approved pair.

Why: Identify the resulting comparison.

Effect: Bounded by the existing ProjectService name contract.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.project_root`

Accessible name: "Comparison project destination".

What: Choose an absent or empty local project directory.

Why: Create without overwriting another project.

Effect: Validated before creation;not a download URL.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.create`

Accessible name: "Create comparison project".

What: Create a project only from both verified complete PE inputs.

Why: Make bytes and orientation explicit before analysis.

Effect: Does not run comparison automatically;context attach is a separate recoverable step.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.approve`

Accessible name: "Approve displayed requests".

What: Authorize exactly the displayed plan's request list and hosts.

Why: Keep network consent specific to this operation.

Effect: Requires current plan_sha,host set and E1 capability;E0 cannot fetch.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.leads_table`

Accessible name: "Investigation leads".

What: Read contextual component/function leads and channel states.

Why: Inspect code evidence while retaining unknowns and disagreements.

Effect: No KEV-driven function reranking.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.group_filter`

Accessible name: "Investigation lead group".

What: Choose a CVE,unattributed or not-applicable lead group.

Why: Keep unsupported associations out of a chosen CVE's list.

Effect: View-only filter.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.goto`

Accessible name: "Open selected investigation lead".

What: Open the exact current function location for the selected lead.

Why: Read the source of a localization suggestion.

Effect: Disabled for stale,component-only,missing or ambiguous locations.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.copy`

Accessible name: "Copy investigation provenance".

What: Copy selected context with scope,source pointers and limitations.

Why: Retain the distinction between advisory facts and observations.

Effect: Clipboard only,16KiB maximum.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.retry_attach`

Accessible name: "Retry advisory context attachment".

What: Attach context to the already created matching project.

Why: Recover from context failure without recreating the project.

Effect: Rechecks both hashes,revision and investigation identity.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.refresh`

Accessible name: "Refresh investigation".

What: Reload the current investigation and attached context.

Why: Pick up saved work without performing network operations.

Effect: Reads only;no automatic acquisition or comparison.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.stale_banner`

Accessible name: "Earlier advisory context".

What: Read why context belongs to an earlier pair,run or advisory revision.

Why: Prevent stale code navigation.

Effect: Reference only;refresh or explicitly prepare new context.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.cancel`

Accessible name: "Cancel investigation operation".

What: Cancel this dock's active local or network operation.

Why: Preserve committed investigation and project state.

Effect: Owned token only;does not delete a created project.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.filter`

Accessible name: "Investigation text filter".

What: Filter currently loaded update rows by displayed text.

Why: Find a record inside the chosen scope.

Effect: View-only;at most256characters.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.copy_plan`

Accessible name: "Copy exact request plan".

What: Copy the displayed destinations,limits and plan digest.

Why: Move a finite fetch plan to another machine for offline import.

Effect: Clipboard only;no request is sent.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.cancel_plan`

Accessible name: "Cancel request plan approval".

What: Leave the plan review without contacting any host.

Why: Keep network consent and project data unchanged.

Effect: No network and no remembered approval.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.retry`

Accessible name: "Retry local investigation read".

What: Retry the failed local lookup or read.

Why: Recover without reusing network consent.

Effect: Fresh read generation only.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.copy_error`

Accessible name: "Copy investigation error".

What: Copy bounded error and attempt metadata.

Why: Share diagnostics without advisory contents or source paths.

Effect: Clipboard only.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

### `kb.row`

Accessible name: "Investigation row".

What: Read {kind}: {label},relation {relation},basis {basis}.

Why: Keep provenance and relation meaning with the row.

Effect: Escaped,bounded template.

Source: kbcorrelation/1 investigation revision,source pointers,coverage and current operation plan.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order Lead,Search,Import,Plan,stepbar,currentpagecontrols in reading order,Cancel. Each table one stop,arrows/Home/End/Page navigation. Product/architecture and pair side spoken in every candidate row. Project controls named separately. Inline exact request review initial focus Cancel,Approveafterfullrequest. Dots/colours never substitute for "index-adjacent","asserted","blocked","unknown". Existing modal helpers must be parented and injected for tests;no new appwindow.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


Lookup<=100ms at1millionedges;tablepaint<=200msafterready;noGUIcallback>100ms and shared50msmaximumtarget wins. Import32MiBdocument<=20s worker. Scope finite<=24months. Index query complexity,table100kcallceilings andsource-specificdownloadcaps are required execution gates,UNVERIFIED here.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


E0 hosts:none. E1 exact host families recorded by the source plan,reachability/paths/licences UNVERIFIED here:api.msrc.microsoft.com for approved CVRF sync;msrc.microsoft.com for approved CSAF paths;winbindex.m417z.com andmsdl.microsoft.com for fileindex/acquisition. These are separate typed transport allowlists,not permission for arbitrary paths on those hosts. NVD/CISAenrichment needs its own source operation;KBapproval cannot authorize it. Exact URLs must come from a validated plan;never construct a guessed monthly endpoint in Qt. Show method/fullURL/host/bytes+caps/why/expectedhash/plan_sha beforeApprove. Redirectornewhost not in exact approvedplan is rejected,never silently followed. No upload,targetexecution,driverinstall orautomaticDISM/PSFXhydration.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests:test_kb_kb0_to_kb17;test_kb_empty_scope_not_complete;test_kb_mention_never_remediation;test_kb_product_mapping_text_unverified;test_kb_pair_requires_two_verified_inputs;test_kb_swap_invalidates_plan;test_kb_plan_no_network;test_kb_exact_hosts_and_plan_sha;test_kb_context_pending_keeps_project;test_kb_retry_attach_does_not_recreate;test_kb_kev_no_function_rerank;test_kb_context_stale_navigation_off;test_kb_no_duplicate_cve_handler;test_kb_100k_lazy_model. ManualWindows:E0localpaircreateandattach,E1explicit-hostflowonlyaftertransportacceptance,lockedworkspace,restartinterruptedattempts,screenreaderstepnavigation.

## 15 Open questions

1. Separate KBC/KPS panels? Default one kb investigation;old patch-search/1 UI variants are annexes,not parallel stores.
2. E1ready? UNVERIFIED. Default E0only,Planreadable,Approveblockeduntiltransportandconsentgatespassed.
3. Cveanchorownership? Default existingLeadshandler;KBhandleskbonly.
4. Extra appwindows? Default none;consentinlineorapprovedparentedmodalhelper,resultsdock.
5. Advisorycontextfailureaftercreate? Default retainprojectandCONTEXTPENDING,offerRetryattach,neverclaimnothingchanged.
