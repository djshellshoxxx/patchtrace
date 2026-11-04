# Search panel (WB1 S7)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

Deepen WB1 S7 project search. Analyst question: "Where does this stored name,text or identifier occur,and which sources were actually searched?" Source WB1-integration-plan.md. Search is a read/index layer over saved evidence,not a new analysis engine. Exact identities,suggestions,grouped counterpart expansion and coverage remain separate. No claim of absence from a binary from no results.

## 2 Identity

search/panel.py PANEL;lazy ui_search.create_panel(ctx) factory proposed UNVERIFIED. id search,title Search,bottom,no tab group,Ctrl+Shift+F,focus_order120,default_visibleFalse,requires('project',),CLAIMS_NEUTRAL plus no false completeness/confidence claims. Full PanelController hooks. The legacy MainWindow.global_search naming is not a panel dependency. Never claim Ctrl+F globally;the host/pane owns that key.

## 3 Data contract

Pure names WB1§7: QueryPlan(search-query/1),SearchRequest,Evidence,Reason,Locator,Presence,PairExpansion,SearchHit,CoverageEntry,SearchResult(search/1),SavedSearch(search-saved/1). parse_query is the sole grammar entry;canonical plan digest binds requests. text<=256,terms<=8,excludes<=4,page1..200,suggestions<=12,hit evidence<=6 plus evidence_total,title<=200,snippet<=300,reasons detail<=80,GUI rows<=5000,candidate cap20000. Presence older/newer present/absent/unknown with basis;raw added string never proves opposite-side absence.

search/view_model.py (proposed path/callable signatures UNVERIFIED) must project ResultRowView(hit_id,side,kind,match_text,where_text,change_text,why_text,search_text,locator,order_key) as frozen slotted values. build_result_rows,build_detail,coverage_rows and copy_lead are required pure adapter operations;reuse existing equivalents. Search service/index readers expose query,suggest,coverage,build_missing,resolve_locator and saved-plan read/write through their domain interfaces;do not invent direct Qt-to-SQL access. PairExpansion resolves live per page and preserves all counterparts. A matching instruction hash is never assembly text.

Ordering tuple remains categorical/ordinal as specified: tier,change_class,negative independent components,current attention rank or missing,table_id,nativeBM25 inside that table,title,side,RVA,doc id. Never average BM25 across source tables or engines. Search modes auto/words/exact/prefix/substring/similar;scope indexed/changed. Unsupported syntax fails with a hint,never raw SQL or model-generated query. Segment digest pins schema/tokenizer/source identity;corrupt cache is rebuilt,not evidence loss.

## 4 Layout

Query with clear control and named suggestion popup;side group Both/Older/Newer;Kinds menu;Scope/Mode/Sort;Save/Saved/Rebuild/Coverage;StateView/progress;feature-owned paged SearchResultsModel;detail;Go to code/Other side/Copy. Table columns Side10em,Kind14,Match36,Where26,Change20,Why40. Default service relevance order;header sort reissues query with sort key,never sorts only loaded pages. Empty side "Not side-specific";location "No code location";change "Unknown";why "Reason unavailable". Model canFetchMore/fetchMore requests one cursor page with index_key+generation;append only matching pages. New generation resets once;retain selection by hit_id only if present.

VirtualTable's ordinary full PreparedTable is not used to materialize unbounded results. Feature-owned paged model uses the same ColumnSpec text/accessibility semantics and lazy-model gate. Display at most5000rows,200/page;no merging/cell widgets. Detail headers Result;Why it ranks here;Pair;Change facts;Provenance;Limitations. HitDelegate bold+underline bounded spans on original display text,no HTML. Folding that changes length produces no guessed highlight.

Suggestions use <=12structured entries:name,RVA,side,category plus Locator payload. Qt popup does not refilter an already prepared list. Empty focused query can list session recent queries;an empty submitted query does not browse everything unless a supported kind/is filter explicitly requests it. Save page has name and exact interpreted plan with Cancel/Save. Coverage rows Group20em,Side10,Status18,Documents12,Basis32 with explicit missing/truncated reasons.

## 5 States

Each announcement is the exact copy below once;Q2 progress is throttled,terminal count announced politely. Complete zero results requires every requested coverage group indexed;partial zero results must use Q6. Q11 is a source note,not a global failure when other text is searchable.

| State | Trigger | Exact on-screen copy | Remedy | Screen-reader announcement |
|---|---|---|---|---|
| Q0/no-project | No key | Open a project to search it. | Host Open | Open a project to search it. |
| Q1/empty | No index | Not indexed yet. Search reads only this project's saved data;nothing is uploaded. | Build index | Not indexed yet. Search reads only this project's saved data;nothing is uploaded. |
| Q2/loading | Index build | Indexing {group} ({done} of {total} groups). You can already search what is indexed. | Cancel | Indexing {group} ({done} of {total} groups). You can already search what is indexed. |
| Q3/idle | Empty query | Search names,strings,APIs,code,notes and advisories. Use quotes for an exact phrase and -word to exclude. | Query | Search names,strings,APIs,code,notes and advisories. Use quotes for an exact phrase and -word to exclude. |
| Q4/ready | Hits | {n} leads for '{q}' in {scope}. Showing {k}. | Go to location | {n} leads for '{q}' in {scope}. Showing {k}. |
| Q5/empty | No hits,complete requested coverage | No results for '{q}' in what is indexed ({coverage}). This does not show the text is absent from the binary. | Coverage | No results for '{q}' in what is indexed ({coverage}). This does not show the text is absent from the binary. |
| Q6/partial | No hits,incomplete coverage | No results yet,but the index is partial: {missing}. | Coverage;Build index | No results yet,but the index is partial: {missing}. |
| Q7/partial | Candidate cap | More than 20,000 matches for '{q}'. Showing the first 200 in index order,not ranked. Add a word,choose a kind or side,or use a phrase. | Query | More than 20,000 matches for '{q}'. Showing the first 200 in index order,not ranked. Add a word,choose a kind or side,or use a phrase. |
| Q8/stale | Segment basis differs | The project changed after this index was built ({what}). Results are for reference;opening one is checked against the current project. | Update index | The project changed after this index was built ({what}). Results are for reference;opening one is checked against the current project. |
| Q9/unsupported | FTS5 missing | Full-text search is unavailable in this build (SQLite FTS5 missing). The navigator filter still works. | Navigator | Full-text search is unavailable in this build (SQLite FTS5 missing). The navigator filter still works. |
| Q10/error | Query/read failure | Search failed: {code}: {message}. Your project was not changed. | Retry;Copy details | Search failed: {code}: {message}. Your project was not changed. |
| Q11/partial | No instruction text | Instruction text is not searchable:Ghidriff keeps only a hash of each function's instructions. Run unified extraction to add it. | Coverage | Instruction text is not searchable:Ghidriff keeps only a hash of each function's instructions. Run unified extraction to add it. |
| query-invalid | Parser refuses query | Search query is invalid: {reason}. {hint} | Query | Search query is invalid: {reason}. {hint} |
| display-cap | 5000rows retained | Showing the first 5,000. Refine the search. | Query | Showing the first 5,000. Refine the search. |
| cancelled | Token cancelled | Cancelled. Earlier results are unchanged. | Query | Cancelled. Earlier results are unchanged. |

## 6 Interactions

Commands match search.* tips. query typing debounces250ms;Enter submits immediately after parse_query;IME composition must not submit incomplete input. side/kinds/scope/mode/sort reissue current parsed request. search.build/rebuild/update-index build derived segments only,no tools or network;Cancel interrupts owned query/build. Coverage displays every requested source with counts and reason. search.retry reruns current query under new key;copy_error copies sanitized code,index identity and operation class,not raw source/query secrets.

Table Enter/double-click/goto activates exact locator;Space detail;Ctrl+C/copy copies title,locator,both applicable hashes,run/revision,source digest/coverage,rank reasons and limits. Other side opens only unique current counterpart;split/merge shows candidate choice. F3/Shift+F3 move and open next/previous lead in the same current result order,requesting next page only under current cursor. Down in query enters suggestions or table. Suggestion activated[QModelIndex] uses its Locator payload,never relooks up duplicate name. Enter with no highlighted suggestion submits normal query.

Escape is handled by ShortcutOverride:close popup,else clear query,else return focus to code. It never cancels the main job. Save opens name/plan form;confirm_save appends create record,cancel_save no write. Saved reruns plan against current data;delete_saved appends tombstone. Context menu Go to location,Show other side,Copy result,Save query,Delete selected saved search uses identical guards. No delete index/evidence shortcut. If navigator filters are cleared to show an exact match,announce "Navigator filters cleared to show the selected search result."

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; key at most 256 characters, label sanitized to 200. Pin run and revision from the row's ProjectKey. Use NavigationPort, not another panel's controller. function and match resolve through MatchIndex. More than one candidate returns ambiguous with at most 20 candidates; never choose the first. Side mismatch is a miss.

Use existing NavResult constructors and exact copy from gui/anchors.py: stale "The project changed after this link was created. Open it again from the source panel."; missing "Not found in run {run_id}: {label}." (omit the run phrase when absent); ambiguous "{n} candidates match {label}. Choose one."; blocked "{title} is unavailable: {reason}". A failed destination changes no selection or focus; only shown enters the 50-entry host history. Alt+Left/Right stay host navigation. A missing project makes any project anchor stale; projectless catalog operations use their local identity and do not enter project navigation history. Never guess an opposite side or same address in another run.


anchors_in={} to avoid claiming kinds owned by feature panels/code host;anchors_out={function,string,import,capability,rule,build_fact,advisory_phrase,cve,kb,cwe} only for Locator schemes with validated conversions. Note/finding/export/pe-field have no identical AnchorRef kind;do not invent a new enum or coerce export to import. Default show read-only detail and blocked navigation until the owning adapter supplies a supported existing route. Locator resolution checks current excerpt hash/line range before reveal_lines;stale text cannot jump into current code. Address is side+artifact-specific,not cross-build identity.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Persistent search-reader lane creates/closes read-only SQLite segment connections on that thread;latest-only coalesced query/suggestion requests interrupt superseded queries. search-builder lane writes staging segments under its cache ownership and atomically publishes digest-named files;never replace an open connection's file. Channels search-query,search-suggest,search-build,search-detail;generation includes plan digest,index_key,ProjectKey and sort. A cursor from another index is refused,never reused.

First project open does no indexing. First search use builds cheap-first sources and exposes completed coverage;later project changes schedule only missing digests after first use. Pause nonessential building when main analysis busy;explicit search may use ready segments. Check cancel every4096docs;query deadline2s,build600s/segment,total1800s. Progress groups actual done/total only. Suggestions debounce80ms,query250ms;no background timer while hidden.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| search/side|enum|both|older,newer,both|
| search/scope|enum|indexed|indexed,changed|
| search/mode|enum|auto|auto,words,exact,prefix,substring,similar|
| search/sort|enum|relevance|relevance,change,name,address|
| search/recent|tuple[str,...]|empty|<=20queries,each<=256characters|

Recent queries can contain sensitive analyst text;default empty and store only upon explicit submitted query under existing recent-query policy. No credentials or source snippets. Kinds default all available;unsupported groups remain coverage entries. Saved plans are project analyst data,not QSettings or cache. No geometry.

## 10 Tooltips

### `search.dock`

Accessible name: "Search panel".

What: Search this project's saved evidence with coverage and provenance.

Why: Find a useful place to inspect without claiming the binary is fully indexed.

Effect: Opening starts local indexing only after first use;no upload.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.action`

Accessible name: "Show Search".

What: Show or hide the project Search panel.

Why: Reach project search from the keyboard.

Effect: Shows dock and focuses query;Ctrl+Shift+F.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.query`

Accessible name: "Search query".

What: Enter words,phrases or supported identifiers to search saved project data.

Why: Find named functions,text and context in one place.

Effect: At most256characters;Enter submits;typing waits250ms.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.side`

Accessible name: "Search side".

What: Choose both,older or newer evidence.

Why: Keep search orientation explicit.

Effect: Reissues the query with the chosen side.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.kinds`

Accessible name: "Search kinds".

What: Choose which evidence kinds to search.

Why: Narrow scope while retaining coverage for omitted sources.

Effect: Enumerated filters only;no implicit tool run.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.scope`

Accessible name: "Search scope".

What: Choose indexed data or changed-function context.

Why: Know which stored records are being searched.

Effect: Scope changes rerun the plan;not a completeness claim.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.mode`

Accessible name: "Search mode".

What: Choose automatic,word,exact,prefix,substring or similar-name mode.

Why: Control how the query is interpreted.

Effect: The interpreted plan is shown;regular expressions are unsupported.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.sort`

Accessible name: "Search sort order".

What: Choose relevance,change,name or address order.

Why: Make reading order explicit across pages.

Effect: Server-side requery;never a local partial-page sort.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.save`

Accessible name: "Save current search".

What: Name and save the current query plan.

Why: Repeat an investigation without saving stale results.

Effect: Appends a saved-plan record;name1 to64characters.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.saved`

Accessible name: "Saved searches".

What: Choose a saved plan to rerun or mark deleted.

Why: Keep reusable analyst queries apart from disposable cache.

Effect: Reruns against current data;deletion is an append-only tombstone.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.rebuild`

Accessible name: "Rebuild search index".

What: Rebuild derived search segments for current project sources.

Why: Recover from stale or missing cache data.

Effect: Local derived cache only;does not delete project evidence.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.coverage`

Accessible name: "Search coverage".

What: Read which evidence groups are indexed,missing,partial or unavailable.

Why: Understand what a zero-result query can establish.

Effect: Shows local coverage without running missing analysis tools.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.table`

Accessible name: "Search results".

What: Read side,kind,match,location,change and ranking explanation.

Why: Inspect the evidence behind each search lead.

Effect: Pages up to200;GUI retains at most5000rows.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.detail`

Accessible name: "Selected result details".

What: Read result,ordering reasons,pair,change facts,provenance and limits.

Why: Judge why a row appears before navigating.

Effect: Plain text;no inferred missing code.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.goto`

Accessible name: "Go to selected search location".

What: Open the exact current location of the selected result.

Why: Read its supported code or context.

Effect: Disabled when stale,missing,ambiguous or unhandled.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.other_side`

Accessible name: "Show search result counterpart".

What: Open the uniquely supported counterpart on the other side.

Why: Compare matching evidence across the oriented pair.

Effect: Never picks the first split,merge or ambiguous candidate.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.copy`

Accessible name: "Copy search result with provenance".

What: Copy the selected lead's evidence and coverage.

Why: Keep source and limitations attached to the text.

Effect: Clipboard only,16KiB maximum;secret redaction preserved.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.suggestions`

Accessible name: "Search suggestions".

What: Choose an exact named suggestion with its side and location.

Why: Distinguish duplicate names before activation.

Effect: At most12rows;selection carries a Locator,not display-name lookup.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.cancel`

Accessible name: "Cancel search work".

What: Cancel this panel's query or segment build.

Why: Stop local work without cancelling the main comparison.

Effect: Sets the owned token and interrupts the reader.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.retry`

Accessible name: "Retry search query".

What: Retry the last failed query against current stored data.

Why: Recover without changing project evidence.

Effect: Fresh generation and identity check.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.copy_error`

Accessible name: "Copy search error details".

What: Copy bounded search diagnostics.

Why: Share the query failure without raw source text.

Effect: Clipboard only;no paths,credentials or target content.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.build`

Accessible name: "Build search index".

What: Build missing derived segments after first use.

Why: Make saved source text searchable locally.

Effect: No network or analysis tool execution.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.status`

Accessible name: "Search status".

What: Read interpreted query,result count and coverage.

Why: Keep partial or broad results distinct from ranked complete results.

Effect: Status completion announced once.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.save_name`

Accessible name: "Saved search name".

What: Enter a name for the current search plan.

Why: Identify a reusable query later.

Effect: Required1 to64characters;stored as data.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.confirm_save`

Accessible name: "Save named search plan".

What: Store the displayed current query plan under its name.

Why: Make analyst-data persistence explicit.

Effect: Appends create record;never stores result rows.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.cancel_save`

Accessible name: "Cancel saving search".

What: Leave the save form without a new record.

Why: Keep saved-search history unchanged.

Effect: No write.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.delete_saved`

Accessible name: "Delete selected saved search".

What: Mark the selected saved plan deleted.

Why: Remove it from normal lists without erasing history.

Effect: Appends a tombstone;does not delete evidence or cache.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.row`

Accessible name: "Search result row".

What: Read {kind} in {side}: {title};{where};{change};{why}.

Why: Hear the result without relying on highlight colour.

Effect: Escaped,bounded template.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.suggestion`

Accessible name: "Search suggestion row".

What: Read suggested name {name},side {side},location {where},category {category}.

Why: Identify the exact suggestion before activation.

Effect: Escaped template;activation uses its stored Locator.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.coverage_row`

Accessible name: "Search coverage row".

What: Read group {group},side {side}: {status},documents {docs},reason {reason}.

Why: Keep unknown coverage separate from absent matches.

Effect: Read-only escaped template.

Source: QueryPlan,SearchResult,CoverageEntry and the digest-pinned source segment.

### `search.clear_query`

Accessible name: "Clear Search query".

What: Clear the current query text and its results.

Why: Start a new search without keeping an earlier plan active.

Effect: Cancels the owned query generation;no project change.

Source: Search controller query state.

### `search.coverage_table`

Accessible name: "Search source coverage".

What: Read source groups with their indexed and unavailable states.

Why: Understand which saved evidence a search can cover.

Effect: Read-only;no analysis or network.

Source: CoverageEntry records.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order query,clear,side,kinds,scope,mode,sort,Save,Saved,Rebuild,Coverage,Cancel,table,detail,Go to location,Other side,Copy. Suggestions popup gets its own name and search.suggestions identifier even though it is not a child under ordinary tooltip enumeration;include it explicitly in audit roots. Side group has one composite stop with arrows among Both/Older/Newer. Coverage table speaks reason with status. Query interpreted_as and result total/partialness are announced after completion,not every keystroke.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


First paint<=200ms;data() calls<=3times visible cells (stricter than shared gate). Keystroke-to-first-page<=250ms with a stub ready service. Query p95<=50ms/100000names,<=250ms/1millionstrings under candidate cap;too-broad detection<=25ms;suggestions100000unique names<=100ms;popup refresh<=50ms. Event-loop latency p95<=100ms during build;worker RSS<=300MiB. Segments<=64 and768MiB/project;global derived cache4GiB;1millionstrings build<=20s/250MB,100000function names<=15s plus code0.1s/MB. All budgets UNVERIFIED execution gates. GUI never accumulates more than5000hit rows.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts:none. FTS queries are compiled from parse_query's closed grammar with parameterized SQL,never pasted MATCH syntax or regex. No arbitrary SQL,extension loading or network source completion. Segment files untrusted:validate application_id0x50545331,user_version1,contract/digests and expected group before read;do not open attacker-selected database paths from a hit. Advisory/code/notes remain untrusted text. Secret-redacted tool strings stay redacted in index,completion,detail,copy and save previews. Saved search stores plan only,not result rows. No cross-project index reuse without an explicit valid source key.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests:test_search_q0_q11;test_search_no_results_requires_complete_coverage;test_search_empty_query_not_everything;test_search_parser_no_raw_match_or_sql;test_search_duplicate_suggestion_locator;test_search_ime_no_partial_submit;test_search_escape_never_cancels_main_job;test_search_fetchmore_cursor_generation_guard;test_search_sort_requeries_all_pages;test_search_5000_cap;test_search_other_side_ambiguous;test_search_stale_excerpt_refuses_reveal;test_search_saved_plan_tombstone;test_search_no_secret_in_index_or_copy;test_search_connections_open_close_lane;test_search_no_qt_in_domain;test_search_100k_service_lazy_model. Manual extra:IME on Windows,NVDA completion popup,large-table speech,frozen SQLite FTS5/tokenizer availability,all UNVERIFIED.

## 15 Open questions

1. Generic Locator-to-AnchorRef for note/finding/export? Default no guessed mapping;detail-only until a typed supported route exists.
2. Similar-name suggestions as evidence? Default separate suggestions,never a fuzzy function identity or extra independent support.
3. Empty query browsing? Default only explicit supported kind/is filter;otherwise Q3.
4. Recent-query privacy? Default existing local policy with no source text or credentials;allow disabling storage in a future settings contract rather than inventing one here.
5. Missing assembly? Default coverage unavailable;instruction hash never becomes fabricated assembly.
6. Shared VirtualTable vs paged model? Default feature-owned paged model passing shared gates;do not load every hit to fit a widget API.
