# Strings panel (WB3 S7b)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

Deepen WB3 S7b. Analyst question: "Which strings differ,what coverage makes that comparison meaningful,and where can the supported links take me?" WB3-integration-plan.md owns extraction,comparison,review tiers and privacy. No guessed function ownership,no automatic FLOSS emulation,no risk score and no unredacted routine export.

## 2 Identity

strings/panel.py PANEL;ui_strings.create_panel(ctx) lazy factory proposed UNVERIFIED. id strings,title Strings,bottom,tabify_with graph,Ctrl+Shift+T,focus_order140,default_visibleFalse,requires('project',),CLAIMS_NEUTRAL with no finding/confidence claim from strings. Manifest supersedes old right/evidence placement. Full PanelController hooks. Register strings tips through PANEL,not the superseded register_entries shared-file hook.

## 3 Data contract

Pure domain names StringBasis,StringTable,StringLink,StringChange,StringsDelta,StringAnchorHit and SearchRow from WB3§7. Basis stages complete/heuristic/not-run/failed/truncated; StringChange states only-older/only-newer/both/representation-changed/edited/not-compared/indeterminate. Pairing links<=8,cues<=8,offsets<=16 per side;value display<=256escaped chars,detail window<=4KiB. Delta<=50000changes,inventory source200000rows/side until documented higher cap accepted. No per-row Pydantic allocation for columnar inventory.

strings/view_model.py required pure build_view,filter_indices,provenance_block and detail_view are proposed adapter names,actual signatures UNVERIFIED. Prepared rows carry id,value_sha256,display,type,encodings,length,status,side offsets,link tier/ambiguity,review tier,reasons,lineage,basis digest and stable order key. Exact value is a separately requested verified read,never inferred by unescaping display text. UI inventory window<=100000rows to meet framework table cap;delta<=50000. Further inventory requires an explicit narrower filter;do not silently discard source rows or pretend total coverage equals visible rows.

Comparability:static semantics equal may compare across sources;min length harmonizes to larger value;types intersect;language/emulation requires compatible tool and options;one-sided emulation is not-compared;truncation/failed stage yields indeterminate not gain/loss. Any orientation/hash/run/raw digest change is stale. L1..L6 link tier remains visible;only supported unique function/match links permit code navigation.

## 4 Layout

Source bar:source,Scan,FLOSS path,Browse,Probe,pin,Run static,Run with emulation,Cancel. Basis banner with harmonizations and Re-scan older. Filters change,type,side,cue,minlen,text,function context,scope,noise. VirtualTable columns Change20em,String50,Type16,Older22,Newer22,Function28,Cues24,Source20. Default ordinal R1..R7 then known functionRVA,casefold display,id;no average with attention. Unknown cells "Unknown: {reason}";no function "No supported function link";no offset "No file offset";source missing "Not run". Glyph+text +Only in newer,-Only in older,~Edited,=In both,?Not compared. Representation change and look-alike are explicit,never silently merged.

Detail tabs Summary/Links/Provenance. Edited shows both values as plain markers [-old-] and {+new+};look-alike lists differing code points and Unicode names. Use SafeTextView for bounded detail,not HTML. Footer shows coverage counts,basis/source identity and hidden/omitted counts. A function context chip is set by navigator selection;clearing it is an explicit action and never removes a project review. PreparedTable/ColumnSpec/TableSpec carry precomputed strings,sort/search keys,chip and accessible text.

## 5 States

Announce exact copy once;preserve retained evidence under stale/partial banners. Missing FLOSS gates FLOSS only,built-in still works. Unknown source stage never becomes no strings.

| State | Trigger | Exact on-screen copy | Remedy | Screen-reader announcement |
|---|---|---|---|---|
| no-project | No key | Open a project to compare the strings of two builds. | Host Open | Open a project to compare the strings of two builds. |
| empty | No observations | No strings have been extracted for this pair yet. The built-in scan needs no setup and reads both files without running them. | Scan both builds | No strings have been extracted for this pair yet. The built-in scan needs no setup and reads both files without running them. |
| loading | Extracting | Reading strings from the {side} build ({n} of 2)... {elapsed}. Cancel stops the operation; nothing is saved from a cancelled run. | Cancel | Reading strings from the {side} build ({n} of 2)... {elapsed}. Cancel stops the operation; nothing is saved from a cancelled run. |
| ready | Comparable differences | {n} strings differ between the older and newer build. They are listed in review order, which is a reading order and not a finding. | Copy escaped | {n} strings differ between the older and newer build. They are listed in review order, which is a reading order and not a finding. |
| ready-empty | Complete zero differences | No string differences found with these settings. Text this scan cannot extract (non-ASCII wide text, compressed or encrypted data) is not covered. | All strings | No string differences found with these settings. Text this scan cannot extract (non-ASCII wide text, compressed or encrypted data) is not covered. |
| blocked | Semantics mismatch | These two scans used different settings, so differences would be misleading: {reason}. Re-scan the older build with the newer build's settings. | Re-scan older | These two scans used different settings, so differences would be misleading: {reason}. Re-scan the older build with the newer build's settings. |
| partial | Truncated/failed stage | The {side} scan stopped at the {limit} string limit. Added and removed marks are shown as '?' because strings may be missing from that side. | Comparison basis | The {side} scan stopped at the {limit} string limit. Added and removed marks are shown as '?' because strings may be missing from that side. |
| error | Extraction failed | String extraction stopped: {code}. {message} Earlier results were not changed. | Retry read;Copy error | String extraction stopped: {code}. {message} Earlier results were not changed. |
| stale | Key changed | The project changed after these strings were loaded. Reload to see the current results. | Reload | The project changed after these strings were loaded. Reload to see the current results. |
| floss-missing | No tool | FLOSS is not set up. You do not need it for plain strings. It is only needed for stack,tight and decoded strings. | Browse;Probe | FLOSS is not set up. You do not need it for plain strings. It is only needed for stack,tight and decoded strings. |
| floss-unsupported | Probe rejects | This FLOSS build is not supported: {reason}. | Browse;Probe | This FLOSS build is not supported: {reason}. |
| cancelled | Token cancelled | Extraction cancelled. Earlier results are unchanged. | Reload | Extraction cancelled. Earlier results are unchanged. |
| too-large | Display cap | Too many strings to display ({n}). Narrow the filter or choose Differences. | Filters | Too many strings to display ({n}). Narrow the filter or choose Differences. |

Conflict:old copy names a fixed FLOSS version and says cancellation waits for current file. Use actual runner semantics and installed pin;that version's current support is UNVERIFIED here.

## 6 Interactions

Command ids match strings.* tips. source/path modify pending choice only;browse local chooser;probe explicit version/help/hash. run.builtin previews bounded scan of both hashes then confirm_run starts in-process data reads. run.floss previews static external run;run.emulation additionally requires the approved EMULATION_CONSENT text and recorded consent_sha256. rescan previews older input with newer comparable settings;never quietly rescans. cancel_preview no work;cancel active token only. filter controls change view only;Ctrl+F inside dock focuses text filter,Escape clears it before any application cancel. Table Enter opens unique supported function,else exact side raw offset;Space detail. open.function/open.hex are distinct context actions.

copy.safe/Ctrl+C copies<=200rows and16KiB escaped single-line forms with id,side,basis,hashes,link tier and provenance;label truncation explicitly. copy.exact/Ctrl+Shift+C is one-row exact-value review;controls/secret-like require confirm_exact,cancel_exact leaves clipboard;unavailable or>16KiB is refused. No silent truncation of exact text. export previews redacted records,basis,lineage and local destination;explicit choice required for sensitive exact fields and overwrite. No automatic upload. reload/retry read saved data only. Context menu Copy escaped,Copy exact,Open function,Open raw bytes,Export uses same guards.

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; key at most 256 characters, label sanitized to 200. Pin run and revision from the row's ProjectKey. Use NavigationPort, not another panel's controller. function and match resolve through MatchIndex. More than one candidate returns ambiguous with at most 20 candidates; never choose the first. Side mismatch is a miss.

Use existing NavResult constructors and exact copy from gui/anchors.py: stale "The project changed after this link was created. Open it again from the source panel."; missing "Not found in run {run_id}: {label}." (omit the run phrase when absent); ambiguous "{n} candidates match {label}. Choose one."; blocked "{title} is unavailable: {reason}". A failed destination changes no selection or focus; only shown enters the 50-entry host history. Alt+Left/Right stay host navigation. A missing project makes any project anchor stale; projectless catalog operations use their local identity and do not enter project navigation history. Never guess an opposite side or same address in another run.


anchors_in={string};anchors_out={function}. String identity is value hash plus source-side/basis identity,not display text. Incoming string anchor may select several observations;return ambiguous with candidates if no exact source key distinguishes them. Open raw uses NavigationPort.show_raw_offset(side,offset) only after current hash check;caption "Offset {offset} is in the {side} file;the other pane shows the same offset of its own file,which is a different place." Never infer a function extent from a string offset. Function context uses selection_changed and same current pairing,not text equality.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Channels strings-load,strings-scan,strings-floss,strings-probe,strings-detail,strings-export;reader lane owns columnar readers. Snapshot both basis digests and pairing digest. Static default600s,emulation3600s,adjustable through existing tool options10..86400s;external memory cap default4GiB remains UNVERIFIED platform behaviour. Poll every4MiB scan or5000rows delta. Emulation runs sequential sides and private scratch under the supervised runner. Progress side/n plus elapsed,no invented percentage. GUI parses/hashes/reads no artifacts.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| strings/scope|enum|differences|differences,all|
| strings/change|enum|changed|all,changed,only-newer,only-older,edited,both,not-compared|
| strings/side|enum|both|older,newer,both|
| strings/min_length|int|4|4..256;view floor also harmonized basis|
| strings/hide_noise|bool|false|true,false|
| strings/detail_tab|enum|summary|summary,links,provenance|

Text query,function chip,exact-copy approval,export choice and emulation consent are session-only. Types/cues default all;actual closed vocabularies from domain constants,not arbitrary persisted strings. Tool path uses existing config,not an invented key. No geometry.

## 10 Tooltips

### `strings.dock`

Accessible name: "Strings panel".

What: Compare strings with their extraction basis and supported function links.

Why: Read text changes without treating missing extraction as absence.

Effect: Opening reads stored observations only.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.action`

Accessible name: "Show Strings".

What: Show or hide the Strings panel.

Why: Reach string comparison from the keyboard.

Effect: Toggles the dock;Ctrl+Shift+T.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.table`

Accessible name: "Strings table".

What: Read change, text, type, side locations, functions, cues and source.

Why: Keep each string difference tied to its basis.

Effect: Enter opens the supported function or exact raw offset.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.source`

Accessible name: "String source".

What: Choose built-in scan or configured FLOSS processing.

Why: Make extraction semantics explicit.

Effect: Selection starts no scan.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.path`

Accessible name: "FLOSS path".

What: Choose an absolute path to an installed FLOSS executable.

Why: Record the exact tool that would parse inputs.

Effect: Stored only through existing tool configuration after probe.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.pin`

Accessible name: "FLOSS pin status".

What: Read the installed FLOSS identity relative to the accepted pin.

Why: Distinguish tested, untested and unsupported builds.

Effect: Read-only; never implies tool compatibility without a probe.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.run.builtin`

Accessible name: "Scan both builds".

What: Read plain ASCII and supported UTF-16LE strings from both project copies.

Why: Obtain a baseline without an external tool.

Effect: Explicit local scan; targets are never executed.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.run.floss`

Accessible name: "Read with FLOSS".

What: Preview static FLOSS processing of both project copies.

Why: Inspect language-aware strings using a named tool basis.

Effect: No emulation without its separate confirmation;no network.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.run.emulation`

Accessible name: "Run FLOSS with emulation".

What: Review exact emulation semantics and limits before processing.

Why: Make instruction interpretation explicit to the analyst.

Effect: Opens operation-specific consent with Cancel focused.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.cancel`

Accessible name: "Cancel string extraction".

What: Cancel this panel's extraction or load.

Why: Stop processing while preserving committed results.

Effect: No cancelled run becomes a completed comparison.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.probe`

Accessible name: "Probe FLOSS".

What: Explicitly check the selected executable identity and help.

Why: Know whether the configured tool supports the requested mode.

Effect: Version/help only;never either target.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.browse`

Accessible name: "Browse for FLOSS".

What: Choose a locally installed FLOSS executable.

Why: Configure a tool without automatic download.

Effect: Injected local file chooser only.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.basis`

Accessible name: "Comparison basis".

What: Read harmonized settings, missing stages and source identities.

Why: Understand when two extractions are comparable.

Effect: Read-only;unknown coverage never creates an absent mark.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.detail`

Accessible name: "String detail".

What: Read summary, links and provenance for the selected string.

Why: Judge link quality and representation differences.

Effect: Plain text with bounded exact-value window.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.rescan`

Accessible name: "Re-scan older with newer settings".

What: Preview a rescan using the newer side's comparable settings.

Why: Repair a basis mismatch explicitly.

Effect: Requires current files and exact settings preview;no automatic run.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.copy.safe`

Accessible name: "Copy escaped string text".

What: Copy escaped single-line string forms and provenance.

Why: Keep controls and secrets out of routine clipboard output.

Effect: At most200rows and16KiB;redacted by default.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.copy.exact`

Accessible name: "Copy exact string text".

What: Review and copy the original value of one selected string.

Why: Access the original text when escaped display is insufficient.

Effect: Requires confirmation for controls or secret-like values;never labels truncated text exact.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.open.function`

Accessible name: "Open linked string function".

What: Open the exact supported function link for this string.

Why: Read code only when a defensible link exists.

Effect: Disabled for stale,ambiguous or file-level-only observations.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.open.hex`

Accessible name: "Open string in raw bytes".

What: Show the selected side's recorded raw byte offset.

Why: Inspect the actual encoded bytes.

Effect: Requires supported file offset;the other pane shows its own bytes at that offset.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.export`

Accessible name: "Export strings".

What: Preview and save redacted string records with provenance.

Why: Retain basis and lineage in a local artifact.

Effect: No upload;explicit overwrite choice;exact values off by default.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.retry`

Accessible name: "Retry string read".

What: Retry a failed stored-data read.

Why: Recover without silently repeating extraction.

Effect: New local load generation only.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.reload`

Accessible name: "Reload strings".

What: Load current stored string observations.

Why: Refresh after a project or tool-basis change.

Effect: No external scan starts.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.copy_error`

Accessible name: "Copy string error".

What: Copy bounded string error metadata.

Why: Share a diagnostic without raw values or paths.

Effect: Clipboard only.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.confirm_run`

Accessible name: "Confirm string operation".

What: Start exactly the displayed local extraction request.

Why: Bind processing to both hashes and extraction settings.

Effect: Rechecks tool,input and request identity before starting.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.cancel_preview`

Accessible name: "Cancel string operation preview".

What: Close the extraction preview without processing.

Why: Keep stored observations and local state unchanged.

Effect: No process,scan or network.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.confirm_exact`

Accessible name: "Confirm exact string copy".

What: Copy the exact displayed string value.

Why: Make sensitive clipboard content an explicit choice.

Effect: One selection only;disabled above16KiB or when exact data is unavailable.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.cancel_exact`

Accessible name: "Cancel exact string copy".

What: Leave exact-copy review without copying.

Why: Keep the clipboard unchanged.

Effect: No copy.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.tabs`

Accessible name: "String detail views".

What: Choose Summary, Links or Provenance.

Why: Separate interpretation from link basis and source identity.

Effect: Local view change only.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.change`

Accessible name: "String change column".

What: Compare only supported presence or edit states.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.string`

Accessible name: "String string column".

What: Read the escaped or redacted display value.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.type`

Accessible name: "String type column".

What: Read the extraction type and encoding.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.older`

Accessible name: "String older column".

What: Read older offsets or the reason they are unknown.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.newer`

Accessible name: "String newer column".

What: Read newer offsets or the reason they are unknown.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.function`

Accessible name: "String function column".

What: Read supported links and ambiguity.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.cues`

Accessible name: "String cues column".

What: Read descriptive cue labels, not a score.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.col.source`

Accessible name: "String source column".

What: Read extraction source and basis.

Why: Keep the column meaning with its value.

Effect: Read-only column header.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.change`

Accessible name: "Change filter".

What: Choose differences or a specific string change state.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;all,changed,only-newer,only-older,edited,both,not-compared.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.type`

Accessible name: "Type filter".

What: Choose the extraction types whose comparable coverage is available.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;static,language,stack,tight,decoded.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.side`

Accessible name: "Side filter".

What: Choose older,newer or both.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;older,newer,both.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.cue`

Accessible name: "Cue filter".

What: Choose a descriptive cue assigned by the pure model.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;closed cue vocabulary.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.minlen`

Accessible name: "Minimum length".

What: Set a minimum length at or above the harmonized basis.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;4 to256 for view filtering.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.text`

Accessible name: "Text filter".

What: Filter escaped display text locally.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;at most256characters.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.scope`

Accessible name: "Scope".

What: Choose Differences or All strings.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;differences,all.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.filter.noise`

Accessible name: "Hide noise-like strings".

What: Hide rows classified noise-like while showing the hidden count.

Why: Narrow the visible inventory without changing observations.

Effect: View-only;default off.

Source: StringBasis,StringsDelta,selected StringChange and recorded extraction provenance.

### `strings.function_context`

Accessible name: "Function string context".

What: Read the current function constraint or clear it.

Why: Keep string rows scoped to the selected function only when requested.

Effect: Clear removes the local constraint;no evidence changes.

Source: Current ProjectKey and function selection.

### `strings.clear_function`

Accessible name: "Clear function string constraint".

What: Show strings without the current function constraint.

Why: Return from a function-scoped list to the chosen inventory.

Effect: View-only;selected row is kept if still visible.

Source: String view options.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order source,path,Browse,Probe,Scan,Run static,Run emulation,Cancel,change,type,side,cue,minlen,text,function context,clear function,scope,noise,table,tabs,detail,Open function,Open raw,Copy escaped,Copy exact,Export. Columns each have their own col.* tooltip. Row speech "{change}. {type} string,{length}characters. Older {older};newer {newer};function {function};link {tier};basis {basis}". Non-printing values are described as escaped control names,not spoken as active formatting. Preview Cancel first.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


Load both sides200000rows each<=4s/400MiB;delta<=1s. Model reset100000rows<=300ms,filter+sort<=400ms,first paint40x8cells<=50ms. GUI memory for two200000-source tables<=250MiB while only capped prepared view is materialized. Columns no ResizeToContents;no per-row widgets. Exact-value detail read<=4KiB window;copy exact cap16KiB. Larger source remains in columnar cache,not silently upgraded display cap.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts:none. No automatic tool download. FLOSS emulation is interpretation in a model,not native target execution;approved consent must state actual engine semantics,skipped imports,limits and residual cap support based on current tool manifest. The old plan's runtime/Python/version statements are UNVERIFIED here,never hard-code them as current. Secret-like values redacted in display,routine copy and export. A URL found inside a string never becomes a browser action. Exact-copy confirmation shows the exact selected value and side/provenance;no persisted consent.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests:test_strings_all_states;test_strings_minlen_harmonizes;test_strings_partial_stage_indeterminate;test_strings_one_side_emulation_not_compared;test_strings_semantics_mismatch_blocks;test_strings_display_escape_not_pattern_bytes;test_strings_lookalike_codepoints;test_strings_exact_copy_refuses_truncated;test_strings_secret_redaction_all_routine_paths;test_strings_raw_offset_caption_both_sides;test_strings_ambiguous_link_never_jumps;test_strings_inventory100k_cap_explicit;test_strings_generation_basis_guard;test_strings_no_emulation_on_open;test_strings_100k_lazy_model. Manual extra:FLOSS probe/runtime pin,blocked-network emulation,Windows child exit classification and EDR,all UNVERIFIED.

## 15 Open questions

1. Source cap400000rows? Default keep200000until WB3 S0 acceptance;display still framework100000maximum and delta50000.
2. Strings claims profile? Default neutral to allow exact domain vocabulary such as Copy safe in legacy ids;the visible label is Copy escaped,not a safety claim.
3. Store exact-copy consent? Default never;one operation only.
4. Infer edit from similar strings? Default only the documented pure algorithm and basis,with explicit Edited reasons;not a Qt similarity guess.
5. Function link absent? Default file-level evidence with raw offset when supported,not a guessed containing function.
