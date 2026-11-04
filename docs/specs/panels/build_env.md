# Build environment panel and pre-flight banner (DIE D5)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

DIE D5 deepens BuildEnvCard and PreflightBanner and moves the card into the reserved build_env dock. Analyst question: "Do build facts, packaging or managed-code limits change how I should read this comparison?" Source: DIE-integration-plan.md sections7–11. This is a display-time overlay, never a new unified evidence atom, score or stored verdict.

## 2 Identity

PANEL in buildenv/panel.py; factory ui_build_env.create_panel(ctx) (proposed adapter, runtime UNVERIFIED). id build_env; title "Build environment"; right; tabify_with evidence; Ctrl+Shift+B; focus_order160; default_visibleFalse; requires('project',); CLAIMS_NEUTRAL, with no inference of source fixes from build context. All PanelController hooks apply. Manifest wins over the plan's interim area=none card: use one dock instance; its notice contribution is posted through ShellPort.notice. No second registration for the same id. The preliminary comparison UI may focus the dock; no new dialog implementation is specified here.

## 3 Data contract

Pure domain inputs from DIE7: BuildFingerprint, BuildEnvDelta, BuildFact, BuildChange, PreflightWarning, NoiseReason and BuildFactAnchor. BuildFact value<=200/version<=120; facts<=128, changes<=128, preflight<=16, options_changed<=8, noise<=4, anomalies<=16. Certainty exact-field/derived/signature/heuristic/unknown. Toolchain same/differs/unknown. Header-only or heuristic-only differences produce unknown. Opposing strong channels stay conflicting; count correlated linker-header/signature evidence once.

buildenv/view_model.py owns BuildEnvViewModel(state,state_text,banners,rows,summary,provenance,technical), build_view, banner_views and provenance_block<=8KiB as named in the plan (runtime signatures UNVERIFIED). Frozen view rows carry key, older_text,newer_text,status,basis,anchors and order key; no Qt. Reads through VerifiedArtifactReader; stored build-env rows are strict build-environment/1, at most64KiB, and additive only. Read tool-run/tool-evidence, never mutate them. Delta recomputed, not persisted. No new contract is introduced by the panel.

Overlay qualifies only current same-orientation review rows, all delta classes in noise-map/1, no omitted deltas/limits and toolchain differs. Shape-only classes may order; cfg/block-added/block-removed tag only. Constants, conditions, comparisons, callees, calls, data/string/struct refs and unknown never receive this noise treatment. Stable partition inside materiality groups only; options context cannot change verdict or result_key.

## 4 Layout

StateView; NoticeStrip contribution; BuildEnvCard; VirtualTable with precomputed ColumnSpec/TableSpec/PreparedTable; SafeTextView technical detail; Copy/Read again/Read with Detect It Easy/Set up. Columns Fact24em, OLDER26em, NEWER26em, Status18em, Basis32em. Default order changed,one-sided-unknown,unchanged then fact key; empty values "Unknown: {reason}", source "Source unavailable". No fact filter in v1; weak hints are a collapsible detail region. Group-last is an overlay option in the consuming unified view; build_env owns its setting and semantics. Timeline is a series contribution, not another dock.

Preflight exact notice templates:

| Code | Copy |
|---|---|
| packed-signature | [!] Caution: {SIDE} looks packed ({name}, matched by signature). Function-level results may be incomplete or misleading for this file. PatchTrace does not unpack files. |
| packed-hint | [!] Caution: {SIDE} may be packed (hint: {hint}). Hints from section layout or entropy can be wrong. Function-level results may be incomplete. |
| packed-low-hint | [i] Notice: {SIDE} may be packed (hint: {hint}). Hints from section layout or entropy can be wrong. |
| packed-one-side | [!] Caution: only {SIDE} looks packed. Comparing a packed file with an unpacked one does not show source changes. |
| protected | [!] Caution: {SIDE} shows signs of a protector or obfuscator ({name}, matched by signature). Results may be incomplete or misleading. |
| managed-only | [!] Caution: {SIDE} is a .NET assembly with managed code only. PatchTrace compares native x64 code, so function results will be empty or misleading. |
| managed-mixed | [i] Notice: {SIDE} is a .NET image that also holds native code. Only the native part is compared. |
| installer | [i] Notice: {SIDE} looks like an installer or self-extracting archive ({name}). The program code may be inside its payload, which is not analyzed. |
| overlay-large | [i] Notice: {SIDE} has {size} of data after its last section. That data is not analyzed. |
| toolchain | [i] Notice: the toolchain differs between OLDER and NEWER ({short}). Some code differences may come from the build, not from source edits. |
| tool-unavailable | [i] Notice: Detect It Easy is not set up, so only PatchTrace's own checks ran. |
| heuristic-only | [i] Notice: {n} weak hints on {SIDE} were found and are not used as evidence. |
| sources-disagree | [i] Notice: build sources disagree for {SIDE}. The conflicting observations are shown separately; the toolchain result is unknown. |
| stale-evidence | [i] Notice: stored build evidence is stale and is shown for reference only. |

Last two are explicit copy completions for codes already in DIE7. Keep every warning accessible in detail; coalesce the workspace strip without silently dropping warnings.

## 5 States

Each state announcement repeats the exact on-screen copy once through ctx.announce. Facts may remain visible under a limitation banner. Error precedes stale, partial and ready; no project removes actionable anchors.

| State | Trigger | Exact on-screen copy | Remedy button | Screen-reader announcement |
|---|---|---|---|---|
| B0/no-project | No project | Open a project to see the build environment. | Host Open | Open a project to see the build environment. |
| B1/loading | PE/stored read | Reading build environment: {side} ({done} of {total})... | Cancel | Reading build environment: {side} ({done} of {total})... |
| B2/partial | DiE absent | Detect It Easy is not set up. Showing the checks PatchTrace makes itself (headers, Rich header, sections, imports). Names of compilers, packers and protectors need Detect It Easy. | Set up | Detect It Easy is not set up. Showing the checks PatchTrace makes itself (headers, Rich header, sections, imports). Names of compilers, packers and protectors need Detect It Easy. |
| B3/ready | Strong comparable facts equal | No toolchain change detected between OLDER and NEWER. Compiler options such as the optimization level cannot be read from a file, so code can still differ without source edits. | Technical details | No toolchain change detected between OLDER and NEWER. Compiler options such as the optimization level cannot be read from a file, so code can still differ without source edits. |
| B4/ready | Strong difference without opposite strong channel | Toolchain differs between OLDER and NEWER: {summary}. Some code differences can come from the build rather than from source edits. Matching rows are marked 'Build differs'; none are hidden. | Technical details | Toolchain differs between OLDER and NEWER: {summary}. Some code differences can come from the build rather than from source edits. Matching rows are marked 'Build differs'; none are hidden. |
| B5/partial | No comparable strong facts | The toolchain could not be compared: {reason}. Unknown is not treated as a difference. | Technical details | The toolchain could not be compared: {reason}. Unknown is not treated as a difference. |
| B6/partial | One side unreadable | Build environment is incomplete for {side}: {reason}. The other side is shown. | Read again | Build environment is incomplete for {side}: {reason}. The other side is shown. |
| B7/stale | Pair/tool basis changed | These build-environment results belong to a different file or tool setup and are shown for reference only. | Read again | These build-environment results belong to a different file or tool setup and are shown for reference only. |
| B8/error | Read failed | Build environment could not be read ({code}). Earlier results are unchanged. | Retry; Copy details | Build environment could not be read ({code}). Earlier results are unchanged. |
| B9/unsupported | DiE version unsupported | This Detect It Easy build is not supported by this PatchTrace installation. Showing the checks PatchTrace makes itself. | Set up | This Detect It Easy build is not supported by this PatchTrace installation. Showing the checks PatchTrace makes itself. |
| cancelled | Cancelled token | Cancelled. Earlier results are unchanged. | Read again | Cancelled. Earlier results are unchanged. |

## 6 Interactions

All actions use build_env.* matching section10. action toggles dock. reread refreshes PE and saved tool facts; retry retries reads; cancel cancels owned task. read_die constructs exact local preview of both full hashes, paths, executable/version/full digest, database identity, argv, timeout120s, output/depth/memory policy and no-network status. confirm runs the unchanged preview; cancel_preview does nothing. setup chooses/probes installed console tool only, no download. table Enter focuses technical row; Ctrl+C/copy copies chosen row or full card with pair hashes, facts, certainty, source refs and tool/database identities. Copy never collapses conflicting sources. banner_details focuses the dock's matching fact; banner_dismiss only dismisses scope/text-specific notice. group_last changes stable display partition without stored result edits. timeline Enter focuses that build's fact detail and does not compare nonadjacent builds. Context menu: Copy details, Show technical basis, Read again; no execute/unpack action.

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; key at most 256 characters, label sanitized to 200. Pin run and revision from the row's ProjectKey. Use NavigationPort, not another panel's controller. function and match resolve through MatchIndex. More than one candidate returns ambiguous with at most 20 candidates; never choose the first. Side mismatch is a miss.

Use existing NavResult constructors and exact copy from gui/anchors.py: stale "The project changed after this link was created. Open it again from the source panel."; missing "Not found in run {run_id}: {label}." (omit the run phrase when absent); ambiguous "{n} candidates match {label}. Choose one."; blocked "{title} is unavailable: {reason}". A failed destination changes no selection or focus; only shown enters the 50-entry host history. Alt+Left/Right stay host navigation. A missing project makes any project anchor stale; projectless catalog operations use their local identity and do not enter project navigation history. Never guess an opposite side or same address in another run.


anchors_in={build_fact}; anchors_out=empty. Resolve BuildFactAnchor by artifact hash, fact key, value and source, with explicit side; the fabric converter's key is not the same as its local anchor_id. Do not derive an anchor from rendered text. Unsupported source/identity returns not-found. selection_changed highlights related facts only if current overlay basis exists.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Channels build_env-read, build_env-die, build_env-detail; lane build_env-reader owns file readers. PE progress B1; optional DiE progress "Reading with Detect It Easy: {side} ({n} of 2)..." with indeterminate stage. Extra PE reads<=100KiB/side, parse<=2s/side. Optional DiE reads sequentially via supervised tool runner, timeout120s/stdout1MiB/stderr256KiB/depth8/detections512. Do not auto-run at project_changed or comparison start. Post notice only after current-generation validation; remove old project-scope notices on switch.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| build_env/group_last | bool | false | true,false |
| build_env/technical | bool | false | true,false |

No auto_diec or confirm_before_run setting enables work in v1: earlier plan buildenv/* auto settings are deferred and the canonical prefix is build_env/. Notice dismissal is host-owned by scope/key/text. No geometry, target paths or raw observations in settings. Setup tool identity uses the existing external-tools configuration contract, not a new unverified key.

## 10 Tooltips

### `build_env.card`

Accessible name: "Build environment".

What: Read compiler, linker, runtime and packaging signs from both files.

Why: Build differences can explain changes without source edits.

Effect: Read-only; targets are never executed.

Source: Hash-checked PE facts and stored DiE observations.

### `build_env.dock`

Accessible name: "Build environment panel".

What: Inspect build facts and pre-flight cautions for the current pair.

Why: Keep the basis of code comparisons visible.

Effect: Opening reads stored data and PE facts only.

Source: BuildEnvDelta and fingerprints.

### `build_env.action`

Accessible name: "Show Build environment".

What: Show or hide the Build environment panel.

Why: Reach the card from the keyboard.

Effect: Toggles the dock; Ctrl+Shift+B.

Source: Panel registry.

### `build_env.status`

Accessible name: "Build comparison status".

What: Read whether the toolchain is same, differs or unknown.

Why: Keep absence distinct from a toolchain change.

Effect: Read-only summary; no score.

Source: BuildEnvDelta.toolchain and reasons.

### `build_env.table`

Accessible name: "Build environment facts for the older and newer file".

What: Read each fact with older value, newer value and its source.

Why: Distinguish exact fields, signatures and weak hints.

Effect: Enter focuses technical detail; selection changes no evidence.

Source: BuildFact and BuildChange.

### `build_env.banner`

Accessible name: "Build environment notice".

What: Read the current pre-flight limitation and its affected side.

Why: Know when function results may be incomplete.

Effect: Nonmodal notice; never blocks comparison by itself.

Source: PreflightWarning.

### `build_env.banner_details`

Accessible name: "Show build notice details".

What: Open the basis and limitations of this notice.

Why: Inspect why a caution appeared.

Effect: Focuses this dock's detail without opening another window.

Source: PreflightWarning.basis.

### `build_env.banner_dismiss`

Accessible name: "Dismiss build notice".

What: Dismiss this notice for its current scope.

Why: Reduce repeated notices without deleting facts.

Effect: Returns when project scope or notice text changes.

Source: NoticeModel scope and key.

### `build_env.setup`

Accessible name: "Set up Detect It Easy".

What: Choose and explicitly probe an installed DiE console program.

Why: Add signature names to header facts.

Effect: No download; probe runs version/help only.

Source: Tool probe and installed pin metadata.

### `build_env.read_die`

Accessible name: "Read with Detect It Easy".

What: Preview a local DiE read of older and newer project copies.

Why: Add optional signature observations with a recorded basis.

Effect: Starts only after confirming the exact local request; no network.

Source: Tool manifest and verified input hashes.

### `build_env.weak_hints`

Accessible name: "Weak build hints".

What: Show hints excluded from strong toolchain comparison.

Why: Keep low-certainty observations inspectable.

Effect: Read-only; hints do not become a strong verdict.

Source: BuildFact.certainty and anomalies.

### `build_env.copy`

Accessible name: "Copy build details".

What: Copy selected build facts and their provenance.

Why: Preserve the distinction between fields and inferred labels.

Effect: Clipboard only, at most 8 KiB.

Source: Current BuildEnvViewModel.

### `build_env.technical`

Accessible name: "Build technical details".

What: Read raw field names, source references and limits.

Why: Audit how the displayed fact was derived.

Effect: Plain text; no target or script execution.

Source: PeBuildFacts, DieSummary and anomalies.

### `build_env.reread`

Accessible name: "Read build facts again".

What: Refresh hash-checked PE facts and stored DiE evidence.

Why: Replace a stale display with current observations.

Effect: No external tool run; earlier records remain unchanged on failure.

Source: buildenv reader and current ProjectKey.

### `build_env.group_last`

Accessible name: "Group build-tagged rows last".

What: Move eligible build-tagged rows later within their materiality group.

Why: Read potential source edits before build-shape changes.

Effect: Default off; stable partition, no hidden row or verdict change.

Source: noise-map/1 and BuildEnvDelta.

### `build_env.timeline`

Accessible name: "Build environment across builds".

What: Read build fact families across at most eight adjacent builds.

Why: See where recorded build context changed.

Effect: No non-adjacent inference; missing cells remain unknown.

Source: BuildEnvReader and series snapshots.

### `build_env.cancel`

Accessible name: "Cancel build read".

What: Cancel the active build facts or DiE operation.

Why: Stop processing while retaining committed facts.

Effect: Cancels only the owned token and supervised child.

Source: TaskRunner.

### `build_env.retry`

Accessible name: "Retry build read".

What: Retry the failed PE or stored-evidence read.

Why: Recover from a transient failure.

Effect: Does not repeat an external tool run automatically.

Source: Previous local read request.

### `build_env.copy_error`

Accessible name: "Copy build read error".

What: Copy bounded build-read diagnostics.

Why: Share an actionable error without file contents.

Effect: Clipboard only; no raw stderr or paths.

Source: Sanitized PT-BUILD or PT-TOOL error.

### `build_env.confirm`

Accessible name: "Confirm DiE read".

What: Run exactly the local DiE operation shown in the preview.

Why: Bind the operation to known inputs and tool identity.

Effect: Rechecks hashes and tool identity; no network.

Source: Local operation request.

### `build_env.cancel_preview`

Accessible name: "Cancel DiE preview".

What: Close the preview without running DiE.

Why: Keep existing evidence unchanged.

Effect: Starts no process and sends nothing.

Source: Local preview.

### `build_env.row`

Accessible name: "Build fact row".

What: Read {key}: older {older}, newer {newer}, basis {basis}.

Why: Keep side and source with the value.

Effect: Read-only template.

Source: BuildChange and BuildFact.

### `build_env.tag`

Accessible name: "Build difference tag".

What: Read build context for change classes {classes}.

Why: Understand why the row receives a build-context annotation.

Effect: Verdict and stored result are unchanged; nothing is hidden.

Source: noise-map/1 eligibility result.

### `build_env.timeline_cell`

Accessible name: "Build timeline cell".

What: Read build {build}: {fact}, {value}, source {source}.

Why: Keep missing values and tool changes explicit across builds.

Effect: Read-only template.

Source: TimelineView cell provenance.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order: card heading, facts table, technical toggle, technical detail, Copy, Read again, Read with Detect It Easy, Set up, Cancel. Workspace notices: Details then Dismiss. Row speech: "{fact}; older {older}; newer {newer}; {status}; basis {basis}". Timelines speak build ordinal,label,side,fact,unknown/not-run reason and source. Dismiss announces "Build notice dismissed." once; detail remains reachable. Do not put the host-owned unified.build_section tooltip under build_env's extra prefix: unified owns that tip and its integration owner supplies it.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


Card paint<=100ms after prepared data. Overlay<=50ms at100000 rows with 5x CI timing slack; no data() calls to the provider. At most128 fact rows,16 notices,8 timeline builds. Rich region<=64KiB/1024 entries; debug entries<=16. Report<=64KiB; copy<=8KiB. Typical DiE time and Windows memory behaviour UNVERIFIED; deadline is enforced regardless.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts: none. DiE must run with the existing offline runner policy; Windows Wintrust/Crypt32 network behaviour is UNVERIFIED in the source plan and requires blocked-network live acceptance. Until that gate proves isolation, expose stored evidence and PE facts and block local DiE processing when the runner cannot guarantee no network. Do not load DiE or its Qt libraries into the GUI. No unpacking, unreviewed database download, script evaluation in PatchTrace or in-process die-python. Source-plan DiE release/version/licence/database claims are UNVERIFIED here; runtime pin validation supplies display facts.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests: test_build_env_b0_to_b9; test_build_env_notice_all_codes; test_build_env_header_only_is_unknown; test_build_env_conflicting_sources_kept; test_build_env_same_origin_counted_once; test_build_env_group_last_preserves_materiality_and_verdict; test_build_env_semantic_delta_never_tagged; test_build_env_overlay_key_unchanged; test_build_env_swap_rejects_old_notices; test_build_env_dismiss_scope_text_change; test_build_env_open_never_runs_die; test_build_env_preview_tool_change_invalidates; test_build_env_100k_overlay; test_build_env_no_automatic_network. Manual extra: signed synthetic/local test input under blocked-network DiE execution, controlled EDR behaviour and per-tool DLL separation.

## 15 Open questions

1. Card or dock? Default reserved dock with embedded card; the same controller contributes a ShellPort notice. The old area=none phase is superseded.
2. Automatic DiE? Default off and no enabling setting before the documented value gate.
3. Unsupported isolation? Default PE facts/stored evidence only; do not silently run a network-capable tool.
4. Optimization inference? Default never infer it from header or signature labels.
5. Timeline scope? Default adjacent builds only, at most8; tool-identity mismatch says "tool versions differ".
6. Additional unified tooltip ownership? Default consumer owns unified.build_section; shared-file change is an integrator ask, never an extra prefix claimed by build_env.
