# Detection rules panel (YARA-X R6b)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

YARA-X R6b presents R6a pure candidate/view services. Analyst question: "Can this reviewed code change yield a pattern that separates these builds, and what did tests actually observe?" Source: YRX-integration-plan.md. A pattern match says the file contains a pattern; it cannot classify affected/fixed software. No generic scanner, arbitrary rule editor, automatic acceptance or automatic export.

## 2 Identity

rules/panel.py PANEL; lazy factory ui_rules.create_panel(ctx) (adapter signature UNVERIFIED). id rules,title "Detection rules",right,no tab group,Ctrl+Shift+R,focus_order170,default_visibleFalse,requires('project',),CLAIMS_NEUTRAL with the footer invariant. Engine and idle gates apply only to actions, preserving readable saved versions. Actual manifest supersedes the plan's evidence tab group and temporary C6 ui.py seam. All PanelController hooks apply; no panel-owned dock creation or tooltip registry edit.

## 3 Data contract

Existing plan contracts yara-rules/1: PairSource, RuleCandidate, RuleDecision, RuleVersion, Gate, EngineStamp, TargetRef, CellResult, MatrixRun, ExportRecord. Identity includes project/revision/run/both hashes/match. RuleVersion immutable; new revision is a new version. Gate ids elig,len,wild,uniq,sep,compile,secret,dist; states pass/fail/unknown/waived. Raw CellResult hit/no-hit/not-scanned/timeout/error and expectation verdict as-expected/unexpected-hit/unexpected-miss/unscored remain separate.

Pure modules rules/view.py and panel_service.py per R6a; exact existing call signatures UNVERIFIED. Required adapter operations: read candidates/versions/history, propose, revise included features, decide, prepare targets, test, preview export, export. Proposed pure functions build_candidates_view, build_grid_view, build_saved_view may only be added if equivalents are absent. Frozen view carries current key, selected candidate/version, precomputed rows/checks, read-only text and provenance. Row labels<=200; detail<=4000; rule text<=64KiB (dedicated bounded plain editor, not SafeTextView's4000-character cap). Candidate<=3/direction,200/run; versions<=50/lineage; source function<=64KiB; targets series8+extra64+clean2000; rules<=50; cells<=105000; file<=128MiB,total<=8GiB. Larger matrix uses the existing hash-checked sidecar contract, not a new UI schema.

Feature toggles retain source side and rerun all checks; missing other-side tool evidence is unknown. Byte windows require verified pdata/IR extent; packed/protected blocks bytes. Capabilities alone cannot form a matching condition. String bytes are reread from verified artifact offsets; escaped display text never seeds a pattern. Do not modify these algorithm rules from Qt.

## 4 Layout

State strip and pair label; Propose/Cancel; tabs Candidates/Test grid/Saved rules. Candidates: list; feature table; checks; read-only monospace rule text; Copy/Accept/Reject/Defer/Open pair. Features columns Include8em,Kind14,Feature40,Older build18,Newer build18,Source24,Where16; empty "Unknown: {reason}", absent only with completed coverage. Checks columns Check30,State12,Measured24,Basis40. Candidate default order direction then candidate_id; gate order elig,len,wild,uniq,sep,compile,secret,dist.

Grid VirtualTable has fixed build identity columns Build8em,Label24,Role16,Expectation20,Advisory says24 plus one version column20em each. PreparedTable columns change atomically with generation. Hard105000-cell cap is lower than100000-row framework cap; use the lower applicable bound. Empty "Not scanned: {reason}". No expectation "No expectation". Defaults series ordinal then target_id, versions ascending. Filters role/state/unexpected-only; unknown remains visible by default. Saved list columns Label28,Version10,Test state30,Created24; no deletion. Feature-owned small list/tree allowed; large flat models use VirtualTable.

Footer: "A match means the file contains this pattern. It does not show whether the file is affected by a flaw. No match does not show that it is unaffected. Counts are raw numbers, not scores." Acceptance and export forms are inline dock pages with Cancel first. Existing modal forms, if retained by implementation, must be parented and pass the same test contract; runtime presentation is UNVERIFIED. No additional application window.

## 5 States

Announce the exact state copy once. Saved rows remain readable in blocked state. Unknown, partial or cancelled test cells cannot be displayed as No match.

| State | Trigger | Exact on-screen copy | Remedy | Screen-reader announcement |
|---|---|---|---|---|
| R0/no-project | No project | Open a project to work with detection rules. | Host Open | Open a project to work with detection rules. |
| R1/blocked | Engine/decoder missing | The rule engine (YARA-X) is not available in this installation. Rules cannot be proposed or tested. Saved rules stay readable. | Saved rules | The rule engine (YARA-X) is not available in this installation. Rules cannot be proposed or tested. Saved rules stay readable. |
| R2/empty | No accepted pair | Select a function pair you have accepted. Rules are only proposed for pairs you have reviewed. | Navigator | Select a function pair you have accepted. Rules are only proposed for pairs you have reviewed. |
| R3/empty | No candidates | No rules proposed for this pair yet. Choose Propose rules. Nothing is generated or saved until you ask. | Propose rules | No rules proposed for this pair yet. Choose Propose rules. Nothing is generated or saved until you ask. |
| R4/loading | Proposing | Proposing rules from the selected pair... | Cancel | Proposing rules from the selected pair... |
| R4/testing | Testing | Testing {n} rules against {m} files. Files that cannot be read are reported as Not scanned, never as No match. | Cancel | Testing {n} rules against {m} files. Files that cannot be read are reported as Not scanned, never as No match. |
| R5/empty | No candidate passes | No rule passed the checks for this pair: {first_check}. Bytes are unavailable when the function size is not known (leaf functions without exception data). | Open pair | No rule passed the checks for this pair: {first_check}. Bytes are unavailable when the function size is not known (leaf functions without exception data). |
| R6/stale | Old analysis/engine | These rules describe an earlier analysis or engine version ({reason}). Test again before relying on them. | Test | These rules describe an earlier analysis or engine version ({reason}). Test again before relying on them. |
| R7/error | Operation failed | Rule work could not finish: {code}: {message}. Saved rules are unchanged. | Retry read; Copy details | Rule work could not finish: {code}: {message}. Saved rules are unchanged. |
| R8/too-large | Target/cell cap | Too many files or cells ({n}). Narrow the folder or the build list. | Targets | Too many files or cells ({n}). Narrow the folder or the build list. |
| ready | Current data | Rule results loaded. Review features and checks before accepting or exporting. | Candidates | Rule results loaded. Review features and checks before accepting or exporting. |
| cancelled | Token cancelled | Cancelled. Earlier results are unchanged. | Candidates | Cancelled. Earlier results are unchanged. |

Cell copy: Match; No match; Not scanned: file is larger than the limit/file could not be read/not a PE image/file changed while reading/run was cancelled; Timed out; Error. Gate labels: Change reviewed as material; Long enough; Not mostly wildcards; Appears in one place in its own build; Does not appear in the other build; Compiles with YARA-X; No secret-looking strings; Builds share one toolchain.

## 6 Interactions

Command ids match rules.* in section10. propose snapshots the accepted current pair; if materiality is not established, explicit confirmation records analyst_confirmed_material and unvetted, never an engine assertion. features toggles create a candidate revision and rerun checks. accept opens label/CVE/KB/CWE/note form; confirm_accept appends decision/version; cancel_accept writes nothing. reject/defer/archive append decisions; no Delete key. candidates/saved/history change view only. open_pair and Enter navigate exact pair; Ctrl+Enter opens Accept only when eligible. copy_text and Ctrl+C copy exact generated text only if<=16KiB; larger output is refused with "Rule text exceeds the clipboard limit. Use Export." Do not truncate something labelled exact.

series/extra/clean choose explicit local targets; targets preview lists basenames/full hashes/roles/expectations/limits. run_test starts only the displayed plan; cancel terminates its supervised child. grid selection opens cell evidence/offsets; no expectation auto-derived from a CVE. export opens exact text/path/version/checklist preview; include_names off. export_warnings may acknowledge informational gaps only. allow_git required for a Git working tree destination. confirm_export writes atomically after identity/gate recheck and explicit overwrite choice; cancel_export writes nothing. Export hard gates compile,separation,secret,integrity cannot be waived. retry redoes reads only, never silently reruns tests. copy_error excludes raw stderr/paths.

Context menu exposes Open source pair, Copy rule text, Accept, Reject, Defer, History and Export with the same enabled conditions. Acceptance does not export. Export does not upload. Required export warning: "The rule contains byte patterns copied from the analysed files. If those files are third-party software, check its licence before sharing the rule or committing it to a repository."

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; key at most 256 characters, label sanitized to 200. Pin run and revision from the row's ProjectKey. Use NavigationPort, not another panel's controller. function and match resolve through MatchIndex. More than one candidate returns ambiguous with at most 20 candidates; never choose the first. Side mismatch is a miss.

Use existing NavResult constructors and exact copy from gui/anchors.py: stale "The project changed after this link was created. Open it again from the source panel."; missing "Not found in run {run_id}: {label}." (omit the run phrase when absent); ambiguous "{n} candidates match {label}. Choose one."; blocked "{title} is unavailable: {reason}". A failed destination changes no selection or focus; only shown enters the 50-entry host history. Alt+Left/Right stay host navigation. A missing project makes any project anchor stale; projectless catalog operations use their local identity and do not enter project navigation history. Never guess an opposite side or same address in another run.


anchors_in={rule}; anchors_out={function,string,import,capability,build_fact}. Resolve rule by immutable version/candidate id and source identity, not display name. Open pair uses function anchors to avoid competing with Leads' match handler. Origin capabilities/string evidence keeps its original lineage; rule derivation is not independent evidence. A test match offset belongs to that target hash; do not jump into the active pair unless its exact side hash matches.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Channels rules-read,rules-propose,rules-revise,rules-test,rules-export; one mutation lane per project serializes decision/version/test publication. Engine/decoder native work stays in the existing capped worker; parent GUI never imports yara_x or iced_x86. Target deadline default30s(range5..300),run wall1h,memory1GiB(hard max2GiB),stderr8KiB. Export file write and project export record are separate outcomes: report a successfully saved file even if recording its ExportRecord later fails; never claim no file was written. Progress "Testing {done} of {total} files..." only with actual counts.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| rules/tab | enum | candidates | candidates,grid,saved |
| rules/grid_role | enum | all | all,older-anchor,newer-anchor,series,extra,clean,control |
| rules/grid_state | enum | all | all,hit,no-hit,not-scanned,timeout,error |
| rules/unexpected_only | bool | false | true,false |
| rules/timeout | int seconds |30|5..300|

include_names, allow_git, warning acknowledgements, target folder paths, analyst metadata and candidate features are session/project-operation state, never remembered as export consent. No rule text or bytes in QSettings. No geometry.

## 10 Tooltips

### `rules.dock`

Accessible name: "Detection rules panel".

What: Review proposed and saved detection rules for a reviewed change.

Why: Keep rule derivation beside its source evidence.

Effect: Opening does not generate, test or export a rule.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.action`

Accessible name: "Show Detection rules".

What: Show or hide the Detection rules panel.

Why: Reach rule review from the keyboard.

Effect: Toggles the dock; Ctrl+Shift+R.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.pair`

Accessible name: "Rule source function pair".

What: Read the selected accepted pair and its materiality basis.

Why: Know exactly which change can seed a rule.

Effect: Read-only; unresolved or stale pairs cannot seed rules.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.propose`

Accessible name: "Propose rules".

What: Generate candidates from the selected reviewed function pair.

Why: Turn a reviewed observation into a bounded pattern proposal.

Effect: Requires accepted pair and materiality or explicit material confirmation; no export.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.cancel`

Accessible name: "Cancel rule work".

What: Cancel this panel's proposal or test operation.

Why: Stop the child process while keeping saved versions.

Effect: Cancels only the owned token; never marks unscanned files No match.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.candidates`

Accessible name: "Proposed rules for the selected function pair".

What: Choose a proposed rule and read its features and checks.

Why: Review evidence before accepting anything.

Effect: Selection changes detail only.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.features`

Accessible name: "Features of the selected rule, older and newer build".

What: Include eligible source-side features in the candidate.

Why: Control which exact observations support the rule.

Effect: A toggle creates a new checked candidate revision; no free-text rule editing.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.checks`

Accessible name: "Rule checks".

What: Read the measured result of every candidate gate.

Why: See why acceptance or export is blocked.

Effect: Pass, fail, unknown and waived remain distinct; unknown hard gates block.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.rule_text`

Accessible name: "Generated rule text, read-only".

What: Read the exact generated rule text.

Why: Inspect the output before accepting or copying it.

Effect: Plain text only; not executed by selecting it.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.copy_text`

Accessible name: "Copy generated rule text".

What: Copy exactly the generated text of the selected rule.

Why: Inspect or retain the pattern locally.

Effect: Clipboard only, 16 KiB cap; refused when exact text cannot fit.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.accept`

Accessible name: "Accept the selected rule and give it a label".

What: Review a label and save an immutable accepted rule version.

Why: Separate analyst acceptance from generation and export.

Effect: Opens the inline acceptance form; requires passing hard gates.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.reject`

Accessible name: "Reject selected candidate".

What: Record rejection of this candidate.

Why: Keep the analyst decision without deleting its source.

Effect: Appends a rejection decision; does not remove history.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.defer`

Accessible name: "Defer selected candidate".

What: Record that this candidate needs later review.

Why: Keep unresolved work distinct from rejection.

Effect: Appends a defer decision.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.archive`

Accessible name: "Archive selected rule lineage".

What: Archive the selected saved rule lineage.

Why: Remove inactive work from the default view while retaining history.

Effect: Appends an archive decision; no delete.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.open_pair`

Accessible name: "Open rule source function pair".

What: Show the exact older and newer functions used by this rule.

Why: Inspect the source of the pattern.

Effect: Disabled when the pair is stale, missing or ambiguous.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.grid`

Accessible name: "Rule test grid, builds by rules".

What: Read per-file results and expectations for each rule version.

Why: Keep missed scans and unexpected matches visible.

Effect: Raw cell states only, never an aggregate confidence score.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.targets`

Accessible name: "Rule test targets".

What: Read the chosen builds, extra files and clean controls.

Why: Know which hashes and roles will be tested.

Effect: No implicit directory scan; selection alone starts nothing.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.series`

Accessible name: "Choose rule test series".

What: Choose a local series with at most eight builds.

Why: Test across explicitly oriented adjacent builds.

Effect: Adds targets to the pending plan only.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.extra`

Accessible name: "Choose extra test files".

What: Choose at most 64 local extra files.

Why: Extend testing with explicit file identities.

Effect: Files are read as data and never executed.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.clean`

Accessible name: "Choose clean control files".

What: Choose a local clean-control folder for bounded enumeration.

Why: Measure unintended matches on an explicit control set.

Effect: At most 2000 regular files; no recursive surprises or target execution.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.run_test`

Accessible name: "Test selected rule versions".

What: Preview and run selected rules on the listed file hashes.

Why: Check separation and expectations before exporting.

Effect: At most50 rules and105000 cells; unscanned remains unknown.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.export`

Accessible name: "Export accepted rule".

What: Review the checklist and save a local .yar file.

Why: Separate local sharing output from analyst acceptance.

Effect: No upload; hard gates cannot be overridden.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.include_names`

Accessible name: "Include function names".

What: Include function names in the exported rule metadata.

Why: Control symbol-derived information in the output.

Effect: Default off; only affects the exact export preview.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.saved`

Accessible name: "Saved rule versions".

What: Read project-local accepted lineages and immutable versions.

Why: Keep older tested versions available.

Effect: Selection changes no decision.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.history`

Accessible name: "Rule decision history".

What: Read proposals, decisions, versions and test records in order.

Why: Audit how a rule changed.

Effect: Read-only append-only history.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.stale_banner`

Accessible name: "Earlier rule basis".

What: Read why this rule or grid uses an older analysis or engine.

Why: Avoid treating old tests as current evidence.

Effect: Retains the old view and enables an explicit retest.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.retry`

Accessible name: "Retry rule read".

What: Retry the last failed local read.

Why: Recover without silently repeating generation or export.

Effect: A failed test requires a fresh explicit Run test.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.copy_error`

Accessible name: "Copy rule error details".

What: Copy bounded rule error metadata.

Why: Share an actionable failure without raw paths or bytes.

Effect: Clipboard only.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.tabs`

Accessible name: "Detection rule views".

What: Choose Candidates, Test grid or Saved rules.

Why: Keep each stage of rule work distinct.

Effect: Switching tabs starts no work.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.label`

Accessible name: "Accepted rule label".

What: Enter the analyst label for the accepted rule.

Why: Keep analyst intent separate from machine evidence.

Effect: Required1 to120 characters; stored as data.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.cve`

Accessible name: "Rule advisory CVE IDs".

What: Enter optional CVE identifiers supplied by the analyst.

Why: Attach context without claiming the rule checks a CVE.

Effect: Validated ASCII identifiers; context metadata only.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.kb`

Accessible name: "Rule advisory KB IDs".

What: Enter optional KB identifiers supplied by the analyst.

Why: Record the update context for later review.

Effect: Validated identifiers; not an affected-build test.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.cwe`

Accessible name: "Rule advisory CWE IDs".

What: Enter optional CWE identifiers supplied by the analyst.

Why: Record weakness context separately from the pattern.

Effect: Validated identifiers; not a vulnerability verdict.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.note`

Accessible name: "Rule analyst note".

What: Enter an optional analyst statement.

Why: Preserve the reason for a decision.

Effect: Stored as escaped text with analyst provenance.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.confirm_accept`

Accessible name: "Accept rule version".

What: Save this reviewed candidate as an immutable rule version.

Why: Make acceptance explicit after reading the checks.

Effect: Stores locally; does not export or publish.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.cancel_accept`

Accessible name: "Cancel rule acceptance".

What: Leave acceptance without saving a decision.

Why: Keep the candidate unchanged.

Effect: No write.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.export_warnings`

Accessible name: "Export with displayed warnings".

What: Acknowledge the informational warnings in this export preview.

Why: Make missing testing context visible before output.

Effect: Cannot waive compilation, separation, integrity or secret gates.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.allow_git`

Accessible name: "Allow export inside Git tree".

What: Acknowledge saving byte-derived patterns inside a Git working tree.

Why: Make repository publication risk an explicit local choice.

Effect: Required only for a Git-tree destination; no automatic commit.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.confirm_export`

Accessible name: "Save displayed rule export".

What: Save exactly the previewed accepted version to the chosen local path.

Why: Bind output to the version, options and checklist reviewed.

Effect: Atomic write; no overwrite without an explicit overwrite decision.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.cancel_export`

Accessible name: "Cancel rule export".

What: Close the export preview without writing.

Why: Keep filesystem and project export history unchanged.

Effect: No file write and no upload.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.feature`

Accessible name: "Rule feature".

What: Read {kind}: {value}, source side {side}, state {state}.

Why: Keep source, side and uncertainty with the feature.

Effect: Read-only escaped template.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.cell`

Accessible name: "Rule test cell".

What: Read build {build}, rule {rule}: {state}, expectation {expectation}.

Why: Hear both observation and expected result.

Effect: Read-only template; unscanned never becomes No match.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.row`

Accessible name: "Rule row".

What: Read {rule}, state {state}, source pair {pair}.

Why: Identify the rule and its basis independently of colour.

Effect: Read-only escaped template.

Source: Stored yara-rules/1 records, engine stamp and current reviewed pair; upstream engine versions/licences UNVERIFIED here.

### `rules.grid_role`

Accessible name: "Rule grid role filter".

What: Filter test rows by target role.

Why: Read controls or build rows separately.

Effect: View-only filter; defaults to all.

Source: Rules pure view model and current operation.

### `rules.grid_state`

Accessible name: "Rule grid state filter".

What: Filter test rows by observed engine state.

Why: Find unscanned files without misreading them as misses.

Effect: View-only filter; defaults to all.

Source: Rules pure view model and current operation.

### `rules.unexpected_only`

Accessible name: "Unexpected rule results only".

What: Show cells whose observed result differs from the stated expectation.

Why: Inspect contradictions before export.

Effect: View-only filter; unchecked includes all.

Source: Rules pure view model and current operation.

### `rules.detail`

Accessible name: "Selected rule test details".

What: Read the selected candidate or test cell basis and provenance.

Why: Inspect exact hashes, offsets and limitations.

Effect: Read-only plain text.

Source: Rules pure view model and current operation.

### `rules.confirm_material`

Accessible name: "Confirm reviewed material change".

What: Record the analyst's explicit materiality confirmation for this pair.

Why: Keep analyst judgment distinct from engine evidence.

Effect: Creates an unvetted proposal basis; does not change the engine verdict.

Source: Rules pure view model and current operation.

### `rules.cancel_material`

Accessible name: "Cancel materiality confirmation".

What: Leave the materiality prompt without proposing a rule.

Why: Keep existing evidence and decisions unchanged.

Effect: No new candidate.

Source: Rules pure view model and current operation.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order Candidates: Propose,Cancel,tabs,candidates,features,checks,rule_text,Copy,Accept,Reject,Defer,Open pair. Grid: targets,series,extra,clean,Run test,Cancel,role,state,unexpected-only,grid,detail. Saved: saved,Export,Archive,History. Each filter is named by its header; section10's targets tooltip applies to its composite. Acceptance: label,CVE,KB,CWE,note,Cancel,Accept. Export: request text,include_names,export_warnings,allow_git,Cancel,Save. Grid speech "Build {ordinal} of {total}, {label}, rule {rule}: {state}, {expectation}". A source name that resembles markup remains literal.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


Proposal<=3s excluding worker startup; an8-build x20-rule grid target<=10s for20MB synthetic files (UNVERIFIED, not a universal throughput claim). First paint<=200ms; sort/filter<=150ms. Large grids<=105000cells. Enforce callback50ms maximum. Preserve stable target/version selection after column swap.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts:none. No network in engine worker; includes disabled, fixed grammar only; target reads remain data, never executed. No free-form generated commands. Do not call system Graphviz or external shell. Local export preview includes all outgoing bytes, target path and names option. Microsoft-derived pattern exports are never committed by this task. Upstream YARA-X/decoder version and licence claims in YRX are UNVERIFIED here and must be read from validated engine stamps and notices. Respect the existing export repo guard and exact local destination policy.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests: test_rules_r0_to_r8; test_rules_no_accepted_pair_blocks_propose; test_rules_feature_toggle_rechecks_gates; test_rules_unknown_hard_gate_blocks; test_rules_accept_never_exports; test_rules_export_never_accepts; test_rules_no_match_requires_completed_scan; test_rules_cancel_cells_not_scanned; test_rules_grid_dynamic_columns_keep_selection; test_rules_rule_text_64k_plain; test_rules_exact_clipboard_refuses_oversize; test_rules_untrusted_label_cannot_change_grammar; test_rules_source_hash_changed_rejects_export; test_rules_export_git_ack_specific; test_rules_native_imports_child_only; test_rules_append_only_history; test_rules_timeout_kills_child_tree. Manual extra: frozen child scan, native module notices, EDR, local-only Tier W test results and clean-set interpretation.

## 15 Open questions

1. Free-text editing? Default no; revise included features only and regenerate through the pure serializer.
2. Missing byte extent? Default bytes unavailable, never guess a contiguous function body.
3. Shared widgets? Default VirtualTable for grid, feature-owned small candidate list; no new generic tree abstraction.
4. Classic YARA compatibility? Default no claim; only the recorded YARA-X engine stamp is supported.
5. Target expectations? Default anchor expectations from rule direction, other expectations analyst-supplied and separate from advisory text.
6. Grid filter tooltip ownership? Default rules.grid_role, rules.grid_state and rules.unexpected_only are defined in section10 and applied separately; no composite tooltip is reused for a focusable child.
