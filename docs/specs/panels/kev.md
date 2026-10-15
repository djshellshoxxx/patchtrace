# Exploitation context panel (KEV K3)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

K3 implements read-only exploitation context for a chosen CVE list, explicit import/update and snapshot comparison. Analyst question: "What does this catalog snapshot say about exploitation of these CVEs, and when was that context recorded?" Source: `docs/specs/program-e/KEV-integration-plan.md`. KEV never locates a patched function, changes a function ranking, or supplies a negative exploitation conclusion from absence.

## 2 Identity

`kev/panel.py` exports PANEL, factory lazily calls ui_kev.create_panel(ctx). Proposed factory adapter name is UNVERIFIED against runtime. id kev; title "Exploitation context (CISA KEV)" (30 characters); area right; tabify_with kb; shortcut Ctrl+Shift+X; focus_order 190; default_visible False; requires empty tuple so catalog import and CVE lookup work without a project; claims CLAIMS_NEUTRAL with explicit bans on inferring vulnerable/fixed code from KEV. Network policy is action-specific. Conflict: old plan says tabify with evidence and controller creates its own dock; manifest and host win. All PanelController lifecycle hooks follow the framework; no dedicated top-level window.

## 3 Data contract

Domain names from KEV section 7: KevEntry, KevCatalogMeta, KevLookup, KevContext, KevDelta, KevPlan, KevCell and KevColumnProvider.cell(cve). Slim project entries are separate from full text. Pure APIs filter_indices and order_indices retain stable input order. Lookup statuses listed/not-listed/unavailable/invalid-id; freshness fresh/aging/stale/future/unknown. Ransomware values known/unknown/absent/unrecognized; forensic values yes/no/absent/unrecognized must remain distinct.

Proposed UNVERIFIED in-process wrapper KevPanelView: snapshot: KevCatalogMeta|None; rows: tuple[KevCell,...] <=5000; input_ids: tuple[str,...] <=5000; selected_cve: str|None; detail: str <=4000; freshness_text: str <=200; pending_plan: KevPlan|None; changes: tuple[str,...] <=200. Typed immutable fields only, no Qt. Proposed build_panel_view(lookups, meta, options) and copy_lookup(lookup, meta) in kev/view_model.py adapt existing functions rather than duplicating them.

Limits: input CVE <=24 ASCII chars; entry vendor128/product256/name256/description4096/action2048/notes4096; CWE list<=16; catalog version<=32; warnings<=20 of 200. Import/download <=16 MiB, catalog <=20000 entries. Strict stored kev/1; unknown upstream fields are reported, not silently reinterpreted. Service calls plan (no DNS), explicit fetch, local import, lookup, status and diff through kev/service.py and store. Current pointer changes only after validation and atomic snapshot/meta/pointer install; failure keeps prior current. No panel prune or delete.

## 4 Layout

Top: StateView, freshness strip, Update/Import/Show changes/Copy; inline consent/progress/main stack. Main: IDs, Look up, filter, sort, VirtualTable and SafeTextView; Go to CVE context and Copy address. Footer always: "KEV is context about a CVE. It does not locate the fix in code. Not listed does not mean not exploited. Data source: CISA Known Exploited Vulnerabilities catalog; not endorsed by CISA or DHS." The source plan asserts CC0-1.0; licence text is UNVERIFIED in this task and must be checked before adding the licence label to production.

| Column | Width em | Empty cell |
|---|---:|---|
| CVE | 20 | Invalid CVE ID |
| KEV | 24 | No catalog |
| Added to KEV | 16 | Not supplied |
| CISA due date | 16 | Not supplied |
| Known ransomware campaign use | 30 | Not supplied |

Default input order. Filter All/List/List ransomware known/Not listed/No catalog or invalid. Optional stable KEV-first order is labelled reading order, not score. KevCell supplies ColumnSpec text/accessibility/tooltip and PreparedTable is computed in a worker. No per-cell widget. Detail includes exact CISA vendor/product/name, short description, required action, notes by segment, dates, ransomware and forensic wording, CWEs, interpretation limits, source URL and final host, retrieval/release timestamps, full raw SHA-256, parser and authenticity. "Unknown" ransomware means no confirmation by CISA, not no use. Due date is a CISA required-action date, not fix publication or exploit start. Drift text compares recorded and current catalog facts without overwriting the old context.

## 5 States

Announce the exact text column on entry, once; K1 additionally announces the host after the full request is focusable. Network-off blocks only Update; import and existing lookups remain usable.

| State | Trigger | Exact on-screen copy | Remedy button | Screen-reader announcement |
|---|---|---|---|---|
| K0/empty | No catalog | No KEV catalog is loaded. PatchTrace works without it. Update from CISA opens an exact request preview. Import file reads a KEV JSON file you saved yourself. | Update; Import | No KEV catalog is loaded. PatchTrace works without it. Update from CISA opens an exact request preview. Import file reads a KEV JSON file you saved yourself. |
| K1/consent | Update pressed | Download the KEV catalog from CISA? | Download; Cancel | Download the KEV catalog from CISA? |
| K2/loading | Fetching | Downloading from {host}: {received} bytes received; limit 16 MiB. | Cancel | Downloading from {host}: {received} bytes received; limit 16 MiB. |
| K3/loading | Validating | Checking the downloaded file... | Cancel | Checking the downloaded file... |
| K4/ready | Valid current snapshot | KEV catalog {version} - released {date} {time} UTC - {count} entries - retrieved {retrieved} from {source} - {age}. | Look up | KEV catalog {version} - released {date} {time} UTC - {count} entries - retrieved {retrieved} from {source} - {age}. |
| K5/aging | Age 4 to 14 UTC days | This catalog is {n} days old. CVEs CISA added since then are not shown as listed. | Update; Import | This catalog is {n} days old. CVEs CISA added since then are not shown as listed. |
| K6/stale | Age at least 15 days | This catalog is {n} days old. A CVE shown as Not listed may have been added since. Update from CISA or import a newer file. | Update; Import | This catalog is {n} days old. A CVE shown as Not listed may have been added since. Update from CISA or import a newer file. |
| future | Future release timestamp | The catalog's release time is in the future. Check this computer's clock and treat results as unverified. | Import | The catalog's release time is in the future. Check this computer's clock and treat results as unverified. |
| K7/error | Fetch/import/store rejected | Could not update the KEV catalog: {reason}. {kept} | Retry; Copy details; Accept smaller catalog when shrink only | Could not update the KEV catalog: {reason}. {kept} |
| K8/blocked | Network off | Network updates are switched off here. Import file still works. | Import | Network updates are switched off here. Import file still works. |
| K9/loading | Local read | Loading the KEV catalog from this computer... | Cancel | Loading the KEV catalog from this computer... |
| older/partial | Older mirror result | The downloaded catalog ({v1}) is older than the one in use ({v2}); the newer one was kept. | Show changes | The downloaded catalog ({v1}) is older than the one in use ({v2}); the newer one was kept. |
| empty-input | No CVE IDs | Type or paste CVE IDs above, or open a KB or CVE view that passes its CVEs here. | CVE IDs field | Type or paste CVE IDs above, or open a KB or CVE view that passes its CVEs here. |
| no-matches | Filter hides every row | No CVEs match the selected KEV status filter. | All CVEs | No CVEs match the selected KEV status filter. |
| cancelled | Token cancelled | Cancelled. Earlier results are unchanged. | Look up | Cancelled. Earlier results are unchanged. |

K7 {kept}: "The catalog {version} from {date} is still in use." or "No catalog is loaded." Reasons are closed templates: "the connection failed or timed out"; "the server answered HTTP {status}"; "the file is larger than 16 MiB"; "the file is not a KEV JSON catalog"; "the file failed checks ({check})"; "the new catalog has {n} fewer entries than the one in use"; "the catalog folder cannot be written". No raw exception message. StateView carries underlying error/partial/stale kinds; date banners may coexist with a ready table. No-project is not a blocker for global lookup.

## 6 Interactions

Commands use the matching kev.* ids in section 10. update prepares a plan, source_cisa/source_mirror changes it, consent_download sends only the exact current plan, consent_cancel leaves without network. Import opens an injected file picker then validates locally. changes reads two snapshots, unavailable without both. lookup_button and Enter in lookup_box perform local lookup, preserving invalid IDs as invalid-id rows. filter/sort affect only the view. copy and Ctrl+C copy one selected lookup with snapshot version/date/age, source/authenticity, full hash, CISA wording and the non-localization/absence caveat. goto and Enter on a row navigate the CVE, not a guessed function; Space focuses detail. copy_url copies without opening a browser.

cancel/Escape while fetching cancels only the KEV token. retry reopens consent for a network operation; it never reuses the prior click. copy_error copies bounded diagnostic metadata. replace_anyway is available only after an already downloaded, validated catalog trips the shrink guard; it cannot permit an older date, corrupt schema or invalid digest. No new fetch occurs from accepting shrink. Selection/Tab are unchanged after a failed install. Host show/hide and panel movement commands come from the registry.

## 7 Navigation

Every emitted reference is an `AnchorRef(kind, key, side, run_id, label, origin, revision)`; keys are opaque, at most 256 characters, labels sanitized to 200. Pin run and revision from the same `ProjectKey` used to build the row. Use `NavigationPort.navigate`, not another panel's controller. `function` and `match` references resolve against `ProjectPort.match_index`. More than one candidate returns `ambiguous` with at most 20 candidates; never choose the first. A side mismatch is a miss.

Exact failure copy: stale: "This location belongs to an earlier project revision. Reload before opening it."; missing: "This location is not present in the current run."; ambiguous: "Several locations match. Choose one to continue."; blocked: "This location is unavailable in the current project." A stale or missing target keeps focus and selection where they were; show the reason beside the action. Only a shown result enters the host's 50-entry history. Alt+Left and Alt+Right remain host navigation. No fallback to another function, the same address in another run, or the opposite side.


anchors_in = {cve}; anchors_out = empty set: the panel does not claim ownership of the cve router handler on the assumption another panel also owns it. Conflict resolution proposal: KB is the canonical cve destination if its current spec declares that handler; KEV accepts inbound show_cves through its typed adapter or explicit focus command until the integrator confirms single-handler routing. UNVERIFIED: actual KB anchor ownership. Default do not register duplicate cve handlers. If registered ownership is assigned to KEV, it may declare cve in anchors_in; Go to context must then focus the KB view through a typed host command, never recurse through the same cve handler. A projectless lookup uses global snapshot identity; project-linked navigation requires the current ProjectKey.

## 8 Threads

Use `TaskRunner` and `CancelToken` through `ShellPort.tasks`; no panel-owned `QThread` registry. Capture an immutable request on the GUI thread. Never pass widgets, the live project service or a thread-bound SQLite connection to a worker. A named lane creates and closes its reader on that same lane thread. Apply results and publish rows only on the owning GUI thread.

A request carries `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)`, a controller epoch and a channel generation. Project change, swap, new run, settings affecting results and shutdown cancel the old token and advance the appropriate generation. Reject a late result unless every captured identity still matches; rejected work cannot publish. Selection-only requests also carry the selected row key. A failed or cancelled operation preserves committed results and marks retained content explicitly stale when appropriate. Recheck the guard immediately before publication.

Progress is bounded to 10 updates per second, latest wins, and terminal progress always arrives. Use counts only when known, otherwise indeterminate progress with elapsed time. Heavy Python loops call `checkpoint()`; cancellation is polled at documented chunk boundaries. Bound-method queued callbacks update Qt. `shutdown()` is idempotent, stops debounce timers, cancels tokens, detaches listeners and delegates lane closure and the five-second join ceiling to the runner. Hidden panels have zero active timers and start no new work; a dirty flag triggers a refresh on the next show.


Named lanes kev-catalog (read/parse/lookup/diff), kev-transfer (fetch/import/validate). Catalog cache lifetime is the reader lane; publish the global pointer through the service's single-writer contract, not a project connection in a worker. Project kev-context publication, if enabled, occurs on the GUI owner thread under its project guard. Context storage failure never falsely rolls back or reports failure of an already valid global catalog installation. Requests carry snapshot_id/content_digest and a separate input-generation in addition to optional ProjectKey. Download 64 KiB chunks; connect10 s, request60 s, plan120 s; at most3 retry attempts on the plan's retryable statuses, capped Retry-After60 s, at most2 same-host redirects. Progress reports received bytes under the hard cap; an expected size is only a hint.

## 9 Settings

| Key | Type | Default | Range |
|---|---|---|---|
| kev/filter | enum | all | all,listed,ransomware-known,not-listed,unavailable |
| kev/sort | enum | input | input,listed-first |
| kev/source | enum | cisa-github | cisa-github,cisa-site only after live source acceptance |

Network policy is supplied by the application, not overridden by a panel setting. No saved consent, CVE queries, credentials, pointer path or geometry in QSettings. Freshness constants remain in kev/limits.py, not arbitrary panel knobs: <=3 days fresh,4..14 aging,>=15 stale. Bad setting values use defaults. UNVERIFIED: whether the K6 workflow has passed for cisa-site; default mirror until a recorded passing result is reviewed.

## 10 Tooltips

### `kev.dock`

Accessible name: "Exploitation context (CISA KEV) panel".

What: Read CISA KEV context for the CVEs being investigated.

Why: Keep exploitation context separate from code-localization evidence.

Effect: Read-only; opening downloads nothing.

Source: Stored CISA KEV catalog; licence CC0-1.0 asserted by the plan, UNVERIFIED here.

### `kev.action`

Accessible name: "Show exploitation context".

What: Show or hide the CISA KEV panel.

Why: Access catalog context beside the KB view.

Effect: Toggles the dock; Ctrl+Shift+X.

Source: Panel registry.

### `kev.update`

Accessible name: "Update KEV catalog from CISA".

What: Preview the exact request to download a KEV catalog.

Why: Control the only network operation in this panel.

Effect: Shows consent first; disabled when network policy is off or a fetch is active.

Source: KevPlan.

### `kev.import`

Accessible name: "Import KEV catalog file".

What: Load a KEV JSON file saved on this computer.

Why: Use catalog context offline.

Effect: Validates a local file; CSV is refused; previous catalog survives failure.

Source: Local KEV JSON and parser.

### `kev.changes`

Accessible name: "Show KEV changes since the previous catalog".

What: Compare the current catalog with the previous snapshot.

Why: See which catalog facts changed.

Effect: Read-only; requires two stored snapshots.

Source: KevDelta.

### `kev.copy`

Accessible name: "Copy KEV details".

What: Copy the selected CVE's details and catalog provenance.

Why: Keep snapshot date and limitations attached to copied context.

Effect: Clipboard only, at most 16 KiB; disabled without a selected row.

Source: KevLookup and KevCatalogMeta.

### `kev.lookup_box`

Accessible name: "CVE IDs to look up".

What: Enter ASCII CVE identifiers for the loaded catalog.

Why: Look up chosen identifiers without sending them.

Effect: Session-only; at most 5000 IDs, invalid IDs remain explicit rows.

Source: Analyst input or inbound CVE anchors.

### `kev.lookup_button`

Accessible name: "Look up CVE IDs".

What: Look up the entered identifiers in the local catalog.

Why: Read status against a named snapshot.

Effect: No network; Enter in the ID field runs the same action.

Source: KevLookupPort.

### `kev.filter`

Accessible name: "Filter by KEV status".

What: Choose all, listed, ransomware-known, not listed or unavailable rows.

Why: Read one catalog status without hiding its meaning.

Effect: Changes the view only; defaults to all CVEs.

Source: KevCell states.

### `kev.sort`

Accessible name: "CVE order".

What: Choose input order or KEV-listed first.

Why: Use an explicit reading order for CVEs.

Effect: Stable inside groups; never changes function ranking.

Source: KevCell order keys.

### `kev.table`

Accessible name: "KEV lookup results".

What: Read CVE status, CISA dates and ransomware-use wording.

Why: Keep catalog facts in their proper context.

Effect: Enter opens the selected CVE context; Space focuses detail.

Source: CISA KEV catalog; licence assertion UNVERIFIED here.

### `kev.detail`

Accessible name: "Selected CVE KEV details".

What: Read CISA wording, source, snapshot date and limitations.

Why: Distinguish catalog facts from conclusions about this comparison.

Effect: Plain text; source text never becomes a clickable command.

Source: CISA KEV catalog; licence assertion UNVERIFIED here.

### `kev.goto`

Accessible name: "Show candidate functions for the selected CVE".

What: Open the selected CVE in the patch-intelligence view.

Why: Continue the investigation with a separate source of code leads.

Effect: Disabled without a current linked CVE context; never picks a function itself.

Source: Current CVE anchor and navigation router.

### `kev.copy_url`

Accessible name: "Copy CISA catalog page address".

What: Copy the configured CISA catalog page address.

Why: Obtain the source address without an automatic browser request.

Effect: Clipboard only; address must come from the approved source metadata.

Source: CISA source configuration; current URL UNVERIFIED here.

### `kev.source_cisa`

Accessible name: "CISA website source".

What: Select the CISA website as this operation's source.

Why: Make the destination explicit.

Effect: Changes the pending plan; no request until Download.

Source: Approved KEV source table; live URL acceptance UNVERIFIED.

### `kev.source_mirror`

Accessible name: "CISA GitHub mirror source".

What: Select the CISA-owned GitHub copy as this operation's source.

Why: Use the alternate explicitly allowlisted destination.

Effect: Changes the pending plan and invalidates old consent.

Source: Approved KEV source table; live source equivalence UNVERIFIED.

### `kev.consent_download`

Accessible name: "Download displayed KEV catalog".

What: Send only the request displayed in this consent page.

Why: Authorize this one catalog retrieval.

Effect: Disabled if plan identity or network policy changed; no CVE IDs leave.

Source: Immutable KevPlan and consent digest.

### `kev.consent_cancel`

Accessible name: "Cancel KEV confirmation".

What: Leave the confirmation without contacting the source.

Why: Keep the catalog and privacy state unchanged.

Effect: No network and no remembered consent.

Source: Inline consent controller.

### `kev.cancel`

Accessible name: "Cancel KEV operation".

What: Cancel this panel's active fetch, import or load.

Why: Keep a partial download from replacing the catalog.

Effect: Sets the owned CancelToken; earlier catalog remains current.

Source: TaskRunner.

### `kev.retry`

Accessible name: "Retry KEV operation".

What: Retry a failed local load or prepare a new fetch confirmation.

Why: Recover without silently reusing network consent.

Effect: Fetch retries reopen the exact plan; local reads stay offline.

Source: Failed operation kind.

### `kev.copy_error`

Accessible name: "Copy KEV error details".

What: Copy the bounded KEV error and snapshot identity.

Why: Provide useful diagnostics without request secrets.

Effect: Clipboard only; no raw paths or project data.

Source: Sanitized KevError.

### `kev.replace_anyway`

Accessible name: "Accept smaller KEV catalog".

What: Accept the displayed shrink warning for this checked catalog.

Why: Make a potentially incomplete replacement explicit.

Effect: Only offered for PT-KEV-SHRINK; never bypasses format, integrity or older-date checks.

Source: Parsed catalog counts and snapshot dates.

### `kev.freshness`

Accessible name: "KEV catalog freshness".

What: Read the catalog's release date and age.

Why: Understand why Not listed can be out of date.

Effect: Read-only; stale data never triggers an automatic download.

Source: KevCatalogMeta and injected UTC clock.

### `kev.cell`

Accessible name: "KEV cell".

What: Read {cve}: {state}, catalog {version}.

Why: Keep the catalog basis with each cell.

Effect: Read-only template; values are escaped and bounded.

Source: CISA KEV snapshot.

### `kev.badge`

Accessible name: "KEV status badge".

What: Read KEV status {state}: {meaning}.

Why: Understand status without interpreting badge colour.

Effect: Outlined word badge only; no severity score.

Source: CISA KEV snapshot.

### `kev.column`

Accessible name: "KEV column meaning".

What: Read column {column}: {meaning}.

Why: Distinguish CISA dates from exploitation and fix dates.

Effect: Read-only template.

Source: KEV view-model column copy.

### `kev.row_header`

Accessible name: "KEV row identifier".

What: Read the KEV row for {cve}.

Why: Identify the row independently of its position.

Effect: Read-only template; vertical headers may instead be hidden.

Source: Lookup input identity.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order: Update, Import, Changes, Copy, lookup_box, lookup_button, filter, sort, table, detail, goto, copy_url. Consent: source_cisa, source_mirror, exact request text, Cancel, Download; initial focus Cancel. Data cells speak "{cve}: {state}, added {date}, ransomware campaign use {value}. Catalog {version}." Do not call absent or unrecognized fields Unknown without their qualifier. Badge uses bold outline and word, no severity colour. Hidden vertical header avoids an unnamed row-header control.

## 12 Performance budgets

Budgets are acceptance ceilings, not measurements made in this task (UNVERIFIED until executed). Factory: no I/O or task start, at most 150 ms. GUI callbacks: median at most 16 ms, maximum 50 ms, none above 100 ms. Fixed row height and em-based columns; no ResizeToContents, QTableWidget, per-row QObject or QSortFilterProxyModel for large data. Prepared strings and order keys are computed off the GUI thread; model data() is O(1). Table paint/sort/filter each use at most 7 times visible cells times 1.2 plus 20 data() calls at both 10,000 and 100,000 rows; a stricter feature ceiling below wins. Pointer-swap publication cannot perform parsing or hashing. Use stable sorts with unknown values last and a row-key tie break. Clipboard ceiling is 16 KiB, detail view ceiling 4,000 characters unless section 3 specifies a smaller one, and ordinary labels are at most 200 characters.


Dock build <=80 ms; local catalog parse/validate <=1 second; 5000 panel rows maximum. Shared KevColumnProvider is O(1); 100000 provider-backed data() calls <=1.5 seconds, filter/order<=1 second. Never turn a KB 100000-row view into 100000 lookups or network requests. Snapshot changes list<=200 lines; full catalog stays in pure service/store, not widgets.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Only update may contact approved hosts. Exact source URLs recorded by the plan (reachability, source equivalence and current licence UNVERIFIED here): cisa-site https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json ; cisa-github https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json . CISA page address https://www.cisa.gov/known-exploited-vulnerabilities-catalog is also UNVERIFIED here and copy-only. Reject userinfo, query, non-HTTPS/non443 and cross-host redirects; no environment proxies or cookies. Transport must still enforce its exact allowlist even if UI data is forged.

Inline K1 shows method/full URL/host, headers Accept: application/json and User-Agent: PatchTrace, 16 MiB cap, timeout/retry/redirect limits, local storage location, and "No project data and no CVE IDs are sent." Do not promise a fixed file size or synchronization delay; current values are UNVERIFIED. Consent binds plan_sha and is consumed for one fetch. Changing source invalidates it; Cancel sends nothing. Display local import authenticity as unverified-local-file. No automatic refresh, startup DNS, browser navigation or implicit telemetry.

## 14 Test plan

All automated cases are required future checks, not executed results. Use synthetic PE data, fake providers, injected clocks and temporary INI settings. No network, target execution or Microsoft-derived fixtures. Short explicit parameter ids, no sleeps, event-based waits, UTF-8 and LF; timing comparisons account for Windows clock granularity. Test the panel standalone and once under the actual host. Check tooltip id completeness, four-line text and uniqueness of What lines, claims lint, no Qt imports in pure modules, all state rows and failure remedies, hostile text, generation rejection, selection persistence, contrast and lazy-model call ceilings. Repeat the GUI teardown matrix 20 times in one pytest session with faulthandler. Run focused tests, ruff and `patchtrace panels check` only when execution is authorized; this task ran none.

Manual Windows checks (all UNVERIFIED): keyboard-only opening, filtering, selection, context menu and closing; NVDA and Narrator table headers and one announcement per terminal transition; Accessibility Insights names, roles and identifiers; each Windows contrast theme; 100/125/150/200 percent DPI and moving between monitors; reduced motion; dock layout save/restore/reset; a frozen package starting without developer tools; cancellation and main-window close during a real permitted operation. Record Windows and tool versions from the machine used instead of copying a version from this specification.


Named tests: test_kev_states_k0_to_k9; test_kev_lookup_projectless; test_kev_no_catalog_is_unavailable_not_unlisted; test_kev_unicode_digits_invalid; test_kev_age_boundaries_3_14_15; test_kev_future_clock; test_kev_consent_change_source_invalidates; test_kev_plan_does_no_network; test_kev_fetch_never_sends_cves_or_project; test_kev_cross_host_redirect_rejected; test_kev_retry_requires_new_consent; test_kev_shrink_override_preserves_date_guard; test_kev_cancel_keeps_current; test_kev_corrupt_current_fallback_announced; test_kev_input_order_preserved_in_groups; test_kev_no_function_ranking_change; test_kev_ambiguous_anchor_never_selects; test_kev_provider_100k_calls. Manual extra: both sources, corporate network behaviour, frozen TLS trust, source licence and CISA directive wording; none closed by this document.

## 15 Open questions

1. Default source? Mirror until reviewed K6 evidence supports the canonical website; no silent fallback across hosts.
2. Who owns cve anchors? Default one canonical KB handler; use explicit KEV show_cves adapter and focus command until ownership is confirmed. Do not merge a duplicate handler.
3. Bundle a seed catalog? Default no; imports serve offline use.
4. Catalog prune in GUI? Default no; explicit CLI-only retention operation remains separate.
5. Projectless global lookup? Default enabled; linked code navigation stays blocked without current project context.
6. Show absent/unrecognized ransomware values? Default explicit words "Not supplied" and "Unrecognized source value", distinct from CISA's "Unknown".
7. Licence and upstream addresses current? UNVERIFIED; verify before release and keep these statements as source-plan assertions until then.
