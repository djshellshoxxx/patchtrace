# Panel build and integration plan

Status: proposed, documentation only. Baseline branch `claude/instance-d-gui`, observed commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`. Delivery branch `chatgpt/panels-1`. No application code, tests, schemas, linters, benchmarks, subprocesses or builds were run. Runtime, upstream and Windows acceptance claims are UNVERIFIED. GitHub reads establish repository contents only.

This plan accompanies the nine files under `docs/specs/panels/`. Each panel file has the required fifteen sections and complete four-line tooltip text. New in-process adapter names are requirements or proposals, not assertions that implementation already exists. Persisted schema and existing API names always come from the repository. If an implementation already supplies an equivalent pure operation, adapt it rather than implementing another model.

The direct task authorizes branch creation, documentation commits and a draft pull request. It overrides worker-brief instructions to never push, append to shared trackers or add another model's coauthor attribution. This task changes no existing file, tracker, source, dependency or workflow. No file required a -2 suffix because none of these target files existed at the baseline.

## 1. Document inventory and ownership

| File | Scope | Builder size |
|---|---|---|
| panels/capabilities.md | CAP-6a stored pair deltas and CAP-6b setup, probe, explicit local run | L; 6a then 6b under one owner |
| panels/kev.md | K3 projectless catalog lookup, snapshot context, local import and consented update | M for read/import; L including transfer |
| panels/build_env.md | DIE D5 dock card and pre-flight notice, display-time overlay contract | L |
| panels/rules.md | YARA-X R6b candidate review, decision/version flow, grid and local export | L |
| panels/guide.md | Deferred-only Guide stub | S |
| panels/graph.md | WB2 G5/G6 call tables, lazy tree and bounded diagram | L |
| panels/strings.md | WB3 S7b comparable string deltas, inventory, exact/escaped copy | L |
| panels/search.md | WB1 S7 paged search, structured completion, coverage and saved plans | L |
| panels/kb.md | Additional manifest-backed KB investigation; E0 before E1 | L |
| panels-build-plan.md | This dependency order, contract decisions, existing-panel inventory and remaining gates | S documentation |

Sizes are relative implementation complexity, not measured time promises: S is a bounded static or thin-adapter slice; M requires an existing pure service plus moderate lifecycle integration; L includes several states, provenance, asynchronous work or a security-sensitive operation. Do not reduce scope silently to meet an estimate. A reduced delivery must visibly disable the corresponding action and retain unknown states.

Each feature owns its pure panel declaration, view adapter, Qt module and focused tests. The integrator alone owns panel_manifest.py, ui.py, tooltips.py, shared settings contracts, enrichment KINDS, packaging hooks and common service seams. The documentation in this PR authorizes no edits to those files.

## 2. Source hierarchy and binding conflict resolutions

Read AGENTS.md, CLAUDE.md and docs/plans/worker-brief.md before implementation. Relevant documents retrieved from the baseline include GUI, CAP, DIE, YRX, KEV, WB1, WB2 and WB3 integration plans; gui-framework.md; ui.md; docs/modules.md; docs/guide/; and the KB, PIL, WBQ, existing evidence, unified, series and preliminary-inspection specifications for adjacent responsibilities.

Several plan status paragraphs describe an earlier branch. The tree and docs/modules.md contain gui/qt implementations and existing panel declarations even where gui-framework.md still says the Qt host is planned. A file's existence proves neither that a Windows gate passed nor that a feature is release-ready. Read the actual implementation before editing and record new evidence separately.

The following decisions resolve conflicts within the new documentation as well as between old source plans. They are binding adapter rules for this build plan; they do not request rewriting earlier commits.

| Subject | Conflicting wording | Integration decision and reason |
|---|---|---|
| Placement | CAP and WB3 older plans use right/evidence | Actual manifest: capabilities bottom/graph, strings bottom/graph. Registry lint compares these fields. |
| Build card | DIE interim area=none, no shortcut | Actual manifest reserves build_env right/evidence, Ctrl+Shift+B. Use one docked card and a notice contribution, not two PANEL registrations. |
| KEV tab group | Older plan uses evidence | Actual manifest: kev right/kb, Ctrl+Shift+X. |
| Shortcuts | Earlier plans reused K | KB K, Capabilities A, KEV X. Host palette P, F6/Shift+F6 and Alt+Left/Right remain reserved. |
| Threads | Feature-owned QThread registries | Existing TaskRunner and named lanes; do not introduce a parallel registry. |
| Announcements | Empty accessible name plus setText described as sufficient | Explicit ctx.announce; empty status name alone is not an announcement. |
| Model storage | Worker brief suggests strict Pydantic everywhere | Strict models for persisted/imported contracts; frozen slotted dataclasses for bounded in-process prepared views. |
| Geometry | Per-feature geometry keys | Host layout state only. |
| Tooltips | Direct shared REGISTRY edits or register_entries at import | PANEL.tips and PANEL.tip_templates through host registration; no Qt import while loading a pure declaration. |
| Tables | WB3 mentions a 200000-row UI inventory | Source tables may retain that many; one shared prepared table is capped at 100000, delta view50000. Narrow filters or feature-owned paging must be explicit; do not imply the display contains all source rows. |
| Graph caps | Widget supports 2000nodes/8000edges | The stricter WB2 query and export limits apply first. Canvas capability is not permission to enlarge a domain query. |
| Existing panels | Prompt calls several surfaces unbuilt | Existing Evidence, Unified, Leads, Files and Series stay their existing panels. Do not build duplicate wrappers with a new id. |

### 2.1 Exact navigation copy and ownership

The capabilities and KEV files were drafted before the final code-level anchor review. Their generic section7 navigation-copy examples are superseded by the actual constructors in src/patchtrace/gui/anchors.py. Do not implement a second set of error strings.

| Result | Exact current copy |
|---|---|
| stale | The project changed after this link was created. Open it again from the source panel. |
| not-found with run | Not found in run {run_id}: {label}. |
| not-found without run | Not found: {label}. |
| ambiguous | {n} candidates match {label}. Choose one. |
| blocked | {title} is unavailable: {reason} |

The constructor sanitizes interpolation and caps messages. Return candidates rather than selecting the first. A projectless lookup does not use AnchorRouter because is_stale returns true when there is no project. It remains a valid local catalog lookup.

The existing pilot/panel.py declares anchors_in cve and match. Therefore the KEV section7 proposal that assumes KB is the canonical cve handler is superseded: keep KEV anchors_in empty and anchors_out containing cve for project-linked Go to context. Go to context navigates cve to the existing Leads handler. Projectless Go to context is disabled. KEV's local show_cves adapter or typed focus-and-input command may display a list without claiming canonical cve routing. KB handles kb only. Do not register two cve owners or route a cve back into the same handler recursively.

Function anchors go to the code-host route. Do not add function to graph or search anchors_in merely to follow selection. A panel follows selection through its existing selection_changed hook and local seed state. Any direct panel-focus command used by the composition root must be typed and validated, not a callback embedded in untrusted data.

CAP emits rule/import/string anchors only with original identity and provenance. The actual rule handler must recognize the producing rule namespace and identity; an unsupported capa rule identity is not found rather than a same-named YARA candidate. No automatic cross-tool identity coercion is allowed.

### 2.2 KEV pure APIs and enum spelling

The source implementation was read after the first KEV draft. This table is the definitive code-facing mapping. The friendly labels or suggested aliases in kev.md must not leak into existing pure APIs or persisted contracts.

| Concept | Existing identifier |
|---|---|
| Catalog service | KevService in kev/service.py |
| Network source plan | plan_for(source), imported from kev/contracts.py |
| Explicit service fetch | KevService.fetch(source, hosts, surface='gui', accept_shrink=False, cancel=..., announce=...) |
| Local import | KevService.import_file(path, accept_shrink=False) |
| Read file without install | KevService.read_catalog(path) |
| Snapshot comparison | KevService.diff(from_id=None, to_id=None) |
| Lookup cell provider | KevColumnProvider(catalog, now).cell(cve) |
| Column cell id | KevCell.cve, not cve_id |
| Column state | listed / not-listed / no-catalog / invalid-id |
| Domain lookup status | listed / not-listed / unavailable / invalid-id |
| Ransomware-known filter | listed-ransomware |
| Unavailable/invalid filter | no-catalog-or-invalid |
| KEV-first sort | kev-first |
| Pure filtering | filter_indices(cells, mode) |
| Pure ordering | order_indices(cells, mode, indices=None) |
| Detail formatter | detail_text(row, meta) |
| Change list formatter | changes_lines(delta, new, previous_version) |
| Consent text | consent_lines(plan) |
| Status and age | status_line, banner_text, age_phrase |
| Error text | error_text and kept_text |
| Older-mirror text | mirror_older_text |

Use the existing enum strings in settings where those settings pass values directly to the pure functions. In particular, kev.md's suggested ransomware-known/unavailable/ listed-first aliases need either the above canonical spelling or an explicit nonpersisted mapping. Default canonical settings are kev/filter=all, kev/sort=input; no new enum or contract migration.

Reuse existing footer, column meanings and ransomware known/unknown/absent/unrecognized wording from kev/view_model.py. Newly proposed wording that changes only a display label is a copy decision for review, not permission to change CISA semantics. Where a prescribed four-line tooltip expands an existing pure entry, retain the existing id and make the registration content consistent before the first real panel load. No actual tooltip registry was modified by this PR.

### 2.3 Transaction boundaries and honest cancellation

KevService currently documents a store with no cross-process lock and one installer at a time. It installs inside fetch/import_file. Its import_file signature has no cancel parameter. A controller generation guard can suppress a stale view result but cannot undo a global catalog installation that already committed.

The implementation must serialize all installation attempts, check cancellation before entering installation, and report a committed installation truthfully even if the panel or project changed. Do not show "Earlier results are unchanged" after a global pointer was actually advanced. The project-specific view may still discard that result. If cancellable staging is needed, add a pure staged-install adapter under an explicit service change, with tests for cancellation before commit and a terminal "installed" outcome after commit. Do not pretend cancelling the GUI callback prevented the service side effect.

The same rule applies to export: a successfully saved file followed by an ExportRecord failure is "file saved; project record failed", not "nothing was changed". KB project creation followed by attach failure is CONTEXT_PENDING and keeps the project. Workers cannot publish into a new active project after a switch.

### 2.4 Complete KB pair-reason copy

These strings complete and supersede the shorthand reason descriptions in kb.md section5. They are displayed next to the blocked or conditional Create action with the reason code; an uncertainty requiring an analyst choice is not automatically a hard block if the reducer permits an explicit recorded decision.

| Code | Exact copy |
|---|---|
| IDENTICAL_CONTENT | These two files are byte-identical; this file did not change between them. |
| DELTA_ONLY | Only a delta payload was found. A complete PE file is required; import one. |
| ARCH | PatchTrace compares AMD64 PE files; this file is {arch}. |
| CROSS_PRODUCT | The two builds belong to different products and are not compared automatically. |
| ORDER_UNVERIFIED | The release order of these builds could not be established, so older and newer are your choice. Swap if needed. |
| DIGEST_MISMATCH | The downloaded file does not match the expected SHA-256; no project was created. |
| NO_OLDER | No earlier build of this file is listed for this product. |
| NO_NEWER | No newer build of this file is listed for this product. |
| WINDOW_CONFOUNDED | {k} other updates ship between these builds; differences may belong to any of them. |
| SERVER_NOT_COVERED | The file index covers Windows 10/11 client updates only; Server-only builds are not listed. |
| NAME_MISMATCH | The two files have different names. Confirm they are the same component to continue. |
| INDEX_GAP | The available file index has a gap around this pair. The update boundary is unverified. |

The SERVER_NOT_COVERED wording is a source-plan coverage statement, not a freshly verified assertion about current external services. Use it only when the actual provider's verified scope matches; otherwise show the provider's current explicit coverage limitation, marked unverified where appropriate.

## 3. Shared prerequisites and widgets

Tree inventory confirms the following modules exist at the baseline. Existence does not establish test results or live Windows behaviour: gui/qt/tasks.py,settings.py,announce.py,metrics.py,runtime.py,labels.py,state_view.py,chips.py,theme.py,table.py,codediff.py,canvas.py,host.py,docks.py,layout.py,commands.py,palette.py and theme_stylesheet.py.

Do not reimplement TaskRunner, StatusAnnouncer, StateView, NoticeStrip, ThemeTokens, VirtualTable, CodeDiffView, GraphCanvas or the host command palette. Reuse the pure registry, text, projection and anchor contracts.

The actual task API read at the baseline is:

- TaskRunner.submit(channel, fn, on_result=None, on_error=None, on_progress=None) -> CancelToken; fn receives token and report.
- TaskRunner.lane(name, init, close=None) -> Lane; a name may be created once per runner.
- Lane.submit(fn, on_result=None, on_error=None, on_progress=None, coalesce=False) -> CancelToken; fn receives lane state, token and report.
- TaskRunner.cancel(channel) supersedes the channel and discards its earlier result.
- TaskRunner.set_applying(channel, applying) holds/replays results for a hidden panel.
- TaskRunner.shutdown(timeout=...) uses a shared join deadline, not an independent five seconds multiplied by every worker.

Store each created lane on the controller and reuse it; never call lane with an already used name on every refresh. Prefix names by panel, and include investigation/project instance identity if multiple simultaneous instances are supported by the host. No proposed panel in this PR requires another main window.

Missing shared widgets: none of the named framework primitives is absent from the baseline tree. Runtime API completeness is UNVERIFIED. The following feature-owned adapters are still needed or need implementation review, not new framework-wide abstractions:

| Adapter | Owner | Reason it stays feature-owned |
|---|---|---|
| Two-level capability tree with stable group keys | CAP | Grouping and union semantics are domain-specific. |
| Paged SearchResultsModel and structured suggestion popup | WB1 | Service cursors and exact Locator payloads are not a full prepared table. |
| Lazy caller/callee tree | WB2 | Expansion requires bounded graph queries and unknown frontiers. |
| Inline operation review for KEV | KEV | Exact catalog request, source choice and one-use consent semantics. |
| Inline/local tool run preview | CAP/DIE/WB3 | Inputs and isolation disclosures differ; share only after actual duplicate code is demonstrated. |
| Rule acceptance/export forms | YRX | Immutable decision, hard gates and sensitive export checklist. |
| Build-env card and timeline projection | DIE | Fact certainty and adjacent-build rules belong to buildenv. |
| Six-step investigation pages | KB | Reducer prerequisites and two-phase project attachment are not general-purpose navigation. |

A generic ConsentView or VirtualTreeModel is a possible later extraction, not a prerequisite. Do not block useful pure/model work on a speculative shared abstraction. A proven gap in an existing shared widget is an integrator ask with the exact interface and failing test; builders do not quietly edit frozen shared files.

## 4. Pure view-model order and concrete module/function boundaries

The following order is based on data dependencies, not panel placement. Callable names marked proposed are UNVERIFIED against runtime and must be reconciled with an existing equivalent before code is added.

| Stage | Pure modules and required operation names | Input/output and dependency |
|---|---|---|
| A | gui registry,projection,anchors,ports,text; existing PanelSpec,ProjectKey,AnchorRef,NavResult,sanitize_text | Fixed panel identity, current-run and safe-text boundaries. |
| B | intelligence/tools/capa_pairs.py: groups_from_project; capa_view.py: build_view,filter_rows,provenance_block (view callables proposed) | Coverage and pair delta before CAP widgets. CAP-1/2 before CAP-3. |
| C | buildenv/view_model.py: build_view,banner_views,provenance_block (named by DIE plan); overlay.py and noise_map.py | Bounded fingerprint/delta before notices and unified overlay. DIE D1/2 then D3. |
| D | strings/view_model.py: build_view,filter_indices,provenance_block,detail_view (proposed) | StringBasis and delta first; no GUI inference of coverage/link tier. WB3 S0 through pure comparison/link/cue slices before S7b. |
| E | kev/view_model.py: KevColumnProvider.cell,filter_indices,order_indices,detail_text,changes_lines,consent_lines | Existing pure data first; use exact identifiers in section2.2. |
| F | callgraph/view_model.py: build_changes_view,build_neighbours_view,build_detail; layout.py: layout_graph (proposed) | G1/G2 resolution, G3 delta before G5 view; G6 layout after query caps. |
| G | search/view_model.py: build_result_rows,build_detail,coverage_rows,copy_lead (proposed); parse_query and reader/index services | Query plan and source-coverage model before S7. Optional feature source adapters may stay missing explicitly. |
| H | rules/view.py and panel_service.py: build_candidates_view,build_grid_view,build_saved_view (proposed wrappers) | R0–R5 pure contracts/synthesis/runner/store before R6a; then R6b. |
| I | kbcorrelation/view_model.py: build_find_view,build_updates_view,build_files_view,build_builds_view,build_project_view,build_leads_view (proposed); workflow.py: reduce | Investigation store/reducer and E0 manual pair flow before Qt; KEV and PIL injected via ports. |
| J | guide/view_model.py: deferred_view (proposed) | Static stub only; no dependency on a working teaching engine. |

Persisted schema ownership remains with the original feature. View-model fields in the panel specs are in-process projections, not new storage. Do not persist a PreparedTable, Qt index, live connection, lambda, callback, task token, clipboard buffer or scene item. Additive contract changes require the existing schema generator and regenerate-and-compare tests in a separate authorized implementation slice.

## 5. Build sequence

1. Inspect the actual base and open work before implementation. Confirm existing framework contracts and panel declarations; reserve file ownership. Read this plan's section2 corrections with the individual panel spec.
2. Confirm pure core and runtime are usable with the actual host; use existing synthetic host fixtures. No panel factory may read disk, probe tools, contact a host or start a task.
3. Land pure projections and coverage logic first. This can be independent feature work, but builders sharing common.py or a store seam must serialize those changes through the integrator.
4. Implement read-only paths: Guide stub, KEV local lookup/import, Build environment PE/stored data, CAP-6a, Graph Changes/Neighbours, Strings stored comparison, Search with existing source segments, Rules saved/candidate read, KB E0. No unavailable provider is replaced with fabricated evidence.
5. Add Graph tree/diagram only after query/table parity and layout caps. Add Search structured suggestions and paging after cursor-generation tests. Add Rules acceptance/test/export only after native-worker and hard-gate tests.
6. Add optional local run controls: CAP-6b, DiE read and FLOSS static/emulation. Require exact input/tool previews, supervised child isolation, cancellation and immutable provenance; no target execution.
7. Add KEV fetch and KB E1 separately after transport allowlist, plan identity, source acceptance and cancellation/commit-boundary tests. E0 and offline import remain usable if those gates are blocked.
8. Connect feature-to-feature adapters at the composition root. Apply the anchor ownership table and keep unsupported Locator kinds visibly blocked. No feature imports another feature's Qt controller.
9. Run focused pure/Qt gates and tooltip/manifest checks, then the integrator's broader gates. Record Windows manual and live-provider checks independently. No Windows result is inferred from Linux or offscreen.
10. Package only through the existing release process; this documentation PR does not publish a package or final release.

No ordering step authorizes a merge or a write to main or claude/*. The current PR remains draft for review. The direct user's branch and new-file restrictions govern this task.

## 6. Additional panels and cards implied by repository plans

This is the complete fourteen-slot manifest inventory, so the nine detailed specs do not leave an implied extra application window undefined.

| Panel/card | Decision | Justification and existing contract |
|---|---|---|
| evidence | Reuse existing panel, do not duplicate | secondary/evidence_panel.py exists; multi-engine-evidence-panel.md sections0–17 define native-score separation, conflict preservation, setup and host migration. |
| unified | Reuse existing panel | unified/panel.py exists; unified-engine/07-ui-and-cli.md plus docs/modules.md S4b/IR-text notes define its own read model and code detail. Build-env overlay is a view contribution only. |
| leads | Reuse existing panel | pilot/panel.py and ui_leads.py exist; PIL integration plan and pilot/read_model.py own tie-aware ordinal leads and existing cve/match routing. KEV cannot alter its function ordering. |
| files | Reuse existing Files dock | pe_overview/panel.py exists; gui-preflight-inspection.md and guide/15-files-and-pe-overview.md describe verified bytes and PE rows. WBQ Build facts is a tab/card inside Files, not another dock. |
| series | Reuse existing Series dock | nway/panel.py exists; series-window.md owns read-only pair access. Its older window terminology is superseded by GUI migration M3. |
| search | New detailed spec here | Reserved slot and WB1 S7; required source-coverage and paged-result contract. |
| graph | New detailed spec here | Reserved slot and WB2 G5/G6; textual alternative plus bounded visual exploration. |
| strings | New detailed spec here | Reserved slot and WB3 S7b; comparable source basis and privacy-sensitive copy. |
| capabilities | New detailed spec here | Reserved slot and CAP-6a/6b; behaviour deltas with coverage and explicit run. |
| build_env | New detailed spec here | Reserved slot and DIE D5; includes BuildEnvCard and PreflightBanner contributions. |
| rules | New detailed spec here | Reserved slot and YRX R6b; derived-evidence consumer, not a second independent detection engine. |
| kb | Additional detailed spec here | Required by the KB workflow and manifest; composes product, file, pair, context and existing Leads. |
| kev | New detailed spec here | Reserved slot and K3; CVE context with independent global snapshot lifetime. |
| guide | Deferred stub spec here | Reserved slot; no fabricated lesson functionality. |

Additional cards/contributions are accounted for without new panel ids:

- BuildEnvCard,PreflightBanner,build difference tags and BuildTimelineStrip are owned by build_env.md and DIE D5/D6/D7. The unified consumer owns unified.build_section/unified.build_tag tips; it is not an extra prefix claimed by build_env.
- WBQ VERSIONINFO/manifest/export/API facts remain in Files under WBQ S5/S6. Pure PE parsers remain Qt-free. A field not wired into inspect_pe is not advertised as displayed.
- WBQ code colours and token marks attach to existing code panes through compose_selections/highlighter slots. They do not become another code window and cannot overwrite diff/search/anchor layers.
- LBL calibration scope is a display-policy contribution to existing evidence/unified surfaces. No calibrated probability is claimed from a placeholder or absent artifact.
- KB CVE context is a card on Updates and a stored ContextReport, not the older interrupting "what to look for" popup.
- Advisory/source inspectors show immutable provenance inside the owning panel or approved parented helper. They are not a standalone application or a new network permission.

Existing specs remain authoritative for those built surfaces. Rewriting each into a competing new panel spec would duplicate established behaviour and risk contradicting actual code; this plan supplies the dependency and ownership links instead.

## 7. Integrator asks and bounded risks

| Risk | Required guard | Owner |
|---|---|---|
| Existing AnchorRouter has one handler per kind | Preserve Leads cve/match ownership; no duplicate registration; test all emitted kinds for supported routing | GUI integrator |
| Pure panel spec importing heavy modules | Subprocess import boundary check; lazy Qt factory only | Each panel |
| Tool raw data missing/corrupt | Show missing/stale reason; never fabricate absent code or downgrade a conflict | Domain owner |
| Global KEV store shared with another process | Single installer policy or a separately designed lock; report unsupported concurrent installer use honestly | KEV service owner |
| Native worker cancellation/commit race | Test cancel before publication and committed outcome after publication; no false rollback text | CAP/DIE/WB3/YRX/KEV/KB owners |
| Task callback exceeds frame budget | Prepare off-thread, publish pointer swaps, instrument callback duration | Feature plus GUI |
| Search recents contain sensitive text | Existing local policy only; no source snippets/credentials; future opt-out is a separate settings decision | Search/settings owner |
| Rule export contains byte-derived content | Exact local preview, names off, secret gate and repo destination policy; no silent git writes | Rules owner |
| DiE may invoke Windows trust APIs | Blocked-network live acceptance or keep PE/stored-only path | Tool runner owner |
| Unverified source/version/licence assumptions | Runtime validated pin/engine stamp and release notice review, never copied abbreviated hashes | Packaging/tool owners |
| KB source-plan scope differs from current provider | Show actual scoped coverage and unverified status; no invented universal history or Server coverage | KB transport owner |
| Existing GUI/API differs from this prose | Read implementation; choose one adapter, list exact discrepancy and test it before changing shared interfaces | Assigned integrator |

No new dependencies are requested by this documentation. No licence statement is independently validated by this task. No external URL is a freshly verified reachable endpoint. These are explicit UNVERIFIED release checks.

## 8. Verification contract and remaining work

Static documentation review performed in this task: inspected newly composed text for the fifteen numbered sections, four-line tooltip structure, What length ceiling, duplicate What wording within this document set, absent placeholders, and path scope. This is text review, not runtime lint, test execution or implementation acceptance. The review found the KEV/anchor differences recorded in section2; those corrections must be applied by future adapters.

Required automated checks, not run:

- Pure import isolation for every panel declaration and domain view.
- Registry placement/shortcut/tip/claims/anchor checks through patchtrace panels check.
- One test for every documented state, remedy and disabled availability reason.
- Hostile text in every display/copy/report path; exact source and orientation checks.
- Generation changes, project switches, cancellation before and after commit boundaries, retained results and deterministic teardown.
- Lazy table calls at10000/100000rows, paged-search cursor boundaries, graph/text parity and hard limits.
- Tooltip completeness with every focusable child and popup included; a11y_audit, contrast per theme and declared Tab order.
- Focused pytest and ruff on eventual implementation changes; the integrator's full suite and frozen smoke under the existing release process.
- Native worker, tool and provider-specific tests from each feature plan, with live facts distinguished from injected tests.

Manual/live Windows checks, all UNVERIFIED: actual screen-reader output, Accessibility Insights roles, high contrast, reduced motion, DPI and monitor transitions, dock layout recovery, frozen style/plugins and FTS availability, installed external tool compatibility and isolation, EDR behaviour, real local servicing pairs, live network source availability and source licensing. Nothing in this task closes those gates.

Documentation delivery reaches all eight named panels, the implied KB panel, the existing-panel/card inventory and this build plan. Implementation, schema changes, tests, running applications, live research, packaging and release are outside this documentation task.
