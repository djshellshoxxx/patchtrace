# SPEC-31-F: Transactional Workflow, Desktop/CLI Integration, Recovery and Migrations

Status: developer-ready implementation workflow. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Depends on 31-A/B/C/D; E is optional. Owner: service/UX integrator. Preserve existing src/patchtrace/cli.py, service.py, persistence.py, ui.py, ui acquisition dialog, tooltips.py.

## F1. Measured existing integration points

At 2026-10-14 main inspection: ProjectService.create(older:Path,newer:Path,name:str,root:Path) creates one normal project; ProjectService.open, backup, _commit, swap_orientation already own lifecycle. The project SQLite and snapshots are under patchtrace.persistence.ProjectStore; enrichment.storage.EnrichmentStore coordinates additive derived data with guard/revision checks. src/patchtrace/ui.py already contains an AcquisitionDialog for SPEC-08 that performs filename -> Winbindex search -> explicit old/new -> consented download and creates project on GUI thread. DO NOT duplicate that dialog's worker machinery or present it as unimplemented. New kbcorrelation widget should either embed/reuse an extracted common acquisition controller or launch existing dialog prepopulated through a carefully reviewed additive interface; never copy its transport code.

Existing src/patchtrace/cli.py command names 'acquire', 'correlate', 'rank', 'flags', 'series' must retain argument semantics/exit status. Add nested 'kb' command by delegating into kbcorrelation.cli. src/patchtrace/tooltips.py apply_tooltip provides semantic what/why/source/status text. Register all new interactive controls except those exempted by established tooltip policy.

## F2. State transition table (complete acceptance subset)

A transition is allowed only when preconditions match current immutable investigation revision, and the resulting event includes plan digest and source evidence ids.

NEW + parse_valid -> IDENTIFIER_PARSED; invalid -> unchanged + PT-KBC-INPUT.
IDENTIFIER_PARSED + cached_lookup -> METADATA_READY|METADATA_PARTIAL|NOT_OBSERVED; network request without consent -> unchanged + PT-KBC-CONSENT.
METADATA_PARTIAL + provider_failure -> still metadata partial (never replace already valid results); resume/retry -> new revision.
METADATA_READY + ambiguous products -> NEEDS_PRODUCT; exact verified user selection -> PRODUCT_SELECTED.
PRODUCT_SELECTED + no credible file -> NEEDS_FILENAME; with file candidate(s) -> COMPONENTS_READY.
COMPONENTS_READY + no compatible pair -> NEEDS_OLDER|NEEDS_NEWER|LINEAGE_BLOCKED; else PAIRS_CANDIDATE.
PAIRS_CANDIDATE + unambiguous selected pair -> DOWNLOAD_PLAN_READY; a tie -> NEEDS_PAIR_SELECTION.
DOWNLOAD_PLAN_READY + exact consent -> ACQUIRING; stale plan or consent mismatch -> unchanged + PT-KBC-STALE/CONSENT.
ACQUIRING + both final verified files -> VERIFIED_PAIR; one direct 404 -> PARTIAL_ACQUISITION; delta base unavailable -> NEEDS_BASE.
VERIFIED_PAIR + confirmed project path + create success -> PROJECT_CREATED. Failure -> VERIFIED_PAIR and error, preserving staged verified bytes if retention policy permits.
PROJECT_CREATED + run started by explicit user action -> COMPARISON_PENDING; completed -> ANALYZED.
ANALYZED + E0 context -> CORRELATED_PARTIAL or CORRELATED; E1 unavailable never blocks E0.
Any active stage + cancellation -> previous committed snapshot plus CANCELLED attempt record, no advancing revision.

Event reducer pure: reduce(snapshot,event)->new_snapshot|KbError. Side effects run outside reducer and propose events containing operation generation ID; generation mismatch or closed Qt window discards late result. Serialize stage transitions on single writer and enforce expected_revision optimistic compare and exclusive project lock at commit. If a crash occurs, mark attempt interrupted, preserve last verified revision; startup never auto-fetches or runs Ghidriff.

## F3. Storage layout and transaction detail

Global cache: content-addressed raw official metadata snapshots and reverse-index tables in app-writable cache (not directly exposed as project blobs). Project attached context: kb_investigations, kb_investigation_revisions, kb_project_links, kb_analyst_decisions, kb_attempts and kb_derived_assessments are additive tables in existing ProjectStore database OR a documented service-managed extension with identical lock and backup semantics; choose one after auditing current ProjectStore. Do not create an independent uncoordinated second SQLite writer.

Every mutation:
(1) check lock, project UUID/revision/hash and feature schema;
(2) validate all source/evidence foreign keys and immutable bytes;
(3) BEGIN IMMEDIATE transaction;
(4) insert next immutable investigation revision plus source snapshot refs and attempt status;
(5) update one current pointer with expected prior revision;
(6) COMMIT; use atomic rename for separately staged raw objects;
(7) after commit notify UI, never before.
On fail roll back, leaving prior current pointer untouched. SQLite DDL must be explicitly transactional (existing enrichment tests found a historical DDL atomicity issue). Backup before first extension schema write, follow ProjectStore.backup conventions and inclusion of source blobs in backup/export. On restored project with missing external cache, source pointers degrade to 'missing source bytes', no phantom verification.

Cache key: (operation, normalized request, source connector versions, raw snapshot digests, product alias version, input project SHA/revision, rules and engine versions when relevant). No sharing derived assessments across projects unless artifact hashes and all relevant context match. Source cache may be reused offline without granting previously used network consent.

## F4. Consent rules and preview protocol

Network consent has exact operation IDs and URLs/host restrictions, expiry/in-memory scope, and may be revoked by cancel. Rendering a plan never triggers DNS. Discovery request and binary acquisition are separate consent steps. UI must show all planned known requests; if index traversal dynamically discovers new URLs, return NEEDS_ADDITIONAL_CONSENT with explicit new plan, unless user explicitly authorized a bounded same-host template+range operation. Never broaden grants silently. --offline blocks all calls including update/telemetry checks in the feature. Use existing networking abstractions and approved retry/redirect logic; do not add unrestricted urllib calls to providers.

Plan example shape:
~~~json
{
  "contract": "kbcorrelation/1",
  "plan_sha": "<64-lowercase-hex-of-canonical-plan>",
  "operation": "fetch-source-document",
  "exact_urls": ["https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2099-10001"],
  "allowed_hosts": ["api.msrc.microsoft.com"],
  "expected_project_revision": null,
  "expires_at": "2099-02-01T12:00:00+00:00",
  "reason": "User requested this synthetic CVE"
}
~~~
Replace placeholder hash with real calculated value in code fixtures. The sample illustrates schema only.

## F5. CLI grammar, JSON and exit mapping

Add 'kb' parser beneath current argparse subcommand tree with actions search, import, components, pairs, plan, acquire, attach, explain, export. Avoid nested duplicate --json declarations and argument shadowing. Search never implicitly fetches. Preserve current correlate as CVE-context-only. Use current CLI numeric exit-code meanings by inspecting tests before new command mapping; do not reinterpret code 3/4.

Command intent:
~~~text
patchtrace kb search KB5000001 --offline --json
patchtrace kb search KB5000001 --plan --json
patchtrace kb components <investigation-id> --product <scope-id> --json
patchtrace kb pairs <investigation-id> --product <scope-id> --file exampledrv.sys --json
patchtrace kb plan <investigation-id> --pair <pair-id> --json
patchtrace kb acquire <investigation-id> --pair <pair-id> --project <path> --consent-hosts <hosts> --json
patchtrace kb attach <project-path> --investigation <investigation-id> --json
patchtrace kb explain <project-path> --cve CVE-2099-10001 --json
~~~
All KB/CVE identifiers and paths above synthetic; placeholders explicitly documentation notation. --json stdout exactly one contract-versioned object; stderr progress only. Stable sort and Unicode-safe encoding. No credentials, local absolute paths or provider payloads in default JSON unless explicit data-inclusion option. Help examples and every argparse code path get subprocess golden tests.

## F6. GUI composition and reuse

Implement kbcorrelation/ui_model.py pure view models + ui_kbcorrelation.py dialog. Open from Investigation menu (two-line import/action hook) and existing-project context command. Stepper pages: Search/Coverage; Product rows; Component candidates; Version pair; Consent/Acquisition; Evidence/Report. Pages never become disabled solely because later optional engines are missing. Show source's last checked date and incomplete coverage directly beside KB results. All identity labels include architecture/release/build and provenance; keyboard can select rows and copy exact hashes.

One confirmation for proposed old/new plan explicitly lists: product/release/arch, KB and CVE links, file hashes, source URLs, intervening known updates, candidate provenance tier and ability to decline. Use existing AcquisitionDialog by a shared service/controller if possible; actual ProjectService.create remains on owning GUI thread, never QThread. After create, popup expected mechanisms only from validated local source facts and versioned rules; never from raw HTML/unsanitized advisory. User action launches comparison, not dialog construction.

Use worker lifecycle patterns from existing ui.py Worker and _release_thread, with generation counter + strong cancellation + close semantics. Prevent cross-thread QWidget mutation and SQLite use. New standard tooltip ids for all actionable controls in source select, product select, file candidate, pair, analyze, export and navigation. Text-only status plus accessible name (not color-only). Verify high-DPI and long product strings, translations/Unicode payloads, keyboard-only.

## F7. Staleness and upgrade tests

Invalidation triggers: newer KB advisory revision, source index coverage change affecting selection, product alias map update, changed source metadata, changed selected build or hash, project swap/reimport, match correction, analysis-run replacement or rule update. Raw evidence retained; old evidence no longer navigates into new run. Export stale history with explicit reasons.

Tests: quit while network pending, close dialog and reopen before worker response, cancel during second SHA verification, stale project revision between plan and commit, SourceRecord not found after cache prune, backup restore on clean machine with no global cache, Qt offscreen HTML-looking advisory text, multiple attached investigations, reanalysis while panel open, old project without KB tables, schema version too new, rollback on disk full. Existing acquisition search GUI continues to work unchanged.

## F8. Native frozen build gate

On Windows release ZIP: login-free metadata-only/offline replay, documented consented sources, search with ambiguity and partial data, import known old/new PE, create normal project, load and reopen, compare via configured supported engine or import fixture, show candidate view and export. Smoke includes dependency metadata, tooltip registry coverage, content-addressed snapshot copies, stale-state persistence, DPI and non-ASCII filesystem paths. Separate tests for Windows DLL/signature behavior and PA30 reconstruction; do not label them validated from Linux unit tests alone.

## Offline desktop implementation seam (2026-11-05)

The bounded first desktop journey imports a supported local advisory, searches a stored KB/CVE, requires explicit product selection, previews two analyst-selected AMD64 PE files, then creates and opens a separate project. Product-only starts are not implemented in the current domain/CLI contract; binary-only manual pair starts also have the explicit desktop route below; online discovery/download remains the existing consented acquisition route. The offline dialog never starts downloads or analysis. Pair previews retain advisory source references, hashes, lineage and attribution limitations.

`investigation_service.execute_request` consumes immutable plain requests on a task-local service and returns plain results; no workspace connection or project service crosses into Qt. Local `import_pair` previews return `investigation_revision`; create passes `expected_revision` and `expected_pair_id`. Under the existing workspace lock, mismatch rejects the commit with PT-KBC-STALE before state changes. Selected product architecture must match inspected files, and missing product mappings require a new selection. No serialized contract/schema additions are required.

A create-only project port prevents resume from adopting a concurrently created project. The dialog invalidates previews on every input edit. Closing/cancelling a creation waits for its completion and reports any retained path without adopting it. Open/adoption failure reports the path and preserves the previous project through the generic adoption transaction. The host checks the current service identity, close state and analysis worker before adoption. Target files are inspected as data only.

## Current project input starting point (2026-11-05)

The offline dialog offers an explicit **Use current project inputs** action when opened from a project. The host captures a frozen Python-only `CurrentProjectInputs(project_id, revision, root, older_json, newer_json)` snapshot using the existing ordered Artifact records serialized as JSON strings. The worker decodes each with the existing strict JSON decoder (including duplicate-key rejection), validates the existing Artifact model and exact `artifacts/<sha>.bin` ownership path, and hashes each copy with `VerifiedArtifactReader`. No project store is reopened and no second writer lock is acquired. UI/host code captures values only; file/hash work stays on TaskRunner.

Successful verification fills the local older/newer controls. Their original names, artifact ids, hashes and source project id/revision appear as **preview-only input origin**. This convenience does not attach the source project's annotations or assert a CVE/file relationship; persisted context remains the existing manually selected pair hashes and same-component decision. Hash-named copies require the existing explicit same-component checkbox even when captured original labels match. The existing local inspection adapter accepts an optional basename hint only for the exact captured paths: it reads/hashes the actual copied file, uses the existing Artifact name for manual display/component metadata, and checks observed SHA/size against the snapshot before returning to pair resolution. The name is not PE OriginalFilename authority or component/CVE identity proof. Ordinary CLI inspection keeps its existing path-basename behavior. KB/CVE search and explicit advisory product selection remain required, followed by the exact pair preview before creating a separate project.

Preview/create reverify the origin copies and refuse any resulting inspected pair hashes that differ from the captured artifacts. Editing either file field clears the preview-only origin. The host's GUI-only current-snapshot predicate checks service identity, project id/revision and ordered Artifact JSON. Stale current-origin results are discarded; if a create already wrote a project, its path is retained/reported without adoption. The original project service/lock survives verification, search, preview and failure. This is not a new product-only/binary-only advisory lookup semantic, has no wire/schema/database additions and never accesses the network or executes inputs.

The existing BinaryRef filename contract remains unchanged: captured original labels must normalize to .sys/.dll/.exe basenames. Unsupported original labels (including projects whose labels are already hash.bin names) return PT-KBC-UNSUPPORTED without prefill/preview. Label preservation for derived projects is a separate open contract. Distinct old/new artifact ids may share a hash/path: identical content with the same canonical label is handled by the existing identical-pair outcome; conflicting canonical labels on the shared path are explicitly unsupported rather than silently selecting one role label.

## Explicit binary-only desktop start (2026-11-05)

The offline dialog offers an explicit **Start from local files without advisory linkage** checkbox. The frozen Python request adds `manual_pair_start: bool = False`; this is an internal task value, not a serialized model/schema change. This mode rejects any investigation id, product scope id or expected investigation revision. It delegates preview and create to the existing `KbService.import_pair('new', ...)` route, whose manual pair rules and append-only analyst orientation/pair decisions remain authoritative. No advisory search, product selection or imported document is required. Product/build lineage and fix boundary remain unverified; no KB/CVE linkage is inferred.

Preview does not create an investigation and returns a null investigation revision. Create requires the exact preview pair id and re-inspects bytes; an investigation is created only during the existing commit. New/empty destination and create-only project port checks still apply. Any input or mode edit invalidates the preview; mode changes cancel pending preview work and discard late results. Advisory controls are disabled in manual mode and request construction omits their previous values. Switching back requires an explicit fresh advisory search. Cancellation/close during commit retains a completed project without adoption. Current-project input provenance remains preview-only and requires the existing explicit same-component confirmation. Product-only desktop starts remain unimplemented and require a separate domain contract.

## Offline investigation keyboard access (2026-11-05)

Each visible input label must identify its actual edit or product selector with a Qt buddy relationship and a distinct mnemonic. Composite file-picker rows associate the label with the line edit, rather than their non-focusable container; explicit accessible names and existing semantic descriptions remain available. Keyboard focus follows the displayed workflow: workspace, advisory import, KB/CVE search, product selection, older/newer files, destination, name, confirmation and actions. Disabled advisory controls in binary-only mode are skipped by Qt's normal focus traversal. A missing workspace preflight moves focus to that field while retaining the actionable status. These changes do not add network operations, persisted fields or project side effects. Native Windows UI Automation and high-DPI acceptance remain separate gates.

## Explicit desktop advisory sync (2026-11-05)

The investigation dialog retains local-only search/import and binary-only pairing. A separate online advisory action takes an explicit KB/CVE and comma-separated month scope (existing maximum 24 documents), then builds the existing `sources.net_plan.IndexPlan` without requesting anything. Its plain-text preview shows every exact GET URL, both fixed headers (Accept and User-Agent), hosts, all caps, source limitations and the plan digest; the strict JSON representation accompanies the readable rendering. This dialog uses a bounded 64 KiB details view so the full supported 24-month plan remains visible, rather than inheriting the generic 4,000-character preview truncation. The analyst must separately choose **Fetch exactly this advisory plan**. That action grants only the displayed host set and digest for one operation; consent is neither remembered nor inherited by other requests.

Internal frozen task requests add `source_months`, `source_plan_json`, `consent_hosts` and `consent_plan`, plus `plan_sources` and `sync_sources` operations. This is an internal Python seam, not a serialized contract/model addition. The backend strictly decodes the size-capped IndexPlan JSON, rebuilds the current plan from the captured month scope, checks equality and verifies exact consent before calling the existing hardened CVRF transport. Cancellation reaches that transport; each successfully parsed document is checkpointed through the existing WorkspaceStore, retaining official-host TLS provenance without upgrading a local import's authenticity. Partial/cancelled work preserves already committed sources and reports requested month outcomes. No KB, CVE, local path, file hash or project content is sent in these month-only URLs.

After a completed sync the backend searches the local index through the existing KbService and the dialog resumes explicit product selection and the existing local-file preview/create/adopt route. No binary is fetched by this action. Any edited field, mode change, cancel, other operation or closed dialog invalidates the displayed plan; old-generation callbacks cannot restore it. A failed or partial provider response is shown with retained source/search evidence, never as a complete live-source qualification. Live endpoint compatibility remains unverified until its separate evidence gate. Online candidate discovery/download, product-only start and the full online acquisition journey remain partial and require later independent work.

## Saved-index candidate inspection and explicit selection (2026-11-05)

The desktop investigation adds an explicit component basename and an **Inspect saved index candidates** action after advisory/product selection. This worker operation reuses KbService.pairs with that filename and current selected scope; it performs no network request. It preserves domain candidate order, grade, tier, uncertainty reasons, intervening-update window and byte-verification state. Validated IndexPort rows supply per-side architecture, size, file-version, observed-build and record-hash claims for display. Those are saved-index claims, not verified local binary metadata or proof of a CVE repair. Unsupported scope, absent record, skipped rows and missing candidates remain explicit domain outcomes.

The selector starts without a chosen pair. A separate **Preview selected index pair** action captures the full pair id, investigation revision and candidate-snapshot digest in an immutable request. Backend re-resolution must match the captured KB/CVE with the stored investigation lead, and match that revision, filename, scope and digest; only then does existing KbService.plan build its metadata-only zero-request preview. The returned preview is distinct from a local-file preview and cannot enable project creation or grant download consent. Source/candidate changes before or during preview return stale without advancing the investigation or creating files. Input edits, product/mode changes and cancellation invalidate the list/selection and stale callbacks are discarded.

The internal task seam adds `candidate_pairs`/`candidate_preview` operations plus `component_name`, `candidate_pair_id` and `expected_candidates_digest`; no serialized contract/model changes. Existing manual/current-project pair fields and hash-bound project creation remain unchanged. Actual Winbindex retrieval and candidate acquisition remain separate pending steps requiring the existing exact request plan and explicit consent; this slice invokes neither network nor acquisition.

Candidate snapshot consistency amendment: each candidate worker binds the existing KbService resolver and pure planner to a private read-only FileIndex snapshot. Validated rows and skipped-entry counts are captured once per filename for that selected scope; all pair decisions and displayed claims reuse those immutable rows. Before returning, compare current underlying availability/rows with the capture and return PT-KBC-STALE on replacement. This prevents pair decisions from one saved record being combined with provenance from a later atomic replacement. The snapshot adapter does not implement ranking, write cache data or permit acquisition; normal final-check pathname races remain outside an atomic filesystem transaction claim.

## Explicit desktop Winbindex metadata refresh (2026-11-05)

The component filename has an optional metadata-request preview and a separate **Fetch exactly this index metadata plan** action. The worker delegates to the existing `sources.winbindex_fetch` plan renderer and refresher; its internal frozen operations are `plan_metadata` and `refresh_metadata`, reusing `component_name`, `source_plan_json`, `consent_hosts` and `consent_plan`. No new serialized model, transport, parser or publisher is introduced. Public basename normalization and the backend's strict captured-plan/host/digest verification remain authoritative. Only that basename is transmitted; local paths, file hashes, projects and KB/CVE identifiers are not sent.

The details view displays the exact metadata URL, headers, host, every cap and digest before separate consent. Monthly advisory and Winbindex metadata previews are distinct and mutually exclusive: every edit, mode/candidate change, cancellation, close or other operation clears both grants; only the currently displayed preview can enable its corresponding fetch action. Consent is consumed by that one operation and never persisted. Cancellation reaches the existing refresher; a late completed cache publication is retained but stale/closed callbacks cannot populate the current dialog or adopt a project.

A successful refresh shows the backend's raw-byte SHA-256/size, source URL, retrieval/source dates and date basis, saved path, parser counts/warnings and third-party/TLS authenticity limits. The analyst then explicitly inspects saved-index candidates through the existing action after selecting the advisory product. Neither refresh nor candidate inspection downloads a binary or enables project creation. Original local/manual previews and their measured hashes remain authoritative; full candidate binary acquisition and native/live qualification remain later gates.
