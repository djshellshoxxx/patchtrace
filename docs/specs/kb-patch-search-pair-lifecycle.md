# SPEC-32B: Verified Binary Pair Eligibility, Session Storage, and Crash Recovery

Status: expanded developer specification (2026-10-14); documentation only.
Parent: docs/specs/kb-patch-search-and-pair-resolution.md
Source data: docs/specs/kb-patch-search-source-adapters.md

## 0. Engineering decisions resolved here

SPEC-32 must distinguish four claims: a product-KB-CVE advisory association, the product lineage of a concrete binary, a pre-/post-update fix boundary, and attribution of changed code to a CVE. These cannot be folded into a single confidence score.

PatchTrace currently uses a strict project.sqlite3 schema version in ProjectStore. This expansion therefore selects an **optional versioned companion SQLite store** (project-root/patch_search.sqlite3) instead of altering the existing ComparisonProject schema or adding mandatory project tables. A normal project remains valid and usable if the companion store is absent, corrupt, stale or not writable.

A successful existing ProjectService.create operation and a successful sidecar attachment are two independent commits. There is no cross-database atomic transaction. Any interrupted attachment MUST preserve the created project and offer idempotent repair. This supersedes general language in the initial SPEC-32 document implying one all-or-nothing transaction across both databases.

Windows servicing / PSFX reconstruction is deferred from MVP. A current Microsoft cumulative update can require a prerequisite checkpoint cumulative update, and offline DISM servicing may leave packages install-pending. A successful DISM process exit is not proof that a complete target patched PE is ready.

## 1. Binary identity and product compatibility

BinaryRef MUST distinguish:
- sha256: SHA-256 over exact bytes, lower-case 64-hex. Compare against expected third-party index hash; recompute before promotion.
- filename: normalized PE basename (SPEC-08 format rules).
- machine: PE IMAGE_FILE_HEADER.Machine; same-machine requirement for automatic pair.
- size: actual bytes and separately claimed source size.
- file_version, product_version: typed version tuple or UNKNOWN; not lexicographic strings.
- windows_release, build_branch, channel and architecture: source-qualified or UNKNOWN.
- product_id: source-qualified exact product identifier or unverified analyst mapping, never product display name alone.
- debug_identity: optional RSDS GUID, age and PDB string, corroborative only.
- signature_state: trusted, valid_untrusted, invalid, unsigned, not_checked, indeterminate; offline revocation may be indeterminate.
- source_kind: symbol_index, imported_pe, offline_image, package_manifest, manual.
- availability: downloaded_full_pe, supplied_full_pe, delta_only, absent.
- provenance: raw source digest and specific pointer, plus verification method/time.

A hash match against Winbindex proves correspondence to its third-party record; it is not by itself proof of Microsoft authorship. Authenticode/catalog identity and online revocation validation are separate optional checks.

## 2. Pair validation: ordered, typed, and explainable

Validation order:
1. Resolve two exact input references and preserve the analyst-selected side order.
2. Identify both as complete parseable PE files; delta/payload bytes must be blocked.
3. Verify sizes and SHA-256; distinguish missing expected digest from mismatched digest. Existing ProjectService may permit imported PE files without vendor reference hashes; label supplied/local source accurately.
4. Require distinct SHA-256; two identical file contents are not a meaningful patch pair.
5. Require same exact basename for automatic same-component pair, and identical compatible PE machine family.
6. Establish product/build lineage from source-backed identity. A cross-product disagreement blocks automatic selection; ambiguous lineage allows explicitly labeled exploratory manual comparison.
7. Derive temporal order only within a proven comparable release/build branch, from numeric version and independently attributable release/update metadata. Never lexical sort versions and never infer pre-fix state from date alone.
8. Evaluate fix boundary independently from older/newer ordering using source-backed vendor fixed versions, applicability, supersedence and selected CVE. UNKNOWN remains UNKNOWN.
9. Require an explicit analyst approval of pair and limitations before acquisition or project create.
10. At commit, re-evaluate exact ordered hashes, file fingerprints, source snapshots, product, project destination and consent scope to prevent stale selection.

Pair state enum:
- VERIFIED_BYTES_SAME_LINEAGE: full PEs, distinct verified hashes, matching component and supported compatible product lineage.
- EXPLORATORY_UNKNOWN_BOUNDARY: files can be compared but fix location not established.
- VERIFIED_PRE_POST_BOUNDARY: additionally there is vendor-source-backed evidence supporting earlier pre-fix and later fix-bearing product build. This state never implies a CVE's changed function is known.
- INCOMPATIBLE_MACHINE; CROSS_PRODUCT_CONFLICT; IDENTICAL_CONTENT; DIGEST_MISMATCH; DELTA_ONLY; NO_COMPONENT; NO_OLDER; NO_NEWER; UNKNOWN_SOURCE; ORDER_UNVERIFIED.

The boundary status, binary verification status, and localization status are separate fields; don't encode them as one enum that implies proof.

### Required explicit cases

| Condition | Project permitted | CVE-specific label |
|---|---|---|
| Two verified x64 full PE revisions from same supported lineage | Yes | Investigative pair; pre-fix may still be UNKNOWN |
| Two hashes differ but both binaries are after the same KB fix | Yes | Not a pre-/post-fix pair; no vulnerability fixed claim |
| Older is full PE, newer only PA30/PSFX without exact base | No automatic project | Reconstruction unavailable |
| Two identical hashes | No automatic patch pair | No byte change |
| x64 vs ARM64 of same filename | No automatic pair | Incompatible arch |
| Same basename across unrelated Windows release families | Manual exploratory only | Applicability unknown |
| Vendor/third-party filename metadata only, unsigned/not checked | Yes if PE identity/hash acceptable | Authenticity indeterminate |
| CVE product explicitly known_not_affected | May compare for general purposes | No applicable CVE fix claim |
| Advisory lacks component filename | Manual filename choice | No invented file candidates |
| User imports two complete PEs with no expected remote hashes | Existing project can be created | Local integrity computed; vendor association unknown |

## 3. Immutable PairAcquisitionPlan

Proposed fields:
- contract: patch-pair-plan/1
- plan_id: domain-separated digest of canonical payload
- kb, selected source-qualified product variant ID, selected CVE IDs
- ordered older and newer BinaryRef identities and exact expected SHA-256/size/machine
- filename, architecture, release family, fix-boundary rationale and source pointers
- source snapshot digest set
- URL request preview (approved origin/method only; no time-limited redirect tokens)
- destination path policy (new/nonexistent or empty) and user-selected name
- consent digest bound to exact planned host/requests
- plan_created_utc, planned_state, known blockers and explicit analyst overrides

Plan generation has no network or disk mutation. Download execution must reject a plan if source identities or candidate hashes differ from what was approved. A low-trust data field is never passed as a shell argument.

## 4. State machine and recoverable outcomes

Main flow:

    DRAFT
      -> SOURCES_SELECTED
      -> SEARCHED
      -> PRODUCT_SELECTED
      -> COMPONENT_SELECTED
      -> PAIR_PROPOSED
      -> PAIR_APPROVED
      -> ACQUISITION_PLANNED
      -> VERIFYING_BOTH
      -> READY_TO_CREATE
      -> PROJECT_CREATED
      -> CONTEXT_ATTACHED
      -> ANALYSIS_PENDING
      -> ANALYSIS_COMPLETED
      -> TRIAGE_AVAILABLE

Additional states:
- SCOPE_REQUIRED when no bounded search corpus is selected.
- PARTIAL_SOURCE when some providers fail but useful source data remains.
- MANUAL_IMPORT_REQUIRED when no complete source-backed binary pair is available.
- CANCELLED_BEFORE_CREATE: remove ONLY operation-private staging; no incomplete project.
- PROJECT_CREATED_CONTEXT_PENDING: preserve valid project after sidecar failure; allow attach retry.
- NEEDS_REVALIDATION if hash, product, source revision or analyst selection changes.
- TRIAGE_STALE when run, orientation, match override or rule evidence changes.
- SOURCE_MISSING when cached source bytes can no longer be verified.
- SIDECAR_UNAVAILABLE: nonfatal feature-only error, main project opens normally.

Transitions must be explicit, validated, append-only auditable, cancellation-aware and idempotent. A provider failure is never recorded as "no CVEs"; a missing binary is not a global search failure.

## 5. Companion persistence design

Existing inspected code: src/patchtrace/persistence.py ProjectStore checks PRAGMA user_version == SCHEMA_VERSION and rejects mismatched schema; src/patchtrace/service.py ProjectService.create creates the normal project and controls original artifact identities.

Proposed folder layout:

    project-root/
      project.sqlite3
      artifacts/<sha256>.bin
      patch_search.sqlite3       [optional]
      patch_search/objects/      [optional source snapshots, SHA-keyed]
      patch_search/journal/      [optional recovery markers]

Do not write new columns into ComparisonProject or change its exactly-two-artifacts requirement.

Suggested versioned sidecar schema:

    CREATE TABLE patch_metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE patch_source_snapshots (
      snapshot_id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      bytes_sha256 TEXT NOT NULL,
      retrieved_utc TEXT NOT NULL,
      source_schema TEXT NOT NULL,
      provenance_json TEXT NOT NULL
    );
    CREATE TABLE patch_sessions (
      session_id TEXT PRIMARY KEY,
      revision INTEGER NOT NULL CHECK(revision >= 0),
      state TEXT NOT NULL,
      project_id TEXT,
      project_revision INTEGER,
      older_sha256 TEXT,
      newer_sha256 TEXT,
      payload_json TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL
    );
    CREATE TABLE patch_events (
      event_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      session_revision INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      event_sha256 TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_utc TEXT NOT NULL,
      FOREIGN KEY(session_id) REFERENCES patch_sessions(session_id)
    );
    CREATE TABLE patch_triage_views (
      view_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      run_id TEXT NOT NULL,
      dependency_sha256 TEXT NOT NULL,
      state TEXT NOT NULL,
      view_json TEXT NOT NULL,
      FOREIGN KEY(session_id) REFERENCES patch_sessions(session_id)
    );

Implementation:
- Sidecar owns its own schema version and migration tests, independent of existing SCHEMA_VERSION.
- Transaction with BEGIN IMMEDIATE and expected-revision compare-and-swap for every session write; enforce unique IDs and foreign keys.
- Reuse existing ProjectLock ownership discipline. Establish one lock order: already-open ProjectService ProjectLock first, then sidecar transaction, and never re-acquire ProjectLock recursively. GUI thread owns database writes; workers return immutable typed result objects via Qt signals.
- Validate digests and Pydantic schema on every read. No unbounded dynamic JSON, strings, absolute-path exports or mutable provider objects.
- Read-only main project open never creates or migrates sidecar; no sidecar means Patch Search pane hidden/not attached.
- If sidecar file corrupt: mark only Patch Search unavailable with repair/export-copy option; core project remains open.
- For reproducible offline review, project-contained source blobs or a verified portable bundle must be available; garbage collected global caches cannot be the only evidence source.
- Prefer snapshots referenced by SHA and copied at most once. Never duplicate PE binaries per CVE.
- Include sidecar and source objects in optional Patch Search backup/export path and verify restoration; do not assume the existing ProjectService.backup automatically captures newly added files.

### 5.1 Two-phase attach and idempotent recovery

A normal ProjectService.create commit and a sidecar attach cannot be one atomic SQLite transaction. Required algorithm:

    1. Validate pair and destination; write plan/recovery marker to owned staging.
    2. Create project via existing ProjectService.create with both verified PEs.
    3. Record immutable actual project ID, revision and ordered artifact hashes.
    4. Initialize optional sidecar, BEGIN IMMEDIATE, guard project identity and
       expected session revision, commit attachment with canonical payload hash.
    5. Mark attach complete, then retire own recovery marker.
    6. If interrupted after step 2, leave project usable and state CONTEXT_PENDING.
       Retry step 4 using same stable session/plan identity. Never delete project.
    7. If interrupted before project create, remove only operation-owned staging;
       user-supplied binaries and pre-existing project folders are never deleted.

Power-loss/restart tests must kill process after EACH step and verify that no earlier project or user file is damaged.

### 5.2 Staleness fingerprint

Triage view dependency digest includes:
- session ID, selected product variant, pair plan ID;
- project ID + project revision;
- ordered older/newer actual artifact SHA-256 and orientation;
- current analysis run ID, raw output hash, engine evidence set IDs/digests;
- source snapshot SHA-256 list;
- analyst match override revision;
- hypothesis ruleset digest and mapper/parser versions.

Any change invalidates only dependent derived triage views; retained advisory snapshots/notes remain historical and immutable. Conservative full project revision invalidation is allowed in v1; optimize to partial dependency hashes only after regression coverage exists. A stale result must never display as a fresh negative finding.

## 6. Windows update servicing and PSFX fallback

Microsoft explains forward/reverse differential hydration against a release base in its PSFX whitepaper. Also, current offline DISM documentation describes checkpoint LCU prerequisite ordering and packages that can remain install-pending. See:
- https://learn.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper
- https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-operating-system-package-servicing-command-line-options
- https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-or-remove-packages-offline-using-dism

V1: do not run DISM, do not silently execute packages, and do not claim generic CAB extraction recovers full PEs. Offer verified manual full-PE import.

Future package adapter contract (separate opt-in module):
- inspect_package -> source manifest OR UNSUPPORTED
- assess_offline_image -> product/arch/build/prerequisites
- plan_servicing -> strictly offline immutable plan + expected disk budget
- apply_to_disposable_image -> operation result; no DISM /Online
- verify_postcondition -> actual hydrated full target PE, SHA, machine, product lineage, update state
- extract_pair -> both complete verified PEs or explicit blocker

Explicit statuses: NEEDS_BASELINE, NEEDS_CHECKPOINT, UNSUPPORTED_DELTA, SERVICING_PENDING, MISSING_COMPONENT, PE_INVALID, HASH_MISMATCH, VERIFIED_PAIR. DISM exit code 0 is not the final acceptance test. A product whose servicing remains pending cannot be labeled patched.

## 7. Crash/error negative tests

B01 identical pair hashes => no automatic project.
B02 hash mismatch => stage never promoted.
B03 ARM64/x64 mix => incompatible machine.
B04 cross-release same filename => analyst exploratory selection only.
B05 both binaries contain CVE fix => older not called vulnerable.
B06 unknown filename => no fake component auto-selection.
B07 unverified signature => not called trusted Microsoft binary.
B08 PA30/PSFX without exact source base => manual import blocker.
B09 source/product known_not_affected => no false CVE-specific claim.
B10 orientation swap invalidates pre/post and triage.
B11 third-party source refresh failure preserves last known-good with stale marker.
B12 cancellation mid-download deletes only stage.
B13 crash immediately after ProjectService.create => valid project + attach retry.
B14 crash during sidecar transaction => no partial session row and project stays usable.
B15 simultaneous attach attempts => atomic revision guard, no lost update.
B16 corrupt sidecar => ordinary project still opens.
B17 copying project offline with source snapshots => auditable provenance survives.
B18 referenced analysis run changes => prior localization marked stale.
B19 product variant changed mid-download => reject stale plan.
B20 source object missing from cache => SOURCE_MISSING not "no evidence".
