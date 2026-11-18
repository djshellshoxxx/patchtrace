# PW-01: Bounded KB file inventory CSV and support links

Status: approved implementation contract; acceptance is tracked separately.
Canonical alias: PW-01. Parent: KBC-G (SPEC-34), with KBC-A/D/F/H.
This spec adds KB file inventories. It does not change strings CSV export,
CISA KEV import, CVE attribution, or supported binary-analysis architectures.

## 1. Ingress and source evidence

The instruction to import only strict JSON continues to govern internal records,
provider output and exchange documents. Two explicit external source adapters are
allowed: the existing validated CVRF XML adapter, and this bounded CSV adapter.
Saved support HTML is parsed as inert link metadata only. There is no general
format auto-detection, script execution, spreadsheet invocation or target execution.

Inspected upstream: https://github.com/originsec/patchwatch at
`5a221622b587a80ed967ebf3fa656f51467f378d` (2026-11-18 UTC).
The files `crates/patchwatch/src/kb/csv.rs`, `kb/tier1.rs`, and their
`tests/fixtures/kb_file_information.csv` and `support_kb_topic.html` were read.
Root LICENSE is Apache-2.0; root NOTICE identifies Copyright 2026 Prelude
Research, Inc. Any copying must preserve that license, notice and modification
attribution. This slice uses independently written Python and authored synthetic
fixtures; no upstream source or fixture is copied. Upstream samples are evidence
of upstream behavior, not proof of live Microsoft format or redistribution rights.

Observed upstream shapes: unquoted comma-containing Windows section banners;
English File name / File version / Date / Time / File size headers; architecture
banners x64-based, x86-based, arm64-based; quoted comma-grouped file sizes.
Upstream permissive digit stripping, first-link selection and unconstrained
redirect following are not part of this contract.

## 2. Pure parser interface and budgets

`inventory_csv.parse_inventory(raw: bytes, context: InventoryContext, *,
limits: InventoryLimits = DEFAULT_LIMITS, cancel=None) -> CsvInventory`.
The parser is Qt-free and network-free, has no filesystem/database writes and
never executes a command. Cancellation raises PT-KBC-CANCEL; fatal input or
resource errors raise SourceError with PT-KBC-INPUT/SOURCE/LIMIT. Nothing is
published on fatal failure. The caller retains prior successful state.

`InventoryContext` is a strict frozen record: kb (normalized KB identifier),
product_scope_id (optional SHA-256), product/release/build (optional bounded
asserted text), architecture (amd64/arm64/x86/unknown, default unknown), delimiter
(comma/semicolon/tab, default comma), locale (invariant/en-US/de-DE, default en-US).
These are explicit analyst context, not authenticated claims from a file header.

Defaults: raw bytes <=16 MiB, decoded characters <=16 MiB, fields <=65,536
characters, a logical record <=262,144 characters, <=32 columns, <=100,000
logical records, <=5,000 retained entries, <=1,000 retained diagnostics, <=1,000
sections, parser wall time <=10 seconds with cooperative checks between bounded
records. Hard byte/text/field/record/column/section limits are fatal. Entry and
logical-record limits return explicitly partial/truncated results; diagnostic
omissions are counted. Limits must be positive and cannot exceed hard ceilings.
Raw bytes are bounded before decoding; no global csv.field_size_limit mutation.

Accept UTF-8 with or without BOM, and BOM-marked UTF-16 LE/BE. Reject malformed
encoding, UTF-32 and unmarked UTF-16. Delimiters are explicit, not guessed. Use
strict quoting, accept quoted delimiters/newlines and LF/CRLF, reject malformed
quotes and text following a closing quote. Blank records do not become data.

Required English headers are File name and File version (case-insensitive,
trimmed for matching). Optional headers: File size, Date, Time, Architecture,
Product, Release, Build. Reordered columns and repeated headers are supported.
Duplicate normalized header names or missing required headers are fatal.
Undocumented localized headers are rejected, not mapped heuristically.

A bounded banner can contain an unquoted comma, as in the inspected upstream
sample. Recognized architecture aliases are x64/amd64, arm64/aarch64 and x86/i386,
including the documented '-based'/' based' section spellings. Recognize banners
structurally, never by finding an architecture word anywhere in a data field.
The banner text starts in the first field; an empty filename followed by an
architecture token is a rejected data row and cannot change section scope.
An unknown section resets architecture to unknown; it never inherits the prior
section architecture. Conflicting column, section or explicit context architecture
is retained as a conflict and cannot become an eligible analysis selection.
Product/release/build spelling and unknowns remain visible; do not infer OS build
from a binary version, collapse products, or choose the highest version.

File versions retain original text and exact four integer components when valid;
unknown or unsupported versions stay unknown. File sizes use exact integers up to
2**64-1. en-US accepts properly grouped commas; de-DE accepts properly grouped
periods; invariant accepts ungrouped ASCII digits only. Invalid/ambiguous grouping,
fractions, signs and exponent notation do not become a fabricated size. Dates and
times are retained as original text; there is no inferred locale, time zone or
chronology. Invalid optional metadata produces a visible diagnostic and an
unknown value, not silent digit stripping.

Use the existing strict PE basename validator for eligible PE names. Directory
separators, drive/UNC/ADS, traversal, reserved Windows names, trailing dot/space,
controls/bidi and formulas are rejected as filenames. A safe non-PE basename may
be retained as descriptive-only metadata. Raw spelling remains in the row and the
original immutable bytes; it never becomes a filesystem destination.

## 3. Frozen records, identities and row references

Models live in `kbcorrelation/inventory_contracts.py`, using strict frozen
Pydantic records and existing identity/text validators. `CsvRecordRef` contains
raw_sha256, logical_record (1-based), line_start/line_end (1-based inclusive) and
section_index (0-based). A quoted multiline CSV row is one logical record but
can span several physical lines. This is a CSV record reference, not a JSON Pointer.

`InventoryEntry` fields: entry_id, reference, original_fields, original_filename,
basename (nullable), original_version, version_components (nullable),
original_size, size_bytes (nullable), date_text, time_text, architecture,
architecture_basis (column/section/context/unknown/conflicted), product, release,
build, state (metadata-only/unknown/conflicted/descriptive-only), duplicate_of
(nullable entry ID), conflict_group (nullable ID), diagnostics (fixed code tuple).
Every accepted claim is retained, including duplicates and conflicting versions.

`CsvDiagnostic`: code, message, level (warning/error), reference (optional).
`InventorySection`: index, banner, architecture, reference.
`CsvInventory`: contract='kb-file-inventory/1', parser_version=1, inventory_id,
raw_sha256, raw_size, encoding, context, limits, entries, sections, diagnostics,
records_scanned, accepted_count, rejected_count, duplicate_count, conflict_count,
diagnostics_omitted, truncated, status (complete/partial).
Accepted count is the retained accepted rows including duplicates; conflicts
count rows in conflicting claim groups. Rejected count is scanned data rows
rejected, not skipped blank/header/banner rows. Truncation means unseen rows may
remain; do not present a guessed total.

The inventory ID hashes parser version, raw digest, canonical context and all
validated parsing limits (including max_seconds serialized as canonical JSON
text). Lower budgets can change partial results, so replay uses those exact
captured budgets. Wall-time exhaustion is fatal, never a time-dependent partial
identity. Entry
IDs hash inventory identity plus logical record. Duplicate identity compares
normalized metadata within exact product/release/build/architecture scope;
product, release and build comparison keys use the same trimmed case-folded
semantics as source/context agreement, while each original spelling remains in
its entry and raw fields. Case variants cannot hide duplicates or conflicts.
different original records remain separate claims. Conflicting metadata for a
shared basename in the same scope is grouped, never resolved automatically.
Timestamp, elapsed time, random UUID and filesystem path never influence
parser/entry identity. A fetched import separately binds its exact retrieval
receipt, including acquisition time; a local import's timestamp is not identity.

## 4. Saved HTML and exact network plans

`sources/support_links.py` accepts bounded saved HTML bytes and an explicit
validated page URL. Use inert HTML parsing; ignore script/style content and HTML
base tags. Return every plausible file-information link with anchor text,
context, original href, resolved URL, acceptance flag and fixed rejection reason.
Keep multiple candidates for selection. Exclude servicing-stack/SSU, hash/checksum
and unrelated links using anchor and nearby context. Relative resolution requires
an explicit approved support page URL. Local HTML remains unverified local data.

`sources/inventory_fetch.py` reuses acquisition Transport for bounded reads,
retries, cancellation and deadlines. A new operation-specific immutable plan
contains kind (support-page/file-inventory), exact ordered URL chain, exact hosts,
GET headers, byte/time/redirect caps and plan_sha. Neither monthly CVRF nor symbol
consent grants this operation. Offline refuses before DNS/socket/openers run.

Only HTTPS, port 443, no userinfo/fragment/control/backslash, exact hosts
support.microsoft.com, go.microsoft.com and download.microsoft.com; no suffix
wildcards. Support-page requests remain support.microsoft.com. File inventories
may use go.microsoft.com/fwlink/ then download.microsoft.com/download/.
These are candidates grounded in the pinned upstream; live capture separately
verifies deployed redirects. Other hosts require a later spec/evidence change.
Reject local/private/link-local/non-global literal or resolved destinations.
The production connection must use the address it validated, with TLS hostname
validation for the original approved hostname. No inherited proxies.

Every request URL, including a redirect target, must be in its exact approved
position in the plan. An unexpected safe redirect returns PT-KBC-CONSENT with a
new proposed preview; it does not request that target. A changed URL/host/cap
requires a fresh digest/consent. Max four redirects, <=16 MiB CSV / <=4 MiB HTML,
10 seconds per connection, 60 seconds total, existing bounded retry policy.
Preserve original/final URLs and actual redirect chain in a fetched receipt.
No automatic link follow-up occurs during HTML parsing or after page retrieval.
The returned source must have complete HTTP framing: reject malformed or
duplicated Content-Length, ambiguous Content-Length/Transfer-Encoding, unsupported
transfer/content encodings and an unexpected Content-Range. A chunked transfer
value must exactly match the reader's case-insensitive `chunked` token; do not
trim padding into a token the underlying reader would fail to decode. If Content-Length is
present, the received byte count must equal it before a fetch receipt is published.
A well-formed CSV prefix from a prematurely closed response is never complete.

## 5. Persistence and provenance

`inventory_store.py` uses the existing WorkspaceStore connection, content-addressed
objects, transaction/fault hooks and strict JSON loader. A versioned additive
`kb_inventory_imports` table stores immutable import records. Existing advisory
schema/version and old readers remain compatible; table creation is transactional
and occurs only for writable stores. Read-only/old workspaces with no table return
an empty inventory set. Existing raw-object verification/orphan reporting must
account for this extension. Never store invented advisory edges from CSV rows.

`InventoryImport` contains import_id, source: SourceDoc (kind kb-file-csv), parsed:
CsvInventory, asserted_source (optional unverified URL), and retrieval (optional
verified fetch receipt). SourceDoc is of original CSV bytes, not normalized JSON.
SourceDoc local-import always has uri=None and unverified-local-file. A supplied
URL is stored only as asserted_source. A fetched source uses tls-allowlisted-host
and preserves exact request provenance, not a signature/authorship claim.

Import ID binds parsed identity and source provenance (not import time); repeat
imports are idempotent, while different contexts and local/fetched provenance
remain separate immutable claims. Raw bytes are written before one transactional
row insertion; failure can leave only an unreferenced object, never half a record.
On replay verify raw digest/size, reparse with captured context/version, and compare
the deterministic parsed record. Reject damaged state without overwriting it.

## 6. KB service, selection, CLI and desktop

Keep storage/parser logic outside Qt. KbService delegates to inventory_service.py:
import_inventory(path, context, ...), inventories(...), inventory_details(id,...),
select_inventory(investigation, import_id, entry_id, product, expected_revision,...),
support_links(path,page_url), inventory_plan(...), fetch_inventory(...).

CLI namespace: `patchtrace kb inventory import FILE --kb KB...`, `list`,
`show IMPORT_ID`, `select IMPORT_ID ENTRY_ID --investigation ID --product ID`,
`links HTML --page-url URL`, `plan URL --kind support-page|file-inventory
[--redirect-url URL ...]`, `fetch --plan-file FILE --consent-plan SHA
--consent-host HOST [--kb KB...]`. Reuse --workspace/--json and enrichment-cli/1
with kbcorrelation/1 results; exits 0 success, 2 input/unsupported/consent, 3 runtime
or partial, 4 empty, 5 cancelled. Import supports explicit delimiter/locale/product/
release/build/architecture context. List/show expose source, accepted/rejected/
duplicate/conflict/truncation counts, raw record refs and remedies; filters are
bounded and do not change stored data. Saved-file import, list and selection are
offline operations. Plan never makes requests; fetch requires exact consent.

Selection explicitly binds an entry to the investigation's existing selected
product and recorded search scope. Require matching KB and explicit product scope,
AMD64 PE eligibility and no conflicting architecture/product/build. Unknown product
mapping remains unknown until the analyst supplies an explicit scope assertion;
show that assertion. Never select a first row/pair automatically. Record selected
import/entry IDs in an AnalystDecision; ComponentHint gains a backwards-compatible
inventory_refs tuple of CsvRecordRef/import identity records. Do not misuse its
existing JSON-Pointer SourceRef for raw CSV. Preserve every selected source claim.

Selection requires the exact current investigation revision, an explicit product
scope ID and an explicit analyst scope assertion when the import lacks that ID.
Any supplied scope ID or known product/release/build must agree with the selected
scope; a user assertion cannot override contradictory source metadata. The selected
scope must be AMD64 and not mapping-conflicted. The CSV entry must be a valid
AMD64 PE basename with known version and no metadata conflict. A missing size
does not invent byte identity or prevent filename-only selection. The KB must
belong to the lead within its recorded search/document scope. Changing the recorded search scope or product does not carry an earlier
inventory selection into the new scope: each decision binds the scope ID and coverage IDs. Persist decision and
the resulting COMPONENTS_READY revision atomically through the existing revision
compare-and-swap; stale or cancelled work leaves both unchanged.

Selected inventory hints remain tier E (explicit analyst selection from metadata)
and carry separate inventory row references, source authenticity and scope-assertion
reasons. They are not upgraded to official structured tier A or validated package
tier B. Multiple selected rows for one basename preserve all references; the
component presentation may group the name. Selection is bounded to 5,000 claims
per investigation; stale selections stay recorded but cannot feed pair lookup.

Eligible selected basenames feed the existing component and saved-Winbindex pair
workflow. CSV metadata never becomes BuildCandidate, binary SHA-256, verified PE
identity, chronology, or evidence that a file contains a CVE fix. Inventory ARM64
and x86 records stay visible but are ineligible for the current AMD64 analyzer.

Add an inventory dialog/module opened from the existing KB panel, usable for
import/inspection without a project. Provide product/KB context, file chooser,
counts, filters, explicit row selection, plain-text details, named keyboard-accessible
controls/tooltips, progress and cancel, and stale-result/revision guards. Use the
same service, and a fresh worker-owned store per operation. Do not grow ui.py or
raise seam caps. Preserve existing KB and #300 navigation shortcuts.

## 7. Acceptance and exclusions

Meaningful checks cover multiline physical spans, BOM/dialect/header variants,
unknown sections, conflicting products/architectures/versions, numeric precision,
malformed quoting, byte/field/row/time limits, bounded property fuzz, no-network
parser/import assertions, URL/redirect/private-address refusals, cancellation,
raw corruption, idempotency, transaction rollback, CLI exit envelopes, saved-source
selection and Qt worker/stale/keyboard behavior. Generate schemas for new records.

Synthetic fixtures prove parser mechanics only. A separate opt-in live capture
records source/date/SHA-256/dialect/outcome; third-party captured bytes stay outside
Git unless redistribution is justified. No overall L1/L2/L3 accuracy or release
completion follows from PW-01. PW-02 local-package fallback is a separate spec and
implementation slice after these gates; PW-03 through PW-12 remain outside scope.
