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
logical records, <=50,000 retained v1 entries, <=1,000 retained diagnostics, <=1,000
sections, parser wall time <=10 seconds with cooperative checks between bounded
records. Hard byte/text/field/record/column/section limits are fatal. Entry and
logical-record limits return explicitly partial/truncated results; diagnostic
omissions are counted. Limits must be positive and cannot exceed hard ceilings.
Raw bytes are bounded before decoding; no global csv.field_size_limit mutation.

The 50,000-entry v1 default and hard ceiling preserve the published capacity
correction. Earlier v1 records captured a 5,000-entry budget; replay always uses
the exact serialized limits, including caller-lowered budgets, without rewriting
their inventory/import/entry identities. A default change is not permission to
reinterpret an existing record. The separate v2 source-page ceiling remains 5,000.
The 16 MiB raw/text and 64 MiB serialized import ceilings remain unchanged; they
are admission limits, not bounds on process memory during parsing or replay.

The 50,000-entry ceiling admits the observed 42,845-record KB5036893 source,
whose x64 section starts at logical record 21,261. The initial 5,000-entry
ceiling truncated that source inside ARM64. This capacity correction does not
raise the byte, logical-record, diagnostic, time, stored-record, UI-page or
selection limits. Previously captured 5,000-entry budgets remain part of their
immutable identities and replay unchanged; reimporting under the current
default creates a distinct contextual import over the same raw source.

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

### 3.1 Explicit retained source pages (2026-11-18)

The v1 parser's captured semantics, serialized records, identities and replay
remain unchanged, including both published 5,000- and 50,000-entry budgets. A
separate offline action can retain a source page from the
complete immutable raw bytes of an existing import. It appends a new import;
it never rewrites a source, changes an investigation revision or selects a row.
The original SourceDoc, asserted source and retrieval receipt remain exact.
V1 PE classification is pinned to its original eight suffixes: exe, dll, sys,
efi, drv, ocx, cpl and scr. Shared acquisition-policy additions cannot change a
saved v1 row's state. V2 `InventoryPageEntry` additionally recognizes tsp; a v1
tsp claim remains descriptive-only under its original inventory/entry IDs.

`InventoryRetention` is a strict frozen record with `architecture` equal to
all/amd64/arm64/x86/unknown (default all) and one-based `page` in 1..100000
(default 1). This architecture is a retention filter, not an assertion. A named
architecture includes rows resolved to that architecture plus unknown/conflicted
architecture rows for review; all includes every accepted row. Existing context
assertions, unsafe-filename rejection and selection eligibility are unchanged.

`InventoryPageLimits` has the same serialized fields as `InventoryLimits`, but
its `max_entries` default and hard ceiling are 5,000. `DEFAULT_PAGE_LIMITS` is
independent of the v1 default. V2 parsing and saved-record validation reject a
budget above 5,000 even when the actual retained population is smaller. Existing
v2 bodies and identities remain byte-for-byte valid with their captured budgets;
the Python limits type adds no serialized discriminator or new identity field.

`inventory_csv.parse_inventory_page(raw, context, retention, *,
limits=DEFAULT_PAGE_LIMITS, cancel=None) -> CsvInventoryPage` scans once to EOF or the
captured logical-record ceiling. A page contains up to `limits.max_entries`
matching accepted rows in original logical-record order. Blank/header/banner and
rejected rows do not consume page positions; duplicates and conflicts do. No
hard ceiling or caller-lowered limit is raised. All normal lexical, metadata,
section, cancellation and wall-time checks apply outside the retained page too.
Fatal parsing, resource and cancellation errors publish nothing. An EOF-confirmed
page with no matching rows raises PT-KBC-INPUT and appends nothing.

Compact per-scope conflict summaries cover every accepted scanned row, including
rows before and after the page. Their count is bounded by `max_records`; full
InventoryEntry objects are retained only for the selected page. Grouping uses
the existing normalized basename/architecture/product/release/build scope and
known-value contradiction rules. A conflict elsewhere in that scope marks every
retained member conflicted, so page boundaries cannot hide contrary evidence.
For each retained group with a cross-row metadata conflict, retain one
`InventoryConflictWitness`: conflict_group, field (version_components/size_bytes/
date_text/time_text), first and second CsvRecordRef. The two distinct source
records witness the contradiction; witnesses remain present independently of
diagnostic truncation. Duplicate links name earlier retained entries only;
every matching source claim remains independently reachable on its own page.

`CsvInventoryPage` is a separately versioned parsed record, with
contract='kb-file-inventory/2', parser_version=2, the existing inventory fields,
retention, scan_complete, matching_count, excluded_count, omitted_count and
conflict_witnesses (at most 5000, one per retained conflicting scope). Entries and
the accepted, duplicate and conflict counts each have an explicit 5,000 hard
ceiling, independent of v1's larger population. These counts still describe
retained entries. Rejected counts
cover scanned rejected data. Matching/excluded counts cover scanned accepted
rows inside/outside the architecture filter; omitted_count is matching_count
minus accepted_count. Counts are exact only if scan_complete is true, otherwise
they describe the observed prefix. Truncated means scanning stopped before EOF;
deliberate page/architecture omissions are separately counted. Any omission,
incomplete scan, conflict or existing partial condition gives status partial.

The v2 inventory identity binds raw digest, canonical context, exact limits and
retention policy in a separate identity version. Entry identities still bind
that inventory identity and the original logical record. Source and row
references retain their original raw digest, fields, logical record, physical
line span and section. A new page never rebinds a prior selection or v1 ID.
InventoryImport keeps its outer contract/table and accepts either parsed
version. Verification dispatches to the captured parser/policy; altering a
policy, witness or observed count cannot bypass deterministic raw replay.

`inventory_store.retain_inventory(ws, import_id, retention, *, cancel=None)`
returns `(InventoryImport, added)` after verifying the parent import and its raw
source. It reuses the parent's exact context and source provenance. New page
limits preserve every captured parent budget except `max_entries`, which is
`min(parent.parsed.limits.max_entries, 5000)`. A parent budget of 1 or 2 therefore
remains 1 or 2, while a 50,000-entry v1 parent produces pages of at most 5,000.
Page offsets and the new v2 identity use those effective limits. The parent and
all historical records remain immutable.
Repeated retention of the same policy is idempotent, including requests made
from another page of that source. No fresh acquisition time is invented.
Unknown imports use PT-KBC-INPUT; corrupt stored evidence uses PT-KBC-VERIFY.
SourceError/KbcStoreError cancellation remains PT-KBC-CANCEL.

`kb inventory retain IMPORT_ID --architecture amd64 --page 1` invokes this
offline action. Architecture/page controls in the retained-source UI are
separate from filters and pagination over an already retained page. The shared
service displays the policy, scan status and observed counts. An incomplete v2
source scan cannot feed filename selection or replayed hints because unseen
records may contradict retained claims; the refusal preserves earlier results.
Existing v1 selection/replay behavior is unchanged. Import/fetch request plans
and exact network consent are unchanged.

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

### Immutable object publication amendment (2026-11-18)

All advisory and inventory object writes use the existing WorkspaceStore facade
and one shared owned-publication primitive. Verify the supplied raw SHA-256 before
any write. Hold ordinary destination-parent objects throughout staging, flush,
verification and exclusive publication. Never replace a pre-existing path, whether
it is valid, damaged, a link, a directory or a concurrently published file.
Existing regular files may be reused only after a bounded read through an owned
handle, bounded single-member gzip decompression, and exact raw digest/length
validation. Their original compressed bytes and filesystem identity stay intact.
Inventory imports continue to reject missing objects already referenced by earlier
records; a new import is not a repair operation.
The named `store.py` adapter may import only `OwnedPublicationError`,
`directory_anchor`, `verify_anchor`, `publish_bytes`, and `read_bytes` from the
stdlib-only shared `owned_publication` module. Pure inventory domain modules
retain their existing sibling-import restrictions.

The caller-selected workspace root may be resolved once; child object directories
and leaves must not follow symlinks or Windows reparse points. Linux publication
uses an anonymous source linked from its exact descriptor into an anchored parent.
Windows publication uses rooted opens, no-delete-sharing directory guards and a
read-shared-only source, then a no-replace rename of that exact source handle.
The Windows source and parent identities remain held through the operation.
Unavailable platform capabilities or observed identity changes fail closed with
the existing storage/verification errors, before import-row admission.
Capture the resolved workspace root's filesystem identity before opening SQLite,
recheck it after opening, and require that same identity on the held root during
every object read/write and final parent revalidation. Renaming and replacing the
workspace pathname cannot redirect object work away from the open database owner.
SQLite opens (including a newer-schema read-only reopen), returned object paths,
and orphan-object discovery use that captured resolved root, not the original
caller alias. Retargeting an allowed root symlink cannot split database and object
ownership between two workspaces.

Failure and cancellation preserve all previous and concurrently written evidence.
Cleanup closes/discards only the owned source; it must never unlink a pathname
which could identify a replacement file. A successful object can remain orphaned
if a later transaction fails, as already specified. This is not a cross-filesystem
and SQLite transaction and does not promise to prevent external mutation after
the completed operation; every later read must still verify its recorded bytes.
The persisted schemas and import/source identities are unchanged. Native Windows
tests remain a separate required acceptance lane.

## 6. KB service, selection, CLI and desktop

Keep storage/parser logic outside Qt. KbService delegates to inventory_service.py:
`inventory_store.py` and `inventory_selection.py` are named SQLite adapters;
`inventory_qt.py` is the named Qt adapter and may use the existing GUI/tooltip
helpers. The parser and contract modules remain free of Qt, networking and
database imports. Their sibling reuse is limited to the shared hostile-text
helper and the acquisition contract's PE extensions and filename validator.
The inventory store reuses only `persistence.strict_json` from that sibling.

The facade exposes:
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
product comparison retains an explicit Windows 10/11 generation even when the
source omits a release. Multiple known advisory builds for the same KB and scope
remain a conflict, never an unknown value that an assertion can override. Selection
requires resolving that recorded advisory scope before adding a filename claim.
The selected
scope must be AMD64 and not mapping-conflicted. The CSV entry must be a valid
AMD64 PE basename with known version and no metadata conflict. A missing size
does not invent byte identity or prevent filename-only selection. The KB must
belong to the lead within its recorded search/document scope. Changing the recorded search scope or product does not carry an earlier
inventory selection into the new scope: each decision binds the scope ID and coverage IDs. Persist decision and
the resulting COMPONENTS_READY revision atomically through the existing revision
compare-and-swap; stale or cancelled work leaves both unchanged.
Capture the ordered advisory source metadata before rebuilding the eligibility
index and verify it is unchanged afterward. Before publishing a selection, check
that same snapshot and cancellation inside the short revision transaction; a
source import or metadata change during validation is PT-KBC-STALE, even if the
investigation revision has not changed. Repeated selections that need no new
decision or revision still check both the exact current revision and source
snapshot together in a short guarded transaction before returning success.
Keep source parsing and inventory replay outside these write transactions.
Existing component discovery must verify selected inventory evidence before
publishing a product change or newly entered filenames. A failed raw replay
therefore preserves the previous product, revision and analyst decisions.

Selected inventory hints remain tier E (explicit analyst selection from metadata)
and carry separate inventory row references, source authenticity and scope-assertion
reasons. They are not upgraded to official structured tier A or validated package
tier B. Multiple selected rows for one basename preserve all references; the
component presentation may group the name. Selection is bounded to 5,000 claims
per investigation; stale selections stay recorded but cannot feed pair lookup.
Replay groups claims by import and retains at most one parsed inventory between
groups, rather than accumulating up to 5,000 full bounded source records in memory.

Stored selection decisions must be SQLite TEXT of at most 8,192 encoded bytes.
Apply that type and encoded-byte bound in the SQL projection before returning
the body to Python or decoding JSON. SQLite character length alone is insufficient
because embedded NUL and multibyte text can conceal a larger encoded body. Reject
non-TEXT decision rows for the investigation and invalid text encoding with
`PT-KBC-VERIFY`; an unreadable decision cannot silently erase a prior selection.
Failed replay preserves existing revisions, decisions and raw inventory objects.

Eligible selected basenames feed the existing component and saved-Winbindex pair
workflow. CSV metadata never becomes BuildCandidate, binary SHA-256, verified PE
identity, chronology, or evidence that a file contains a CVE fix. Inventory ARM64
and x86 records stay visible but are ineligible for the current AMD64 analyzer.

Add an inventory dialog/module opened from the existing KB panel, usable for
import/inspection without a project. Provide product/KB context, file chooser,
counts, filters, explicit row selection, plain-text details, named keyboard-accessible
controls/tooltips, progress and cancel, and stale-result/revision guards. Use the
visible selected row as the explicit filename choice; keyboard focus or a current
cell left after deselection is not a selection and must disable the Select action.
For each retained row with a metadata-conflict witness, its bounded plain-text
detail must include that exact matching witness, including both complete source
record references, before potentially long original fields. Build the witness
lookup and row text on the worker. Do not depend on the whole-inventory preview
or repeat unrelated witness arrays: a full diagnostic budget or long source
fields must not hide the selected row's cross-page contradiction.
Use the
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
