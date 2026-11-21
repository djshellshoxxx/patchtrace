# Strings CSV document-metadata repair — 2026-11-19

Base: `e36b83be1ef86d28a58318cc601a35f20b22bf06`, integration branch
`codex/maximum-completion-20261119-4c8d`. Implementation worktree:
`codex/csv-metadata-20261119-4c8d`.

## Defect and uniqueness

The earlier independent review in `strings-csv-provenance-follow-up.md`
identified an observable export defect: CSV serialized only string rows,
discarding the document's extraction basis, truncation, redaction policy,
counts, anchors and lineage. Two empty exports with materially different
provenance consequently had the same 103-byte header and digest.

The inherited three public-export counterexamples reproduced unchanged:
**3 failed in 0.36 seconds**. The new contract tests produced **17 failures
and one pass in 0.75 seconds** on that same runtime. These include repeated
observations of the one formatter defect and validation of the proposed
encoding; they do not represent 17 unrelated bugs.

The retained-ref audit examined **637 origin/PR ref entries**, including
the remote HEAD alias. **508** contained the canonical export module;
five distinct source blobs all had the same `render` AST, `_csv_row` AST,
and eleven-column header. The integration base's exporter blob is
`6191d24744362c36401f6f68f33b75ef7b749e4a`, with the same metadata-losing
formatter AST. Other blob differences concern publication, not metadata
encoding. No existing formatter repair was available to extract from those
versions. This is bounded evidence about the canonical export path, not a
claim that every historical feature has been semantically reviewed.

## Change and compatibility

The WB3 contract was updated before the production change. CSV now starts
with a two-field `strings-export-csv/2` record: the fixed format marker and
canonical JSON for every document member except `changes`. The existing
eleven-column table follows, with the same header and string cells.

An empty export contains metadata and the table header, with no fabricated
finding. `ExportResult.rows` still counts selected strings only. Metadata
preserves the selected scope, default/explicit redaction policy, basis,
harmonized settings, notes, delta counts, truncation, anchor summary and
selected lineage. Delta counts retain their existing scope and need not
equal the selected row count.

**Header-first CSV readers require a deliberate migration:** validate and
consume the preamble before handing the remaining stream to `DictReader`.
The WB3 specification includes a minimal reader example and explicitly
distinguishes this encoding from historical unversioned CSV. Legacy files
cannot retrospectively supply metadata they never stored. A v2 preamble is
not silently represented as a string record under the old column names.

The metadata JSON starts with `{` and escapes control characters; a
formula-like string nested inside it cannot become a spreadsheet formula.
Finding cells retain the existing six-prefix neutralization. Revealed row
values are not duplicated into metadata. JSON output remains byte-for-byte
the existing `strings-export/1` encoding. The three-line production change
does not alter publication, introduce a sidecar, change selection, or weaken
the existing file digest/ownership checks.

## Verification

The focused export selection, including the original public-export
counterexamples, passes **32 tests in 1.15 seconds**. The complete affected
Strings, Strings Qt, and shared publication selection passes **575 tests,
with one skipped in 23.12 seconds**. Raw logs and JUnit files are retained
under `evidence/csv-metadata/`; `receipt.json` records commands, environment,
source blobs, the skipped check, ref-audit scope and SHA-256 of each artifact.

Controls cover empty and populated files, changed/all scope, exact metadata
round trips, redaction and explicit reveal, commas/quotes/CR/LF/Unicode,
all six formula prefixes, unchanged JSON, deterministic bytes, unchanged
finding row count and the actual CLI receipt/digest path. Existing formula
and CLI tests were adapted only to consume and validate the new preamble;
their prior assertions remain in place.

Whole-tree Ruff and whitespace checks pass. The Strings schema generator
was run and its outputs remain unchanged; its `--check` mode also passes.
The stored models and JSON schema contracts were not changed.

## Independent reader-example correction

Fresh review of implementation `9308cef64592a5a7e7d7fb051cffa68464277c31`
produced six passing controls and one failure in the specification's reader
example. A valid 1,200-row export with distinct 128-character lineage groups
was 443,201 bytes; its metadata field was 157,612 characters, exceeding
Python CSV's default 131,072-character limit. Runtime serialization retained
all metadata. The defect was in the documented migration example.

The example now reads at most an explicitly chosen 8 MiB plus one overflow
byte, refuses overflow before decoding, and parses that bounded snapshot.
It sets a matching field limit and restores the previous process-global
limit in `finally`. The specification distinguishes this reader policy from
exporter limits, describes larger valid exports and spreadsheet display
limits, and calls for an isolated process or serialized global-limit changes.
No runtime, test, publication, or generated-schema code changed.

The implementer replayed the reviewer's unchanged seven controls against
the corrected example: **7 passed in 0.57 seconds**. Output is retained in
`evidence/csv-metadata/reader-example-peer-replay.log`. The reviewer's own
independent replay and report remain separate evidence.

## Remaining qualification

The coordinator owns independent review and the combined full suite.
Offscreen/synthetic controls do not qualify native Windows or an external
FLOSS producer. The existing Linux forced-replacement source-name race,
native publication acceptance and other release gates remain open. This
format repair does not resolve them.
