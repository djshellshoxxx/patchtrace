# Slice card SEC-D - PE table bounds and caps (PE-2/PE-3 in the Tier W copy, PE-6, PE-7, PE-8)

Sources: `jq '.actionable_now[] | select(.id=="I1-T05" or .id=="I1-T08" or .id=="I1-T12")' docs/status/inventory/I1.json` and
`jq '.features[] | select(.id=="I1-F05") | .defects' docs/status/inventory/I1.json`. Audit: docs/audits/20261015-pe-codetext-representations.md
(items PE-2, PE-3, PE-6, PE-7, PE-8) and docs/qa/pe-parser-security-20261105.md.

One commit per item, red test first each time.

## 1. PE-2 / PE-3 in tools/calibration/tier_w/pe_tables.py
The fix pass repaired these in the product PE readers but skipped this copy. `PeView.read_rva` still does one unchunked
read, so a directory above the single-read limit raises ArtifactBytesError that escapes the module's PeTableError contract
(PE-2), and one warning is appended per unknown relocation entry (PE-3: unbounded warning list on a hostile file).
Look at how the product code fixed the same two items (git log -S / grep the fixed readers under src/patchtrace/pe_overview
and src/patchtrace/artifact_bytes.py) and apply the same approach here: read in MAX_READ_BYTES pieces, convert a failed
read into PeTableError, warn once per unknown relocation type.
Acceptance (tests/test_tier_w_pe.py): a directory larger than one read is read completely; a failed read surfaces as
PeTableError; unknown relocation types produce one warning per type, not per entry; Tier W outputs for the existing
ordinary fixtures stay byte-identical.

## 2. PE-6 - import-table caps must not flag a table that ends exactly at the cap
File: src/patchtrace/pe_overview/imports_exports.py (about lines 57-60): exactly 512 descriptors followed by the terminator
is reported `import_dlls_over_cap`, which makes api_delta and import_slots unavailable for a complete table. Same boundary
for the per-DLL import cap. Fix the off-by-one: only a table that actually has more entries than the cap is over cap (one
extra bounded read to see the terminator is fine; cancellation and budgets unchanged).
Acceptance (tests/test_pe_overview.py or a new tests/test_pe_overview_import_caps.py): 511 and 512 entries are complete
(no over-cap warning), 513 is over cap; the same three cases for the per-DLL cap; existing PE overview goldens unchanged.

## 3. PE-7 / PE-8 - export-name lookup and truncation wording
Files: src/patchtrace/pe_overview/exports_table.py (about line 94: a quadratic list scan over names; the audit measured
1.8 s at the 20,000-name cap) and src/patchtrace/pe_overview/_common.py (about line 63: the warning says "longer than
{cap} bytes" when the string was cut by the section boundary, which is a different fact).
Replace the scan with a dict/set lookup that preserves the existing output ORDER and duplicates semantics exactly; make
the cstring warning say which limit applied (cap versus section/file boundary).
Acceptance: 20,000 names on one ordinal complete under a generous bound (use a relative bound or >= style, never a tight
absolute time) with identical output to the base implementation on a randomized-with-seed comparison of 200 small tables
(keep the old function in the TEST as the oracle); a section-bounded cstring yields the boundary wording; check whether
any golden or spec quotes the old warning text (`grep -rn "longer than" tests docs/specs | head`) and update only what
quotes it, saying so.

## Owned files
tools/calibration/tier_w/pe_tables.py, src/patchtrace/pe_overview/imports_exports.py,
src/patchtrace/pe_overview/exports_table.py, src/patchtrace/pe_overview/_common.py, tests/test_tier_w_pe.py,
tests/test_pe_overview.py, new test files for these items, docs/specs/pe-overview.md (only the sentences describing the
caps/warnings you change).
NOT yours: src/patchtrace/unified/ir/pe_tables.py (the same PE-2 defect exists there; it belongs to another session's lane -
list it under "Integrator asks"), src/patchtrace/pe_overview/resources.py (slice SEC-B owns it).
