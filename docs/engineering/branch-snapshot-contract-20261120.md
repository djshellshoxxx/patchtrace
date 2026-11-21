# Branch inventory snapshot replay contract — 2026-11-20

This is **read-only, offline provenance tooling**. A retained `--refs-tsv` snapshot is an input record, not permission to change refs, delete branches, publish, or infer semantic uniqueness.

The replay reader must:
- Accept raw CSV/TSV rows containing tabs, embedded newlines and escaped quotation marks in the `note` field without silently truncating long provenance evidence.
- Limit total snapshot bytes to the existing `MAX_METADATA_BYTES` (32 MiB by default) **before** allocating decoded rows or invoking Git.
- Permit a field larger than Python's process-default CSV maximum while the bounded input is being read, and restore the prior process-global `csv.field_size_limit()` value on success and on every decoding/parsing failure.
- Preserve strict UTF-8 and identify malformed TSV as input failures; reject duplicate branch names and rely on the original existing Git commit validation.
- Keep previous published inventory evidence on input failure. Do not weaken existing `delete_safe=no`, source/branch identity, shallow-history refusal or all-pages PR metadata validation.

The implementation is limited to `tools/branch_inventory.py::branches` and regression tests in `tests/test_branch_inventory.py`. A successful replay proves parsing fidelity for the supplied snapshot, not branch-history semantic equivalence. The test-local Git repositories contain synthetic commits and do not execute analyzed target binaries.

Source of reviewed candidate: PR #346 / session 95fe, change `076c1ffaea35e922b206da5818023fe96459de23`. Preserve that published history and its original failures. Exact combined-source qualification, whole-tree Ruff and independent fresh review remain separate.

## Follow-up: TSV column integrity before Git lookup (2026-11-20)

The replay reader must reject malformed snapshot structure **before calling Git**.
Python's `csv.DictReader` silently overwrites earlier values under a repeated
header name, stores extra row fields under a `None` key, and represents a missing
row field as `None`. Without explicit validation, a repeated `branch` header
can reassign a retained commit tip to a different branch name even when the
original exact-tip replay succeeded. This is a provenance association error, not
only a display problem.

Require unique non-empty field names including `branch` and `tip_sha`, exactly
one value per declared field on every row, and non-blank branch/tip values.
Reject invalid column shapes as a fixed `ValueError` rather than running Git
with an altered or incomplete mapping. Permit reordered columns and additional
named columns for compatibility with retained snapshots. Preserve existing raw
UTF-8, 32 MiB limit, large quoted `note` support, CSV field-limit restoration,
atomic prior-output preservation and `delete_safe=no`. This does **not** prove
that a complete/all-head snapshot was supplied; provenance completeness and
semantic branch review remain separate gates.

Quoted TSV fields must also have complete, valid CSV quoting. Refuse an
unterminated quoted field or unexpected text after a closing quotation mark
before any Git lookup, including when the damaged field is only a provenance
note on a later row. Preserve embedded tabs/newlines and doubled quotation
marks in valid fields, restore the process CSV limit after rejection, and keep
previously published output unchanged. A row with the expected number of
columns is not sufficient evidence that its quoted content was complete.


## Follow-up: bind replay tips to exact Git commit object IDs (2026-11-20)

The `tip_sha` value in a saved branch snapshot is an exact commit-object identity,
**not** a Git revision expression or a symbolic reference to resolve at replay
time. `git rev-parse --verify <value>^{commit}` currently accepts values such
as `HEAD`, abbreviated hashes and `HEAD~0`; these can resolve to a different
tip after the original inventory was recorded, while still appearing valid in
a replay. An annotated-tag object's SHA can also peel to a different commit.

Before issuing *any* Git lookup for snapshot rows, require every `tip_sha`
to be a canonical lowercase full 40-character SHA-1 or 64-character SHA-256
hexadecimal identifier. Keep this check alongside column/header and branch
shape validation so a late malformed record cannot trigger partial Git access.
After Git resolves the requested object, require the canonical returned commit
ID to equal the supplied tip exactly, refusing tag-object peeling and any
other object-to-commit substitution. Preserve mixed column ordering, unrelated
named metadata, bounded large quoted fields, CSV limit restoration, previous
published outputs, branch retention and `delete_safe=no` unchanged.

A full-length hash alone is a syntactic commitment, not proof of branch
provenance or completeness; it must still exist and resolve to the same commit
in the local object database. Tests must use synthetic Git objects, not
analyzed target binaries. Do not infer semantic uniqueness or release
eligibility from this admission control.


## Follow-up: strict saved all-pages PR JSON admission (2026-11-20)

The saved `--pulls-json` document is immutable review evidence, not an
untrusted object whose identity fields may be silently overwritten during
parsing. Before using it for branch-to-PR association, reject repeated JSON
object keys at **every nesting level** (including PR number, head/ref/repo and
head SHA), and reject non-finite JSON numeric constants (`NaN`, `Infinity`,
`-Infinity`). Python's default `json.loads` accepts both categories, so
strict admission is required before any inventory Git analysis or publication.
Preserve the existing 32 MiB byte limit, ordinary Unicode JSON, valid all-pages
array shape, existing output on failure and unmodified valid PR records.
Excessively nested JSON and malformed Unicode/JSON must also return a fixed
input error rather than an uncaught parser recursion traceback. Read and
validate the saved PR JSON before remote-branch Git lookups or any inventory
publication; a corrupt source cannot cause partial Git replay work.
Error messages must be fixed and must not echo private PR payload contents.
This is a parser integrity repair, not authentication of the saved PR dataset,
all-pages completeness proof, or permission to merge/delete any branch.
