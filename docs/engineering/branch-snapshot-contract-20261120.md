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
