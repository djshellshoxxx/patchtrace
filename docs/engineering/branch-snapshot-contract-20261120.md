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
