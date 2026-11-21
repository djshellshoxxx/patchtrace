# Strict saved all-pages PR JSON admission — continuation handoff

Repository: https://github.com/djshellshoxxx/PatchTrace
Date: 2026-11-20, America/Vancouver

## Scope, source and ownership
- This isolated branch `codex/patchtrace-pr-snapshot-json-strict-20261120` is based on `a63a20b2a272d53a09422222050080823fc3c664`, the immutable-tip inventory successor of draft PR #347. No predecessor, review branch, tag, or main ref was rewritten.
- Contract-first: `1b0c90a82846c9c3d4c284306aa7c3a973d27be4`; follow-up nesting/order contract: `a7aaa3656b69b73b214dce46d52586554d0420e3`.
- Test-first: `7b681f498cc870dc62619d604acf76ab039007c9`; test fixture correction `fe065808d801ac58a602a68a50efaf08e66806b2`; additional malformed/deep tests `ff50555bf45dce3f86938676126f994300ce664c`; output preservation and UTF-8 tests were subsequently refined. Refresh latest head and complete tree before acceptance.
- Implementation: `1c8f02d7d0b68dc92c1137de8b7e11723a816b34`; bounded excessive-nesting classification `9def9acd7ab131bc28adf6c30b518638bf307269`.
- File ownership is `tools/branch_inventory.py::read_json/main`, `tests/test_branch_inventory_pr_json_strict_20261120.py`, contract, ledger and this handoff. The earlier TSV shape/immutable tip guards are retained unchanged.

## Confirmed distinct defect and behavior
The default Python `json.loads(raw)` accepts repeated keys in nested JSON objects and non-standard `NaN`, `Infinity`, `-Infinity` values. Repeated `head.ref`, `head.repo.full_name` or PR identity keys could silently replace a prior saved claim before branch-to-PR reconciliation. Both the current main and the PR347 predecessor used the permissive `read_json` decoder. This is distinct from TSV column integrity and Git tip-OID admission.

The strict parser now uses an `object_pairs_hook` that rejects duplicate keys at every level and `parse_constant` to reject non-finite values. Malformed JSON, invalid UTF-8, and deeply nested arrays are converted to a fixed input error without echoing metadata. The previous 32 MiB bound and ordinary valid Unicode JSON remain intact. The CLI parses PR metadata before invoking `branches()`, preserving existing output when metadata is invalid and avoiding partial Git replay against invalid PR claims. No branch mutator, matching/correlation logic, release gate or source provenance claim changed.

## Tests and evidence
- Added eleven authored repository regression cases: six ambiguous JSON inputs, one valid Unicode nested PR payload, one CLI previous-output/no-replay test, two malformed/deep input tests, and one invalid UTF-8 case.
- A local Python stdlib copy of the changed reader reproduced all six default decoder admissions and passed **nine mirrored controls** including Unicode, invalid syntax and deep nesting. It did **not** import the repository module. [Machine-readable receipt](../engineering/evidence/inventory-pr-json-strict-controls-20261120.json).
- A second-pass author source check verified complete read_json and CLI ordering and corrected an initially escaped TSV test fixture. It is **not** independent reviewer acceptance.
- No complete checkout is mounted; `git ls-remote` fails `Could not resolve host: github.com`. `ruff` is absent. Actual `python -m pytest -q tests/test_branch_inventory_pr_json_strict_20261120.py tests/test_branch_inventory.py`, whole-tree `python -m ruff check src tests tools`, complete offscreen suite, native Qt/Windows/package/CI and an independent reviewer remain unverified.
- PR347 original QA workflow `44843482603` showed Linux QA and four Linux Qt successes with Windows QA and Qt still active at the last source inspection; five native checks were successful in `44843482467`. These are PR347 source-only, not this branch.
- PR345 Windows NSIS Chocolatey HTTP 503 is an original failed workflow, not repaired by this parser. All historical SIGKILL/Qt/native failures remain separate.

## Next executable handoff
1. Fetch exact parent/head refs and check whether PR347 hosted QA is terminal; do not relaunch an active full suite.
2. On a clean source-bound checkout run eleven new cases and existing inventory tests, Ruff, pip check, then an instrumented complete offscreen suite only on an adequately supported runner. Preserve every failure and exact source identity.
3. Obtain a truly separate reviewer for nested key admission, nonfinite values, recursion limits, no payload leaks, CLI read-before-Git, valid PR compatibility and preservation of the previous inventory bytes. Check that the old TSV and OID guards remain unchanged.
4. When parent CI has terminal results and the exact new source is independently reviewed, create a stacked draft PR for hosted qualification. Do not merge into main until every applicable check and manual acceptance gate is green.
5. Continue remaining unowned tasks: selected registered table-header help IDs, full raw Winbindex/index membership, Windows native trust/catalog/manual accessibility, Linux forced-overwrite limitations, native Qt disposition, 181 unknown/16 patch-equivalent historical semantic heads, L1/L2/L3 separately verified labels.

No target binary execution, force-push, rebase, branch deletion, release, deployment or outbound message.
