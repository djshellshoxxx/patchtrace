# Independent release qualification review: corrected source

**Disposition:** no remaining blocking finding in this bounded review of
`05176698d0265e4e1e577e06fa38bb52d7bbcf43`. The three confirmed defects in the
original `0bb63363ed675266ec4572a85ee0c0861aa714b7` are repaired. This accepts the
reviewed qualification mechanism; it does not qualify a hosted release or waive
any missing native or security gate.

## Source and isolation

Original detached checkout: `/workspace/scratch/c7a9e8d98848/release-review`.
Corrected detached checkout: `/workspace/scratch/c7a9e8d98848/release-review-fixed`.
Both remain clean. The author worktree was not edited. The original independent
controls and their red log/XML remain byte-for-byte retained alongside the final
receipts. `source-context-original.json` and `source-context-fixed.json` record
the exact source and test hashes, interpreter, import path and Git status.

Runtime: `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, Python 3.12,
`QT_QPA_PLATFORM=offscreen`. Every run pins absolute `PYTHONPATH` to its detached
source checkout. External tests additionally use that checkout's `tests` and
root, preventing the shared interpreter's older editable install from supplying
the code under review.

## Findings and repair verification

| Confirmed defect on original source | Corrected behavior | Independent result |
| --- | --- | --- |
| Changed tracked bytes hidden by replacement objects or index flags qualified | Canonical `ls-tree` blob identities are checked against actual streamed file/link bytes and modes, without the real index, replacements or filters. Source entry and parent identities are rechecked. | All three original real-Git reproductions now refuse. |
| JSON exponent overflow became an infinite float, including in otherwise unused native metadata | JSON `parse_float` rejects values that do not remain finite. Literal nonfinite tokens and duplicate object keys remain rejected. | Both decoder controls and the full authored native aggregate control now refuse. |
| Two platform records could qualify one artifact ID twice | Native artifact list entries require distinct positive integer IDs before platform selection. | The original shared-ID aggregate now refuses. |

The original external suite reports **11 passed in 0.29 s** on the corrected
source; its original **7 failures and 4 positive controls** remain retained.
The repair was read directly, including its spec clarification and added tests.

Eight additional independent controls exercise the newly introduced byte
verification, beyond the original reproducers:

- Matching source with either index flag still qualifies, without modifying the
  index.
- Valid nested paths, Unicode and newline filenames, a tracked symlink, and
  executable mode qualify without altering the index.
- Replacing a tracked file or its parent with a symlink is refused even when the
  visible contents are identical; changing executable mode is also refused.
- Mutation after hashing, including restoring the old mtime, is detected before
  acceptance.
- Exceeding the total source-byte budget cannot qualify a verified prefix.

These **8 controls pass**, retained in `source-verification-fixed.log` and XML.
They use authored temporary repositories/files only and execute no target.

## Affected gate and actual CLI

The exact corrected-source affected gate reports **458 passed, 3 expected
failures in 1.99 s**. The files are `test_release_qualification.py`,
`test_backend_bundle_workflow.py`, `test_release_gate.py`, `test_workflows.py`,
`test_workflow_contract_dependencies.py`, `test_codex_pkg_workflows.py`,
`test_milestone_notes.py`, and `test_verify_release.py`. The three expected failures
remain the existing CODEX-1 action-pinning, CODEX-5 pip-hash and CODEX-6 corpus-cache
requirements. They are not passing gates. Whole-tree Ruff passes.

The actual corrected CLI was invoked with its real committed SHA. It returned
exit 1 and a persisted `qualified: false` receipt because its actual commit message
contains `[no release]`. This check occurs before the GitHub API is constructed.
`actual-cli-hold-fixed.json` and its stdout log preserve the result.

## Other checked semantics

The review covered exact source/run/attempt/job and critical-step ownership,
canonical event/repository selection, changed run attempts, missing/skipped scans,
native artifact metadata and bounded ZIP parsing, strict JSON, annotated-tag
peeling, existing release/asset refusal, and command-output credential isolation.
Valid nested annotated tags and complete authored evidence remain usable; the
dummy-credential control retains no marker in public error output. The required
workflow checkouts have no custom source-ref override in this source.

The author's original QA archive was fully verified against its manifest:
34 unique members, 70,444 bytes, SHA-256
`7f5d2eeddfe5b6db3aee84615064b816c78cf79287f8a41166ffb5361061101f`.
Actual historical job receipts contain `run_attempt`; their historical hosted
observations are not attributed to the corrected source.

## Limits and remaining publication holds

No remote mutation, workflow dispatch, release, target download/execution or
native experiment occurred. REST/ZIP qualification evidence in tests is authored;
local Git and file-identity controls are real local operations. This is not
proof of native compatibility, live CVE attribution, package acceptance, or a
passing dependency/security scan.

The policy intentionally still refuses the missing dependency/security workflow
and the blocked Windows BinDiff network-denial result. The corrected source is
held by its own `[no release]` metadata. The three existing CODEX expected failures
remain explicit. Publication therefore remains blocked until the applicable real
gates pass for the eventual exact publishing source.

Canonical source verification is bounded to 50,000 entries, 2 GiB of tracked
content and the existing command-output bound. It verifies a point-in-time local
snapshot with replacement checks; neither it nor the remote guard claims a
transactional filesystem or remote-ref lock through later publication. Publishers
run on Linux with canonical checkout bytes; filtered bytes that differ from the
commit are intentionally refused. No product platform behavior was changed by
this review.

Root owns final integration and publication decisions. The companion manifest
and archive retain original red evidence, unchanged reproducers, corrected-source
receipts, supplemental controls, source hashes and patch snapshots.
