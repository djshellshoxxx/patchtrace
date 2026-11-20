# Generation-18 adversarial review: post-selection nonregular source

**Scope:** `WorkspaceFileIndex.rows_for` on source branch stacked after draft
PR #328. The following is an independent successor-turn review of the prior
generation, **not** independent signoff of the new generation.

### Original failure

The prior generation-17 source calls `_record` and then
`open(path, 'rb', opener=no_follow_open)`. When the admitted file was
replaced with a directory immediately after the scan, Linux Python 3.13.5
raised `IsADirectoryError(errno=21)` before `fstat`. The prior broad
`except OSError` mapped this to `PT-KBC-INPUT`, despite SPEC-31-D's
`PT-KBC-SOURCE` requirement for a matching nonregular object.

The observed baseline console: `IsADirectoryError errno=21 EISDIR=21`.
A separate FIFO control showed that the nonblocking descriptor opened
without waiting and `fstat` reported `S_ISREG=False`.

### Correction and tests

New contract commits precede the two new actual-repository regression
tests, which precede the tiny `errno.EISDIR` classification change. On
the isolated standard-library mirror, five controls pass in 0.06 seconds.
All tests use self-created synthetic files; no analyzed target is run.
Do not infer real Windows behavior, backend compatibility or empirical
accuracy from this receipt.

**Host qualification not performed:** the actual repository's
`tests/test_kbc_winbindex_held_admission_20261120.py`, prior
`test_kbc_winbindex_read_budget_20261120.py`,
`test_kbc_winbindex_source_identity_20261120.py` (verify filename),
`tests/test_kbc_pairs_index.py`, whole-tree
`QT_QPA_PLATFORM=offscreen python -m pytest -q`, and
`python -m ruff check src tests tools` require a complete supported
checkout. Project dependencies and full source cannot be fetched in
the local runtime. Hosted exact-head CI remains pending.

**Remaining adversarial cases:** Windows may surface `EACCES` for a
directory open; no Windows source-classification proof is made. A
regular-file swap can still read untrusted foreign bytes; a parent
directory can be replaced. The separate forced Linux source-name
replacement race in Strings export remains confirmed. Source
authenticity, original raw index retention, resolver replay membership
and live provider consent are not established by this patch.

## Source identity

Base PR328 head: `0d55516788a8de8244b5599a83b4413757d6c1be`.
Contract: `4c24b9bda6b91ee6df60ae0a1847a67068876304`.
Tests: `b3e54eb973044a6f1fde3e4b0b62b03a92952086`.
Code: `4d5e7d4ce4f1f9d1e027a4ed5ec5da657abe803a`.
No Git main merge, release, deployment or silent change to the ASM gate.
