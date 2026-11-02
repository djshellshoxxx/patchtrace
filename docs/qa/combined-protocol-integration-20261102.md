# Full protocol branch integration — 2026-11-02

The combined candidate merges complete local branch
`bdf214e874f19a8a15382703e5c480e792b3568b`, whose parent is original PR #154
`f27d23a80ee49573ccca54cdf036427f57eebb2a`. The local branch's tree
`265dfaef41f946daf0397ec4bd30039a36e216ef` matches published PR #161
`9b9452b4677ee3809a6e0f43d49567a8d15602e6`; that published commit/tree/parent
mapping was verified through the GitHub connector. Local and published commit
IDs remain distinct.

This is a full branch merge. The latest complete Markdown-cell, code/comment,
digest-identity and before-input-access guards remain intact. The gate source
matches the protocol branch exactly, including its bounded prefix-only fence
expression. Historical main-port and fence-review receipts are retained.
Training retains the combined candidate's managed replay/transfer reader and
updated version bound; its source required no further change in this merge.
No owner approval, preregistration freeze, final-look consumption, threshold,
or scanner suppression is introduced.

The two text tracker conflicts were resolved by a three-way union. Every
nonblank line, including multiplicity, from both complete histories is retained.
This protocol branch's tracker text was intact. Twenty-four locally missing
protocol blobs were restored from the source checkout only after exact Git-blob
hash matches; two missing merge-base tracker blobs were fetched at exact base
`6579ed83211b7ff2039e3152728ac1cddc3e93d6` and individually hash-verified.

## Validation

`tests/test_train_prereg_selection.py`, `tests/test_prereg_tools.py`, and
`tests/test_prereg_constants.py` passed **138 tests** with **3 legacy-output
compatibility warnings** in 1.21 seconds using
`QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests`. These include rejection before
corpus access and constructed small report/rehearsal checks. No real corpus or
locked evaluation was consumed. Whole-tree Ruff and whitespace checks passed.

Console, JUnit and Ruff receipts are retained in
`combined-protocol-integration-20261102.tar.gz`. This is local integrated
validation; fresh hosted quality checks, the final immutable complete suite,
and native acceptance remain separate.
