# Independent explicit creation retry review — 2026-11-02

No remaining blocking findings. Requires both `7c20e546ef2b759be963181f21177ec263aa71d6` and `3b1b875161ddfc438dbac45327225e7a8161668b`, from base `5b247c061c6faba5df2e42876d811807fae9d75f`. Final tree `7f13fb0bacdb1a107323419fdfe7a512dde5ecec`. Adjacent JSON binds source and evidence hashes.

Initial 236 tests passed, but an independent actual retry exposed `abspath` hiding a linked component before `..`. The follow-up records lexical identities before normalization and rechecks them under the held lock. Actual symlink and modeled reparse refusals now preserve all destination bytes; ordinary directory/.. remains usable.

Private input staging, unchanged lock bytes, strict read-only incomplete-layout validation, exclusive publication and held-lock ownership cleanup were reviewed. Normal Create remains guarded. Actual Qt workers retain completed projects and reject cancelled or stale adoption.

Final frozen source: **82 passed in 4.80 s**, including six independent preservation/cancellation/path controls. Initial and final selections overlap. Changed-file Ruff and diff checks passed. A prior final-selection tool summary was unavailable across context truncation and is unqualified; the recorded rerun has saved log/JUnit evidence.

No native Windows, power-loss, hostile filesystem writer, full-suite or performance acceptance claim. No source edits or remote actions. Broader issue116 remains separate.
