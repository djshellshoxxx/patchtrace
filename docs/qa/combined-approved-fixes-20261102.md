# Approved backup/UI integration and source freeze — 2026-11-02

After the complete replay/schema and protocol merges, the coordinator supplied
independently approved backup, UI and fixture-documentation commits. Each was
applied unchanged in a separate local commit:

| Change | Supplied source | Applied local commit |
|---|---|---|
| Stable backup byte observations | `b86159f4823c2e1bb2d21d00cf0b470749a289fe` | `5129a0d272a9a0796fba77f19ee350b1427c1050` |
| Wrapped raw-controls container allocation | `b762828f5cbc644359e7fec0addd8f353e98aa11` | `e2207785ea773e9f3d69236a15ff3be50e38585f` |
| Historical PR #90 fixture handoff reconciliation | `47653db17db06e434612f51f8622d6b1c3be7cf2` | `8cd46a958e6bd28c132b825cc59854e8b261cb07` |

The backup and UI owned source/test/spec files match their supplied commits
byte-for-byte. No merge conflict altered either repair. The documentation-only
PR #90 follow-up retains its historical continuation and separate current-state
observations without claiming broader live or integration acceptance.

Published backup follow-up PR #162 is
`f1a55c4cf21ddb0dea243bd417b74f86caaed142`, tree
`61ddda8e5b94e4eaaeb13e9939625740d1124067`, with published main
`ce8c65bf41541cf6adb52289d2a530ce2817a53a` as parent. These remote identities were
read through the connector; the applied local commit has combined-candidate
ancestry and is deliberately a different commit.

## Integrated checks

The combined backup/UI selection passed **161 tests** in 15.48 seconds:

```text
tests/test_verified_backup_byte_integrity.py
tests/test_verified_backup_stat_api.py
tests/test_verified_backup_publication_admission.py
tests/test_verified_backup_reuse_filter.py
tests/test_prune_backup.py
tests/test_enrichment_storage.py
tests/test_ui_raw_alignment.py
tests/test_raw_alignment_view.py
tests/test_representations.py
```

The command used `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests`. It includes
the original Windows-failing byte-integrity and wrapped-summary regressions,
the added equal-change-time and larger-font controls, completed-publication
admission, and live-row preservation checks. The test source stayed unchanged
while the run completed; the PR #90 cherry-pick changes only its handoff document.

Whole-tree Ruff and whitespace checks passed. Every corpus/calibration and
training-transfer JSON schema still matches the merged model renderer. The
console, JUnit and final Ruff receipts are retained in
`combined-approved-fixes-20261102.tar.gz`.

The resulting source-plus-PR90-documentation checkpoint is
`8cd46a958e6bd28c132b825cc59854e8b261cb07`, tree
`aa1de4006163f9021577a398960014c0ed9dc8b0`. This receipt and its QA/tracker entry
are an evidence-only follow-up. The coordinator will record the resulting final
commit/tree for the immutable complete run.

## Remaining gates and limits

The earlier Windows failures now have reviewed repairs and passing integrated
Linux controls; their previous hosted outcomes remain failures until a fresh
Windows run qualifies the new source. No native Windows acceptance is inferred.
The backup repair adds one complete bounded read/hash pass per successful
fingerprint and is not an atomic snapshot against arbitrary concurrent writers.
The UI allocation keeps the existing bounded layout loop and immediate geometry
assertions; no timing allowance was weakened.

No complete suite was run by this integration agent. Independent review of the
full merges, one immutable complete suite, exact-head hosted/quality/package
gates and remaining native acceptance are coordinator-owned. No real corpus,
locked evaluation or compared target binary was executed during these checks.
