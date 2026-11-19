# Combined recovery qualification — 2026-11-19

**1,199 passed, one native Windows skip and one explicit deselection in 213.79 s.**
The bounded run exited zero without reaching its 360-second outer timeout.
Ordinary Ruff over src/tests/tools and both source-range/working-tree whitespace
checks passed. No source, test assertion or test threshold was changed during
this run.

## Exact source and independent review

Runtime: **9335e7dcadc6d0337243f894e8f234ccc74bc62e**.
Runtime tree: **05509de7d8038a9079fe80b08fa97da8cb61b7fd**.
Start/finish QA-only head: **2ff86a96752bde9718460206c5e4b679bdad9cd4**.
The later immutable-action pin repair changes only the previously unselected
tests/test_tier_r_shard.py workflow assertion; its separate 21-control result
and independent review are recorded in the CI packet. Runtime and workflows
remain identical to this tested source. Other later changes are documentation
and evidence. The publication must verify those exact boundaries before using
this result.

Both independent reviewers verified all 30 changed runtime files against the
reviewed inventory, GUI, helper, Search and Strings component pins. The security
review also checked 106 inventory/schema/control blobs and the protected core
repair paths. The two intentional core overlaps are Search CLI/Qt; saved-query
handling is retained. See [the full source/strict-scan review](../assembly-source-20261119/README.md).

The independent GUI reviewer also ran ten actual integration seam controls:
header-help/fallback, host announcements, distinct inventory help, inventory
worker ownership/prior rows, owner-thread Search capture, actual saved-search
save/run/reopen, delayed-build generation and cancellation preservation. All ten
passed in 8.85 s. Earlier root GUI controls passed 15 in 4.28 s. These selections
overlap and are not added to the combined 1,199.

## Combined selection

The [exact command](command.txt) and [execution receipt](result.json) preserve the
94 explicit file/node selectors, environment and source checks. Collection was
narrowed from 1,568 to 1,200 selected tests before execution by selecting relevant
help/spec cases and already-reviewed current-evidence/failed-stage boundaries.
Both collection logs and the initial/final selection lists are retained.

Coverage includes inventory parsing, store/service/CLI/Qt, JSON compatibility,
current-index and unreadable-source admission; shared tool admission; actual
Strings cache/metadata/dock admission; Search CLI/Qt/saved/current sources;
publication ownership; core profile/raw/advisory/manifest/environment/current
evidence overlaps; CI toolchain receipts; and relevant help, tooltip and schema
checks. The inventory schema suite includes the generator's --check gate.

The dedicated Python 3.12.14 interpreter was verified in both normal and -I modes
to import this worktree. The runtime, tests and configuration matched the frozen
source before and after execution.

## Explicit non-passes

- The sole skip is the native Windows existing-object sharing acceptance in
  tests/test_kbc_object_publication.py. Linux execution does not qualify it.
- The sole deselection is
  tests/test_kbc_inventory_csv.py::test_default_entry_and_logical_record_caps_are_enforced,
  the unchanged 50,001-row elapsed-time control. Its earlier broad-run failure
  and unchanged isolated 9.28-second pass remain in the inventory packet. No
  threshold or assertion was relaxed, and it is not counted as passing here.
- Earlier full-suite exit-137 attempts and the Strings outer-bound exit-124
  attempt remain incomplete. This is an affected selection, not a full-suite pass.
- Actual Windows/native tools, packaging, installer lifecycle, manual acceptance
  and L1/L2/L3 accuracy require separate current-source evidence.
- The unsuppressed runtime security scan remains red: 82 findings here versus
  68 on the core baseline. Ordinary Ruff success is a different check.

## Evidence integrity and historical correction

Fourteen prior recovery/failure packets, containing 279 entries, were checked
against their manifests with zero byte/hash mismatches. The residual packet
contains 14 payload members plus its original embedded source-hash manifest;
that manifest was verified separately against its original bytes and all nested
hashes. The first verifier's schema assumptions and their correction are recorded
in the verification receipt; no evidence archive was changed.

The original Search stale-row CLI probe failed to commit its SQLite mutation
before closing. Its in-owner snapshot observation is valid, but its reopened-CLI
claim was withdrawn. The corrected probe commits, reopens and asserts the bad
row before checking the caller. Four CLI regressions then failed on old wiring;
the corrected caller passed 60 focused and 418 adjacent controls. See
[the corrected Search receipt](../search-admission-20261119/README.md).

This archive retains raw logs/XML, the exact runner and selectors, source proofs,
independent GUI controls, initial collection and filename-guess records, and
the evidence verifier. The initial unresolved GUI filename was a review-harness
guess, not a product or test failure. Archive CRC and every member digest were
checked. [Source map](source-map.json), [archive](evidence.zip),
[manifest](manifest.json).

## Subsequent hosted CI assertion correction

The full core Linux job on a56 completed 23,268 passes, one failure, 50 skips
and six expected failures. Its only failure was the older workflow test rejecting
the already approved actions/cache immutable SHA because it required a version
tag. Source 5575af797dfaabdce6a3ee4081d680054d0a2d8f adds only that exact reference
to the existing assertion, preserving tagged cache actions and the exact MSVC
pin. One red control precedes 21 related passes; six independent guard controls also pass. Production code, workflows,
configuration and thresholds are unchanged. The old full run remains failed;
new-head full/native qualification is still required.

[CI source, original full failure and correction](../tier-r-cache-pin-20261119/README.md).

The corrected core was published as 8d130aefe1be6e737cff1d90d2a5b1658d60a3a6
with tree ce0399940c5fa24ea017498f9e4cf80b0ee6d2de, matching the verified local
core tree. [Publication proof](../../audits/consolidation-20261119/core-cache-pin-publication.json).
The [independent documentation review](document-review.json) records its exact
prefix/file hashes before these later publication-status additions.
