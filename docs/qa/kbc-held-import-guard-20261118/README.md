# Exact shared-reader import guard and retained Linux full-QA failure

## Reviewed correction

Guard source **52a562b6f4c8063b7cb47b31c3942f55db7fa5f5**, after specification
and regression commit **5cdf1732a1d85679bb9a72ab79a4337fd8497405**, passes
**247 tests, zero failures/errors/skips**, in 0.69 seconds. The independent
reviewer separately replays the same 247-case scope with 39 canonical imports,
zero drift and no child/network audit events. These are two runs of the same
cases, not 494 distinct checks. Full normal Ruff passes. The isolated strict S
scan still exits 1 with **80 unchanged path/code/selected-statement findings**.
No strict finding is suppressed or waived.

The change corrects a stale static architecture guard for the already reviewed
KB held-input implementation. The dedicated held-input specification and module
index already authorize its neutral standard-library-only reader types. The
guard now permits seven explicit file/symbol combinations: `HeldInput` and
`PairInputReaders` in KB service/store/wiring, plus `InputReadError` only in
store. It never adds the whole module to the broad sibling allowlist.

The new controls reject aliases, wildcard/absolute/whole-module/submodule imports,
other exports, other domain files and mixed allowed/forbidden declarations.
The existing Qt, network, SQLite, persistence and sibling restrictions continue
to inspect every import. No product, tool, workflow, schema or configuration
byte changes in this correction. The two edited files are the dedicated
specification and `tests/test_kbc_contracts.py`.

## Original red and assertion preservation

The spec-first 247-case run records **13 failures / 234 positives**, zero
errors/skips, in 0.85 seconds. Three failures are the actual existing service,
store and wiring imports; ten are newly authored permitted forms. The 57 new
refused forms already fail closed. The exact probe/test bytes, command, JUnit,
output, source hashes and owned failed-run directory are retained.

Independent structural comparison proves all 45 original functions remain
identical in the spec-first commit. The four new test functions expand into
67 controls and remain unchanged through the fix. Removing only the new
explicit `input_readers` branch restores the original guard AST exactly.
No prior assertion, parametrization or skip was removed. The guard fix itself
has 14 insertions and one replacement line. Both author and independent
verification preserve exact source/import receipts and normal cleanup behavior.

The independent review records one verifier-only path error: an optional
root-level `schemas` tree does not exist. The first structural command stopped
before pytest or a file write. Its corrected check uses the actual exact changed
paths and source/tool/workflow/configuration trees. That correction did not
change product source or a test assertion.

This guard inspects explicit imports in the existing top-level KB domain files.
It is not a runtime sandbox or new held-origin entry point. Native sharing,
durable reader-less recovery and package qualification remain separate gates.

## Actual full Linux result at preceding published source

Hosted run **44409973351**, Linux job **135175350876**, completed at
2026-11-18 22:52:53 UTC with failure. It checks out merge preview
`ac6632ad6de486ba16343f0eeb4a2b5a446e4ac1`, whose tree equals published head
**771e5a775f5bf60a8d9094232b51dcdbb47d6389**. The canonical tree is
`ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`; main remains
`9c411ca3d7b47f950be5f0c6f01b3c54184554c6` at the separately retained priority
readback. No main merge or release action occurs here.

The command `python -m pytest -q --junitxml=qa-results.xml` reports
**25,292 passed, 3 failed, 60 skipped, 3 xfailed, 21 warnings in 1893.98 seconds**.
Its three failures are exactly the static guard cases above. JUnit contains
25,358 cases; its 63 skipped elements include the three expected failures.
The preceding immutable-publication selection reports 134 passes / 3 skips.
The subsequent hosted normal Ruff step is skipped after the full-test failure.

The original hosted result remains failed. The corrected local scope does not
retroactively qualify that job or convert its skipped/expected-failure cases
into passes. The old-source full run also does not qualify the newer core
admission or subsequent workspace/native changes. At the separate refresh,
five Windows/Qt jobs remain in progress and the release gate remains skipped.

Root verified the 434,680-byte original Linux artifact, all three ZIP members,
exact 96,006-character decoded log, API ownership, merge-preview parents and
eleven canonical source snapshots. Its sealed 27-payload packet is retained
alongside this correction. No artifact or target image was executed locally.

## Continuing work and release boundary

The independently verified core checkpoint already retains the 1,200-pass
affected gate at a8f698f6, actual Windows dependency UTF-8 acceptance, the
restricted NUL-open failure and unified repeated-analysis mismatch. This guard
correction keeps all of those outcomes and the strict 80-site failure intact.

The next bounded workstreams are the explicit non-initializing workspace open
and acquired-connection handoff, trusted stdin duplication inside the existing
Windows handle list, and bounded first/second unified evidence retention. Real
CVE/KB/analyst journeys, final platform/Qt/native/package/security/reproducibility
gates and qualified main consolidation are still required. No beta-readiness
claim, branch deletion, force-push, tag, release or deployment is made.

## Archive integrity

42 payloads; 1,960,597 bytes. SHA-256 `cfd6dcbb12ab72e820fb37f555ae77dd5707d0da3193d6782e3af258b4776510`.
