# Navigation-only validation QA receipt

[Sealed archive](signal-navigation-validation-20261118.zip): **150 members**,
**801,824 bytes**, SHA-256
`c5bfd92f7e884661fa54572a99dbf3739ca2a7ca8c19edff208dfcb2155dde80`.
All archive members and 45 exact Git source/test/spec snapshots were read back
and verified. Seven append-only commits retain the original specification,
fixture corrections, candidate source, size-limit correction and reviewed
representation-scope extension.

## P2-NAV-1 navigation validation: author evidence

Baseline: `068513a72e8a1412ce3960d3024c462d68d51376`.
Final production: `9592f8b362537c0545010d4499e35770a248297e`, tree
`b45bb30da5489bfac18ba1e68e5afaedc31ab296`.

The only changed existing production symbol is `MainWindow.jump_signal`.
It delegates its location action to the new 19-line `ui_signal_navigation.py`.
The helper refuses non-decompiled representations, calls the unchanged live
`views.validate_location`, and only then preserves the existing mode/reveal
behavior. Fixed typed error text is bounded to 300 characters and uses the
existing plain error presenter. No detector, score, confidence, model, schema,
cache, storage or publication implementation changes. The unchanged host seam
ceiling is 3077 lines; final `ui.py` is 3069.

## All actual outcomes are retained

| Receipt | Source | Actual outcome and meaning |
| --- | --- | --- |
| `original/navigation-boundary-red` | 068513a7 | 3 failed / 4 passed, 1.67 s: original persisted/reopened location defect; malformed rows intentionally authored through the real store |
| `spec-red` | 390f6123 | 10 failed / 1 passed, 6.09 s: nine deleted Qt item fixture failures and one existing source/evidence consistency guard; not the corrected product regression |
| `spec-red-corrected` | 74fd5f52 | 8 failed / 3 passed, 5.29 s: real wrong/stale navigation, all failures at `assert not revealed`; fixtures reacquire live list items and use normal evidence invalidation |
| `final-affected` | 0c7c8682 | 170 passed / 1 failed, 24.89 s: unchanged UI line ceiling exceeded by one; no test or cap relaxation |
| `final-original` | 0c7c8682 | 7 passed, 1.77 s: original probe byte-identical, fresh observations |
| `final-affected-budget` | c8ee650f | 171 passed, 23.87 s: method-local import consolidation fits the existing cap |
| `final-original-budget` | c8ee650f | 7 passed, 1.51 s: unchanged original replay |
| `root-review-original/initial` | c8ee650f | 2 failed: root probe's sample lacked authored assembly; no navigation was reached |
| `root-review-original/fixture-corrected` | c8ee650f | 1 failed / 1 passed, 1.05 s: assembly-valid stored location reveals unrelated decompiled text; v2 adds inert assembly without changing expected assertions |
| `representation-spec-red` | 2c48f4c5 | 4 failed / 11 passed, 8.50 s: assembly and metadata in both current modes wrongly reveal text |
| `final-representation-affected` | 9592f8b3 | 175 passed, 27.94 s: ten files, all original location neighbors, new representation cases, host seam and global tooltip sweep |
| `final-representation-original` | 9592f8b3 | 7 passed, 1.49 s: original Phase2 probe unchanged |
| `final-representation-root` | 9592f8b3 | 2 passed, 0.94 s: root v2 representation probe unchanged |

Every listed test invocation has zero skipped cases and zero collection/setup
errors in its JUnit report; the initial failures described as fixture defects
are assertion/runtime failures within tests. Required `ruff check src tests tools`
and `git diff --check` pass on the final source. Earlier Ruff/diff receipts are
also retained. Counts serve separate overlapping purposes and are not additive
coverage or a completion percentage.

## Proof and preservation

The original location probe SHA-256 is
`61b5d7c21778e12ba71bc6d32a0779f7d1d457656955bf2bfdab64c8c5953688`.
Root's original representation probe is
`cbae7fc481bb206000735d3a314c3076b86c219c16e0dccab157c35147005002`;
its corrected v2 is
`828f531e083ec4dc04733298ca976e1da5e9c0648db8af08c391627ba808f3a5`.
Original source files, observations and failures remain unchanged at their
original paths and are copied byte-for-byte here. Observation-only routing
records bind the final fresh destinations; no inputs or expected assertions
are replaced. Source pins and normal system-temp fixtures are explicit in the
command records. The first corrected-red process completed with exit 1 and
complete receipts; a later polling attempt returning an unknown process ID
did not interrupt or invalidate that run.

`source-proof.json` checks exact bytes and AST outside the owned UI method,
the two-file production boundary, all unchanged neighboring test files, and
unchanged validator/detector/scoring/storage/service source. `git-snapshots.json`
binds exact source/test/spec blobs. `history.json` and `commits/` retain all
append-only spec, fixture, source and ceiling corrections. `manifest.json`
binds every archive member except itself; all members and Git snapshots were
read back and verified before sealing.

The valid controls include exact displayed text in root's persisted/reopened
positive, existing decompiled behavior, mode switching, address zero and
repeat activation against live modified code. Refusals retain current mode,
cursor positions, project/ranking values and enrichment rows. They do not
claim that ordinary detectors produce the authored invalid rows.

## Limits and review

This is Linux/offscreen, authored source-backed validation. It does not qualify
native Windows, packaged/frozen applications, real engines, live providers,
manual desktop acceptance or calibration. No target or native engine was run.
The reference package is not imported or declared wire-compatible; its separate
disposition remains at `1307a627797063c64df79f4d2971b28df85b2c0b`.
Root independent final review/integration is separate from this author packet.
Later published PR316 trees are not relabeled as the tested 0685-based source.
No remote mutation, main merge, release or whole-branch closure occurred.
