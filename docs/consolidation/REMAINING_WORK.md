# Remaining consolidation work

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Recorded source: `7dfba50f`; draft PR #320. No Git conflict is unresolved. Full
consolidation is **in progress** and is not qualified for default-branch merge.

## Immediate actionable work

1. Finish and independently review Tier-W runner cancellation and paired output
   preservation; integrate the dedicated regression controls. Assess whether the
   CLI can safely expose the existing library runner only after those gates pass.
2. Recover the current managed Tier-R training-artifact slice from `c13d3257`,
   including shard/merge ownership, generated schema and opt-in CLI integration.
   Preserve current legacy diagnostic behavior and current CI pins. Test refusal
   of a rerun without clobbering the earlier completed transfer's diagnostic.
3. Recover useful research runner/receipt entry points from `2fdac2ea` against
   current manifest/output-store/preregistration interfaces. Port individual
   compatible slices with provenance and bounded-input controls.
4. Complete the frozen `7dfba50f` sequential test run, inspect every failure, fix
   reproducible defects and run affected suites for subsequent code changes.
5. Refresh the complete remote census and semantic residue against the eventual
   final candidate. The present inventory's semantic comparison is `77204ef5`;
   it deliberately leaves 43 branches without historical focal receipts and
   broader residue on other branches open. Examine docs/config/test deltas as
   well as missing Python filenames. Review old #102 packaging/parser residue.
6. Run current-source static/security/dependency checks, investigate actual
   findings, and inspect exact-head CI receipts. Preserve release gates.
7. Publish each coherent tested checkpoint to PR #320 using an expected-head
   update with exact local/remote tree equivalence. Preserve local source history.

## Features requiring further decisions or external tools

- Tier-W network transport/resolve/fetch CLI adapters are still explicit blocked
  stages. Historical saved-plan fetch work at `codex/tier-w-fetch-20261015`
  (`c0255b78`, `68876dea`, `5b7b2591`) must be compared with current library APIs
  and consent/ownership contracts before selective recovery.
- Tier-W audit/review/audit-report CLI stages still need usable adapters and
  conservative identity handling; their pure libraries are present.
- Linux forced publication retains the final source-name race described in
  `SECURITY_REVIEW.md`. Content verification detects bad publication but does not
  restore a displaced destination automatically.
- Windows native file/formatter/fixture gates, repeated Qt gates, real native
  engine compatibility and a standalone Windows build require suitable runners.
- Accuracy acceptance requires verified corpus facts and separate L1/L2/L3
  results. Fixture or mocked backend tests do not satisfy that requirement.

## Constraints, not stopping shortcuts

The shared workspace reached ENOSPC and an initial full pytest process was
killed; a later execution outage recovered. Dependencies now live in the task's
dedicated home-directory virtualenv and broad QA uses bounded processes. Keep
the worktrees isolated; remove only this task's verified disposable artifacts.
Do not delete other workers' data or weaken gates to save space.

No branch deletion, source-branch rewrite, force merge, release or deployment is
part of this checkpoint. Further safely actionable work remains authorized.
