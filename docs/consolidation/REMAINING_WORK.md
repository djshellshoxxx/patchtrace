# Remaining consolidation work

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Recorded source: `eb595b82`; draft PR #320. No Git conflict is unresolved. Full
consolidation is **in progress** and is not qualified for default-branch merge.

## Immediate actionable work

1. Finish and independently review Tier-W offline audit/review/report and selected
   run CLI adapters. Runner cancellation and paired-output repair is integrated;
   cancelled attempts must identify their retained record, not prior run.json.
2. Recover strict saved FetchPlan and consent-gated exact-plan execution against
   current fetch/transport APIs. Retain throttling and owned no-replace outputs;
   historical loose/unbounded transport code is not an acceptable replacement.
3. Recover production Search stored-source wiring with bounded owner-thread
   snapshots and current source identity. Recover Strings shared CLI/GUI comparison
   context and source choice while preserving the newer export ownership repairs.
4. Finish the frozen `7dfba50f` bounded suite. Repair the reproduced KEV fixture's
   socket-class/import-order error. Preserve host-denied AF_UNIX acceptance as an
   explicit environmental failure. Qualify later changes on affected selections.
5. Refresh the complete remote census and semantic residue against the final
   candidate. The current inventory's semantic comparison is `77204ef5`; 43
   branches lack historical focal receipts. Review docs/config/test deltas and
   old #102 packaging/parser residue, not only missing module names.
6. Inspect remaining project retry/lifecycle, config/build provenance, native
   receipts/journey gates and research probe/automation branch contributions.
   Compare actual current behavior before importing obsolete helpers.
7. Run current-source static/security/dependency gates and inspect exact-head CI
   receipts. Keep separate native, package and real-data accuracy qualification.
8. Publish each coherent tested checkpoint to draft #320 using an expected-head
   update and exact local/remote tree equivalence; retain local source history.

## Open engineering and external gates

- Linux forced publication has the final source-name race described in
  `SECURITY_REVIEW.md`; detecting a bad publication does not restore prior bytes.
- Tier-W multi-file labels/evaluation and run outputs are not filesystem
  transactions. Preserve retained attempts and explicit publication limitations.
- Strict security scan still reports 80 classified findings at `3c6f5905`.
  Fresh isolated dependency/platform qualification remains open even though the
  installed Linux development environment has zero current advisory findings.
- Native Windows ownership/formatting/fixtures, repeated Qt acceptance, actual
  Ghidra/Ghidriff/Rizin/BinDiff/capa compatibility and Windows standalone package
  checks require suitable actual runners and evidence at the accepted source.
- Accuracy acceptance needs verified corpus facts and separate L1/L2/L3 results.
  Fixtures and mocked engines cannot satisfy that gate.

## Resource continuity

Two executor interruptions lost home/tmp state while workspace Git files survived.
The virtualenv is now an actual directory at
`/workspace/scratch/792fd5ca6555/.venv`. Broad QA uses bounded processes and retains
raw failures. Only identical immutable historical archives were deduplicated
within this task's own worktrees; do not edit those archives in place. Do not
remove another task's data or weaken gates to save space.

No branch deletion, source-branch rewrite, default-branch merge, release or
deployment is part of this checkpoint. Further safely actionable work remains
authorized.
