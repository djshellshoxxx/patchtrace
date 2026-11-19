# Remaining consolidation work

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Recorded code: `cb1b508c`; draft PR #320. No unresolved Git conflict. Consolidation
is in progress and is not qualified for default-branch merge.

## Immediate actionable work

1. Review and integrate the explicit incomplete-project retry workflow. Ordinary
   creation cancellation, context-bound adoption and primary-error cleanup are
   already integrated; reuse the current exact-schema and ownership mechanisms.
2. Complete independently reviewed saved FetchPlan execution and its explicit
   consent CLI. Offline plans and bounded streamed transport are integrated;
   the executor must revalidate current inputs, exact plan digest/hosts and
   existing destinations before requests and preserve completed outcomes.
3. Refresh the all-page remote census and semantic residue against the new
   candidate, including the newly observed active branches. Original census:
   319 branches, 59 tags, 309 PRs; semantic baseline 77204ef5. The 43 branches
   lacking historical focal receipts still require bounded source/doc review.
4. Inspect native-receipt/journey tools, research probes and cloud automation
   residue. Current inspection lifecycle replaces the old TaskRunner helper's
   analyst behavior, while bench_workloads has narrower active-harness additions
   worth assessing. Historical config.py was an unwired tested proposal, not a
   lost working settings flow; assess a current consumer before importing it.
5. Add reviewed package producers for the strict build-info consumer and qualify
   native frozen packages. The new version command deliberately reports source
   cleanliness as unknown, avoiding Git clean-filter execution.
6. Resolve the open Linux forced-publication source-name race or explicitly
   narrow the supported guarantee. Continue current-source parser/publication,
   dependency and strict-security review without relaxing acceptance thresholds.
7. Qualify the final integrated candidate. The frozen `7dfba50f` run covers 953 files
   but retains nine later-fixed KEV errors, one host-denied AF_UNIX failure and
   three killed 60k benchmark cases. Completed counts: 25,943 passed, 150 skipped,
   three expected failures. Keep source scopes and omissions explicit. Reattempt
   high-memory cases only when the environment can support them.
8. Publish coherent reviewed checkpoints to draft #320 using expected-head updates
   and exact local/remote tree equivalence; retain source history. Inspect hosted
   receipts, including actual source trees, before crediting any native result.

## Open engineering and external gates

- Linux forced publication detects a bad final source-name race but cannot promise
  restoration of prior bytes. Shared immutable no-replace stream publication has
  a stronger separate contract; do not conflate them.
- Tier-W multi-file outputs are not filesystem transactions; retained attempts
  and explicit concurrent-writer limits remain part of the contract.
- Strict security Ruff reports 81 findings at ecfd5960; the original 80 are also
  reproduced in the hosted `087f` artifact. The extra query construction uses fixed
  identifiers/caps and bound SQLite values; the gate still fails.
- Fresh dependency profiles, native Windows ownership, actual Ghidra/Ghidriff/
  BinDiff/capa compatibility, repeated Qt acceptance and Windows standalone
  packaging still need actual evidence at the accepted source. Historical Linux
  rz-diff 0.9.1 passed a real 30-match control on 087f's tree; it does not qualify
  a newer candidate or other engines/platforms.
- Accuracy needs verified corpus facts and separate L1/L2/L3 results. No authored
  fixture or mocked tool result satisfies that gate.

## Resource continuity

Two executor outages lost home/tmp state while workspace Git survived. The actual
virtualenv is `/workspace/scratch/792fd5ca6555/.venv`. Bounded test attempts and
raw failures are archived; the full-file manifest contains no duplicate credited
cases. Workspace disk is constrained. Only identical immutable historical
archives were deduplicated within this task's own worktrees. Do not edit those
archives in place or remove another task's data.

No source-branch rewrite/deletion, default-branch merge, release or deployment has
been performed. Further safely actionable work remains authorized.
