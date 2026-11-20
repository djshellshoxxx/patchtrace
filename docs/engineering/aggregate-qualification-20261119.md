# Combined-source qualification

Source: `bffcfa99d6a5044024256edbc0457ab20c92cbae`.

The required unsplit `QT_QPA_PLATFORM=offscreen python -m pytest -q` ran in a
separate clean detached checkout, with JUnit output requested. Its process was
terminated by **SIGKILL (return code -9) after 1,729.332 seconds**, at
`2026-11-20T00:32:03.102136+00:00`. Qualification is **incomplete**. Pytest wrote
neither a final failure traceback/summary nor its requested JUnit file. The
original log and environment/source receipt are retained unchanged in
[`evidence/aggregate-qualification-20261120.zip`](evidence/aggregate-qualification-20261120.zip);
the adjacent JSON manifest records every archive member's hash.

A separate successful collection lists **23,756 node IDs**. The preserved log
contains 19,877 progress markers: 19,776 dots, 93 skips, six xfails and two
failures. Alignment with that collection maps the failures to the table
row-count test and the local Unix-socket test; the original exception details
are unavailable. **3,879 nodes had no reported result in that original run.** Progress markers are
not a terminal full-suite pass.

The same table test passed unchanged in isolation. Independent diagnosis
reproduced a separate test-helper error: class-wide call instrumentation counted
other model instances during pending Qt work. The bounded correction retains all
existing performance limits and application code. Its 186-case affected run and
the coordinator's 41-case table replay pass; these selections overlap. The
original aggregate table failure is not attributed to that defect without its
traceback. See [the diagnosis](qa-diagnosis-20261120.md).

The unchanged AF_UNIX acceptance test and an unguarded control both fail at
socket construction with `EPERM`, before the project's network guard is entered.
No permission, network control, skip policy or assertion was changed. That local
acceptance gate remains blocked.

The SIGKILL cause is **unestablished**. Environment diagnostic APIs are absent,
the exposed filesystem has no usable cgroup memory-event counters, and ordinary
kernel-log access returns `Operation not permitted`. A later free-memory reading
cannot establish the reason for the earlier termination. No OOM or host-load
cause is claimed.

The unreported remainder completed in **14 bounded fresh processes** against the
same frozen source: **3,849 passed and 32 existing skips**, with zero failures,
errors, xfails, missing IDs, ambiguous IDs or duplicate IDs. The entire boundary
module adds two deliberate overlap nodes for **3,881 distinct selected nodes**.
Every node reconciles to exactly one JUnit testcase. All 32 skips require the
unavailable LLVM/MSVC-free fixture toolchain; a separate capability check records
the missing tools and supported installer. No skip or policy was changed.

The interval was `2026-11-20T00:44:02.768Z` through `00:51:44.505Z`. The highest
per-process peak RSS was 845,428 KiB; this is neither host-total memory nor an
explanation of the earlier SIGKILL. Logs, exact commands, node results, runner and
checksums are in [`evidence/aggregate-remainder-20261120.zip`](evidence/aggregate-remainder-20261120.zip).
These receipts remain diagnostic coverage, not an unsplit-suite pass.

The later acquisition implementation and GUI helper correction were checked
together on clean detached source `97ca0adfad5ea4e6cae0648a55529b9165a40b21`:
**1,737 passed and one native Windows skip in 98.56 seconds**. Configured Ruff,
KB schema drift and whitespace checks pass. The exact 62-module selection and
source identities are in [`evidence/followup-combined-20261120.zip`](evidence/followup-combined-20261120.zip).
This affected selection overlaps prior runs and does not qualify the full suite.

The first integration checkpoint's later CSV reader-example and peer-review
commits change documentation only. `integration-checkpoint.json` is an explicitly
historical record of that checkpoint's equal `src`, `tests`, and `tools`
identities and source-history bundle. Configured whole-tree Ruff and pip check
passed there; sixteen schema generators completed without drift, and the CSV
worker separately rechecked Strings schemas. Later acquisition and test-helper
changes do not inherit a full-suite qualification from this interrupted run.

## Local history recovery

The REST publication uses a verified tree mapping. To recover the original
local commit history, first fetch the PR #322 prerequisite commit, then:

```sh
git bundle verify docs/engineering/evidence/integration-history-20261119.bundle
git fetch docs/engineering/evidence/integration-history-20261119.bundle \
  refs/heads/codex/maximum-completion-20261119-4c8d:refs/remotes/local-evidence/integration
```

The bundle tip and SHA-256 are recorded in
`evidence/integration-checkpoint.json`. It preserves the exact local source and
review SHAs without pretending that REST-created commits retain local timestamps
or identities. Later status/publication records remain ordinary repository files.

Native, Windows, manual, release and layer-specific accuracy gates remain
separate; consult `release-readiness-20261119.md` and `task-ledger.json`.
