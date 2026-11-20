# PatchTrace engineering handoffs

Repository: <https://github.com/djshellshoxxx/PatchTrace>.

Start with [generation 17](generation-17-20261120.md) for the held offline
source admission repair and its limited reproducible controls, then read
[generation 16](generation-16-20261120.md) for the preceding read budget and
rejected-row fix and [generation 15](generation-15-20261120.md) for original
source selection. These successors remain distinct draft-only candidates.
Then read [generations 9–14](generation-9-through-14-20261120.md), the
[machine task ledger](../engineering/task-ledger.json), and the
[feature inventory](../engineering/feature-status-20261119.json). Resolve
current refs and CI before claiming any new ownership.

The [master directive](master-directive.md) preserves the authorized scope.
[Generations 2–8](generation-2-through-8-20261119.md) retain the initial integration.
[Generation 1](generation-1-20261119.md) is historical; its assignments do not
imply those workers are still running. The frozen
[reference census](../engineering/consolidation-inventory.json) and
[human interpretation](../engineering/consolidation-inventory.md) retain
unreviewed work explicitly. Later refs need a delta inventory.

## Successor bootstrap

1. Read the current handoff, task ledger and `AGENTS.md`.
2. Fetch heads, tags and pull heads; check current main/candidate, open PRs and
   active worker ownership against recorded identities.
3. Claim an unowned bounded scope in an isolated branch. Prove semantic and
   behavioral uniqueness before editing; unmatched history is insufficient.
4. Preserve a failing reproduction, update contracts first, implement and obtain
   independent review. Retain failures and exact source/test evidence.
5. Run meaningful affected checks and required combined gates. Keep native,
   mocked, offscreen and empirical-accuracy evidence distinct.
6. Publish a reviewable result, update this index and ledger, then transfer the
   next actionable scope to an actual worker or scheduled execution.

Focused passes do not authorize main promotion. Applicable checks must be green,
with no blocker and a fresh expected-head REST merge guard. Release publication
remains a separate process.
