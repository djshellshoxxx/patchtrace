# PatchTrace integration queue

Authority: [task-ledger.json](task-ledger.json). Refresh remote refs, source-specific
checks and active ownership before every consequential action.

| Order | Unit | State | Dependency / next action |
| --- | --- | --- | --- |
| 1 | Existing PR #344 stack at `67f7e08e` | Preserved; hosted qualification active at capture | Read actual latest CI; parent successes do not transfer |
| 2 | Cycle 95fe request-order repair | Reviewed and merged locally | 183 related cases pass on combined source; full and hosted results remain required |
| 3 | Cycle 95fe narrow PR #321 GUI recovery | Reviewed and merged locally | Preserve newer Evidence methods; actual accessibility remains separate |
| 4 | Cycle 95fe inventory replay repair | Reviewed and merged locally | Ten inventory cases pass on clean combined source; captured report replays identically |
| 5 | Cycle 95fe coverage additions | Reviewed and merged locally | Full source-specific qualification |
| 6 | Other foreground TaskRunner / report / publication work | Owned by separate active session | Inspect its exact final commits, review and evidence; reconcile disjoint changes |
| 7 | Main integration | Blocked | All applicable checks green, no blocking findings, fresh expected-head REST merge |
| 8 | Release/deployment | Not authorized by this cycle | Separate explicit approval and complete acceptance gates |

## Preserved donor branches

PR #321 is only selectively recovered. Its optional Search-source wiring and
Strings composition remain retained for separate scope and dependency review.
Do not replace current files wholesale. The historical UI/integrity branches in
[semantic review](cycle-95fe-semantic-review.md) need no further implementation
port for their reviewed behaviors; preserve their refs and historical records.

## Publication rules

Publish this reviewed candidate on a new branch based on PR #344. Preserve
local commit lineage and exact source trees. If connected Git Data API creates
different commit IDs, record the local/remote mapping and verify identical trees.
Never move another worker's ref or force-push. The configured PR workflows must
supply QA, Qt, native and package evidence; no workflow or test gate is weakened.
Keep releases disabled with the existing `[no release]` convention.

The terminated local full run does not qualify this candidate. Bounded tests and
mechanical/semantic branch reviews remain useful independently of that blocked
aggregate. Do not repeat the killed command unchanged merely to obtain a pass.
