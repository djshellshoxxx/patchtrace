# Rules repair consolidation — 2026-11-02

PR #146 was integrated into its existing coordinator, PR #126, after the exact
head completed the checks stated as pending in its original draft description.
Independent source review found no blocker in the three-file repair. No branch
protection was bypassed; the PR was marked ready and merged through the ordinary
GitHub PR API with an expected-head guard.

| Item | Verified identity |
|---|---|
| Reviewed #146 head | `798e11ef345ed7a7a65508a466eaf77ee85ef77c` |
| Coordinator head before merge | `8d958f0a1950a29c1d1cef9525a114654f4c9904` |
| Coordinator merge commit | `280bf05856eb60f4ddb0d58210616f65a3735816` |
| Resulting tree, identical to reviewed #146 | `e29d83a20e9a6d2d3e1a023f51fb30350d88bc73` |

Exact-head QA run `41172562182` and native run `41172562184` both completed
successfully. All 19 check runs completed: 16 successful and three skipped
(CodeRabbit, release, release-gate). Full Linux/Windows pytest and Ruff steps,
all Qt legs, Linux packaging/smoke, Sonar, and existing native controls passed.
Snyk's status context also reported success. Inline review threads and submitted
GitHub reviews were empty. CodeRabbit's skip is not a review approval.

The merge preserves the actual parent commits. After the operation, #126 remained
open and draft. Its description now records the current source scope and pending
main integration, rather than relying on its initial docs-only description.

This is consolidation within the development lineage. The seven rules paths are
still absent from main and #163, the named-superseded warning needs disposition
under saved-scope semantics, and Windows special-device race acceptance remains
unverified. No source acceptance or final-build status is inferred from closing
the child PR.

The other disposition reports in this directory retain their original snapshot:
their count of 50 predecessor PRs was captured before #163 was opened and before
this separate parent-branch merge. Do not treat that count as a current open-PR
total.
