---
name: patchtrace-parallel-handoff
description: Coordinate PatchTrace parallel agents with unique branches, isolated file ownership, valid shared contracts, fast reviews, tested merges and no orphaned branches.
---

# Parallel worker contract

Read `AGENTS.md`, current branch heads and open PR checks, `docs/plans/multi-instance-coordination.md`, and the relevant specs before assigning work. Pair with Superpowers `dispatching-parallel-agents`, `subagent-driven-development` or `using-git-worktrees` where supported.

- Each worker gets a distinct branch, files and modules exclusively owned, current spec paths, acceptance criteria, exact stop condition and expected proof. Agree on shared contract seams before parallel work.
- Never let two agents independently edit the same path. Sequence overlapping changes and honor other agents' branches.
- Keep commits small and PRs reviewable. Require exact SHA, changed paths, tests run, results and current blockers in handoffs.
- Refresh heads and verify CI before integrating. Review the diff; do not suppress failures or overwrite other agents' work.
- Merge reviewed, passing work promptly; report intentional unmerged tasks and clean up only branches confirmed redundant.

Token efficiency is achieved through narrow worker briefs, not missing acceptance facts.
