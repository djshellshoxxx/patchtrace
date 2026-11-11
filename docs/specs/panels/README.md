# Panel specs

Index of per-panel implementation specs. Written 2026-10-15.

| File | Status |
|---|---|
| `related.md` | proposed contract for the FAB-6 panel `related` (no manifest slot yet); written from the code |
| `build_env.md`, `capabilities.md`, `graph.md`, `guide.md`, `kb.md`, `kev.md`, `rules.md`, `search.md`, `strings.md` | NOT in this directory on `claude/instance-d-gui`. ChatGPT drafts, unreviewed, live on `origin/chatgpt/panels-1` (commit `cfd7cff`); read one with `git show origin/chatgpt/panels-1:docs/specs/panels/<id>.md`. Their companion `docs/plans/panels-build-plan.md` (same branch) lists binding corrections to older plans in its section 2 |

Existing panels (`evidence`, `unified`, `leads`, `files`, `series`) keep their own specs; see `docs/handoff/features-and-panels.md` section 1.2.

When a draft is reviewed and merged, copy it into this directory with the same file name (the names above do not collide with `related.md` or this README), update this table, and keep the "Status" line of the file itself honest (a draft says UNVERIFIED about runtime facts; remove the marker only after a test or run supports the claim). The build recipe for any panel is `docs/handoff/features-and-panels.md` section 3.0.
