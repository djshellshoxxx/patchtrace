# Claude Code entry point

Read [AGENTS.md](AGENTS.md) first; it is the authoritative engineering policy. Then read [docs/modules.md](docs/modules.md), [tasks/todo.md](tasks/todo.md), the relevant [docs/specs](docs/specs), and the current [autonomous alpha handoff](docs/plans/claude-autonomous-alpha-handoff-20261013.md).

This repository has **active parallel contributors**. Before starting implementation, inspect GitHub's current default-branch SHA, all open PRs and their checks. Do not reuse stale snapshot facts or overwrite any other worker's branch. The handoff records the state observed on 2026-10-13; changes may have landed since.

Work spec-first when changing interfaces, use red/green regression tests for behavior, keep pure domain models and adapters separate from Qt, and preserve existing persisted contracts. Prefer small mergeable slices over long-lived speculative branches. Prioritize build/CI correctness and a usable **Windows standalone alpha**, then the next SPEC-26 inspection slices. Run focused tests during development; run full Linux/Windows CI gates for integration. Report genuinely blocked external acceptance separately from automated evidence.

Cost discipline: use the lowest-cost model that can do each task reliably, and only delegate bounded independent work. For narrow searches, docs, test fixtures and straightforward lint, use a low-cost model. For integration, architecture and nontrivial implementation, use a capable mid-tier model. Escalate to highest-tier reasoning only for a demonstrated hard blocker, nuanced security invariant, or failed lower-cost approach. Do not pay for repeated retries with an underpowered model. Avoid agents for single-file edits.

Do not automatically ship a final release, silently bypass a failing test, or falsely claim a successful GitHub Release when the token is missing permission. Leave a verifiable handoff, PR links, exact test results and open gates.
