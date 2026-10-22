# PatchTrace agent skill catalog

Use `AGENTS.md` and `docs/specs/agent-skill-workflow.md` (SPEC-56) to determine what to read before editing code. The skills folder is an optional, task-specific workflow catalog. Select by skill name and description, then read only the required `SKILL.md` documents. Never load the entire folder into every agent's context.

## Superpowers (already present, unchanged)

At upstream commit `bb92a77741419a4ab5f06e711a283343f1ada0c3` the existing 15 skill packages and all their support files were byte-identical with `obra/superpowers`. They are: `brainstorming`, `diagnosing-superpowers`, `dispatching-parallel-agents`, `executing-plans`, `finishing-a-development-branch`, `receiving-code-review`, `requesting-code-review`, `subagent-driven-development`, `systematic-debugging`, `test-driven-development`, `using-git-worktrees`, `using-superpowers`, `verification-before-completion`, `writing-plans` and `writing-skills`. Source https://github.com/obra/superpowers, MIT license at `_third_party_licenses/obra-superpowers/LICENSE`.

## Caveman (new static imports)

Source https://github.com/JuliusBrussee/caveman at commit `d262ab3882952a59312ff3537cd86d894523c5ab`. Imported unchanged `SKILL.md` only for `caveman`, `caveman-commit`, `investigate-first`, `lean-build`, `safe-refactor`, `surgical-patch` and `verify-and-stop`. Apache-2.0, NOTICE, LICENSING.md and legacy MIT notices are in `_third_party_licenses/JuliusBrussee-caveman/`. No installers, hooks, proxy, CLI, cloud connection or telemetry are installed. Caveman's terse-output style is opt-in; exact code, evidence, logs, error messages, tests and technical documentation must remain complete.

## PatchTrace-owned skills (new)

| Skill | Select when |
|---|---|
| `patchtrace-spec-routing` | Product development, changed contracts, specs, integration and contract-derived testing |
| `patchtrace-evidence-integrity` | Binary parsing, diffing, CVE/security evidence, data provenance, network/providers and exports |
| `patchtrace-test-and-release` | Local tests, CI, Windows native packaging and release acceptance |
| `patchtrace-token-efficient-work` | Any agent task where context, delegation and token consumption can be reduced without losing quality |
| `patchtrace-parallel-handoff` | Agent delegation, competing branches, open PRs or merge coordination |

These project-owned skills are instructions only. They are subordinate to `AGENTS.md`, accepted contracts and security rules. Before adding/updating an external skill, review its source revision, licenses, network behavior, install scripts, output requirements and conflicts.
