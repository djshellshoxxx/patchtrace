# SPEC-56: Agent skills and specification-first workflow

**Status:** approved, process and documentation only
**Date:** 2026-10-14
**Owners:** `AGENTS.md`, `CLAUDE.md`, `skills/`, `docs/specs/REGISTRY.md`, `docs/specs/INDEX.md`
**Runtime impact:** none. No application code, dependencies, network policies, hooks or build scripts are changed.

## 1. Purpose and coverage

Coding, review, testing and delegated agents must read **applicable** PatchTrace specs and use the relevant skills before editing product behavior. This is not a requirement to load every document for each task. Avoid incorrect changes caused by missing a feature's contracts, and avoid excessive context consumption caused by indiscriminate loading.

This repository already included all 15 Superpowers skill packages, matching `obra/superpowers` upstream at `bb92a77741419a4ab5f06e711a283343f1ada0c3`. Those files remain untouched. The following static Caveman `SKILL.md` packages were imported verbatim from `JuliusBrussee/caveman` at `d262ab3882952a59312ff3537cd86d894523c5ab`: `caveman`, `caveman-commit`, `investigate-first`, `lean-build`, `safe-refactor`, `surgical-patch`, `verify-and-stop`. Five project-specific skills bind these general techniques to PatchTrace. See `skills/README.md` and bundled third-party notices.

## 2. Instruction precedence

Explicit current task constraints and `AGENTS.md` product invariants govern. The `docs/specs/REGISTRY.md` canonical path/alias/status determines which spec is meant; approved current feature specs define behavior. `docs/modules.md` maps architecture/ownership, with source code and tests establishing the current implementation. `CLAUDE.md` provides agent entry guidance. General imported skills are workflow advice **only**. A skill cannot authorize work outside scope, change a security boundary, or override contracts, tests or user instructions.

A draft spec is not automatically implemented or approved. When sources disagree, document the conflicting paths and requirement, resolve through the relevant registered spec and owner, and do not silently guess.

Non-negotiable: never execute a target binary; never silently upload to external providers or make unconsented network requests; remain offline by default; never fabricate binary evidence, vulnerability conclusions, model output, provenance or test results. Unknown is not negative; do not label uncalibrated scores as vulnerability confidence or average independent engine scores. Do not commit Microsoft binaries, PDBs, Winbindex payloads, or copy GPL/AGPL engine code into the product. Ghidriff stays separate/unmodified. Preserve raw prior evidence on failure.

## 3. Mandatory per-task routing

1. **Classify task.** Read-only investigation, bug fix, refactor, new feature, data schema/contract, GUI, external adapter, packaging, documentation or tests. A narrow docs typo need not trigger complete architecture review.
2. **Discover specs.** Read `AGENTS.md`; use `docs/specs/INDEX.md` to locate candidate files, `docs/specs/REGISTRY.md` to determine authoritative aliases/status and `docs/modules.md` to locate owner modules. Check relevant `docs/plans/`, `docs/qa.md`, `tasks/todo.md` and active PRs if the task requires current integration context.
3. **Read applicable clauses.** Read the owning spec and necessary linked dependency/acceptance sections before editing. Include persistence/schema, failure modes, user consent, licensing and platform requirements if affected. Do not blindly ingest every spec.
4. **Trace requirements.** Keep a compact `requirement -> spec path/section -> owning source path -> expected test/acceptance` map, in a plan, PR description or brief internal working notes. Cite `path (canonical alias)` when SPEC numbers conflict.
5. **Check need for a spec edit.** If behavior, schema, API, evidence contract, UI workflow or security/privacy contract changes, update the owning spec before or together with code. Register a *new* spec only if material new behavior is not covered by existing specs. Add the new path/alias/status to `REGISTRY.md` and `INDEX.md`. Include invariants, failures, compatibility/migration, examples and test gates. Keep regular implementation and test changes synchronized with specs.
6. **Implement and verify.** Follow a narrow complete vertical slice, preserve module boundaries, add relevant negative and regression tests, and run project gates. Record actual results, blockers and open acceptance only.

For a read-only audit, use the spec to identify what should hold, but do not modify contracts unless asked. Documentation-only changes need not run application runtime tests, but must validate references and licensing.

## 4. Routing guide

| Task class | Specifications to inspect (choose relevant subset) | Skills |
|---|---|---|
| New module/integration | `architecture.md`, `schemas.md`, specific engine or integration specs and `docs/modules.md` | `patchtrace-spec-routing`, `lean-build`, `writing-plans`, `test-driven-development` |
| Known bug or uncertain cause | Existing owner spec, tests, QA | `systematic-debugging`, `investigate-first`, `surgical-patch` |
| Engine matching / diff / evidence fusion | `multi-engine-orchestration.md`, `unified-engine/`, `multi-engine-evidence-calibration.md`, `schemas.md` | `patchtrace-spec-routing`, `patchtrace-evidence-integrity` |
| PE and raw data | `pe-overview.md`, `byte-representations.md`, `pe-version-authenticode.md` | `patchtrace-evidence-integrity` |
| KB/CVE and acquisition | `kb-cve/`, `kb-patch-search-*.md`, `enrichment.md`, `network-egress-privacy.md` | `patchtrace-evidence-integrity` |
| Qt GUI / workflows / reports | `ui.md`, `gui-framework.md`, `accessibility-baseline.md`, report specs | `patchtrace-spec-routing`, `test-driven-development` |
| Safe architectural refactor | Affected contracts in registry, persistence/schema specs | `safe-refactor`, `test-driven-development` |
| Windows release / external tooling | `verification.md`, `windows-acceptance-and-milestone-builds.md`, `windows-release-signing-policy.md`, `docs/release-process.md` | `patchtrace-test-and-release`, `verification-before-completion` |
| Concurrent branches | Active PRs/checks, `docs/plans/multi-instance-coordination.md` and affected specs | `patchtrace-parallel-handoff`, `dispatching-parallel-agents` |
| Token-cost discipline | The *same* owning specs as a normal task | `patchtrace-token-efficient-work`, optionally `caveman` |

These are examples rather than an exhaustive list. Recheck index/registry because they evolve.

## 5. Token preservation without quality loss

Keep every necessary fact. Save tokens by targeted file/symbol searches, reading specific spec sections and file ranges, concise working plans, reusing current helpers and tests, eliminating repeated explanations, incremental proof, bounded worker tasks, and stopping at acceptance. Never shorten code, error output, test assertions, evidence, risk analysis, privacy decisions, paths, checksums, contract language or developer documentation to meet arbitrary brevity targets.

Use the least expensive model **likely to complete the assigned task reliably**. Low-cost workers may handle inventory, documentation, well-defined fixtures and mechanical edits. Use capable models for concurrency, security, binary evidence and architecture. If low-cost model retries cause more overhead, escalate; cost includes revisions, wasted tool calls and review. Delegate only independent modules with explicit branch ownership and a bounded handoff: goal, spec and clauses, owner paths, tests, acceptance and blockers. Avoid multiple agents for one trivial edit.

`caveman` style is opt-in. Its shorter prose is not proof of whole-session savings and should never be forced on reports, documentation, security warnings or irreversible operations. Never install its proxy, CLI, Cloud client, scripts, hooks or telemetry merely by importing `SKILL.md` files. No model/provider can be contacted without a legitimate task authorization and applicable consent.

## 6. Parallel implementation and review

Check latest `main` SHA, open PRs, passing checks and overlapping work. Workers must use unique branches and clear exclusive file ownership. Freeze shared seams or sequence dependent tasks. No worker may overwrite another worker's branch or assume a historical PR state still holds. Require small commits and PRs including exact revision, touched modules, focused test results and open gates. Verify integration CI against current head before merge; avoid orphan branches and duplicate efforts.

## 7. Verification and release

For code changes, execute focused positive/negative tests, then the applicable repo-wide checks `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools` where environment supports them. Regenerate schemas after contract changes. A mocked backend/provider check is not live interoperability. Linux cannot certify native Windows standalone packaging; record Windows and manual UI gates independently. Classify evidence explicitly as pass, fail, blocked or not run. Do not hide a CI failure or declare release acceptance without proof.

For changes only to this skill catalog or policy, verify that imported upstream files remain verbatim, each skill has readable YAML frontmatter (`name` and `description`), local links resolve, the new spec is in REGISTRY and INDEX, and no unsafe automatic installation/network behavior was introduced.

## 8. Sources, licenses and ongoing updates

`skills/README.md` records source commits. Existing `obra/superpowers` files remain unmodified under MIT. Imported `JuliusBrussee/caveman` SKILL files remain unmodified, under Apache-2.0; bundled LICENSE, NOTICE, LICENSING and legacy LICENSE-MIT are at `skills/_third_party_licenses/JuliusBrussee-caveman/`. No Caveman executable helpers are imported. Review future skill updates for upstream license changes, new dependencies, prompt overrides, hooks, telemetry and network operations before rebasing them. The source package may mention commands that are not installed here.

## 9. Acceptance criteria

The imported skills are discoverable, licensed and local. Existing Superpowers is unchanged. `AGENTS.md` and `CLAUDE.md` direct agents to consult SPEC-56, the canonical registry and relevant specs; no blanket all-spec loading. The five PatchTrace skills explicitly cover specs, evidence/privacy, QA/release, token efficiency and parallel handoff. This file appears in `REGISTRY.md` and `INDEX.md`. No product code or external runtime/tool installation changes. Test status claims are supported by observed evidence.
