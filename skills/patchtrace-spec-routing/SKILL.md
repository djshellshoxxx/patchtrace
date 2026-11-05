---
name: patchtrace-spec-routing
description: Find and apply PatchTrace's canonical specs, owners and acceptance gates before implementation, changes of behavior or contract-derived tests.
---

# PatchTrace spec routing

Read `AGENTS.md`, use `docs/specs/INDEX.md` to find relevant specifications, `docs/specs/REGISTRY.md` for authoritative aliases and statuses, and `docs/modules.md` for the owner of each layer.

1. Classify the work as investigation, bug fix, feature, integration, refactor, contract/schema change, verification or docs-only.
2. Identify exact behavior, entry points, boundaries, persisted schemas and tests. Read the **relevant** spec sections and linked acceptance requirements. Do not load all specs for every change.
3. Before editing, map `requirement -> path (canonical spec alias) and section -> module owner -> acceptance test` in a concise working plan or PR description.
4. Existing approved specs govern behavior. A draft is not permission to alter shipped semantics. Resolve contradictory docs explicitly; do not guess or silently create competing contracts.
5. Update the owning spec when a contract or feature behavior changes. Create a new registered spec only for a substantial new interface/invariant not covered by existing specs. Update both `REGISTRY.md` and `INDEX.md` and link affected schemas/tests.
6. Follow the narrowest complete module slice, with focused regression tests and required downstream gates. Log genuine failures and blocked acceptance.

Routing hints: GUI -> `gui-framework.md`, `ui.md`, `accessibility-baseline.md`; binary/PE -> `pe-overview.md`, `byte-representations.md`, `schemas.md`; engine -> `unified-engine/`, `multi-engine-orchestration.md`; KB/CVE -> `kb-cve/`, `kb-patch-search-*.md`; Windows -> `windows-acceptance-and-milestone-builds.md`. Consult the updated index for actual paths.

Full rules: `docs/specs/agent-skill-workflow.md` (SPEC-56).
