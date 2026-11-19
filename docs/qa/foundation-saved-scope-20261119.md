# Foundation saved advisory scope repair — 2026-11-19

## Reason and scope

PR #304 at `d8c02caea407f6d323eecd636735849c1eb31a2d` retains a source-scope correctness blocker from historical issue #118. An independently authored control takes the committed factual CVRF fixture, gives two revisions the same publication date, and removes remediation claims from one revision. Both revisions remain active. The complete corpus correctly disputes all 43 positive edges. Selecting only the positive document incorrectly resurrected all 43 edges and removed the revision-conflict warning. Both zoned and unzoned date cases reproduced this defect. These are synthetic mutations of factual source bytes, not a new accuracy result.

This narrow port applies global revision admission before projection into a saved finite source scope. It records cached-corpus document membership, validates saved search coverage before derived decisions or writes, refuses missing or changed members, and preflights captured journal revisions before attachment recovery. Context identities use the same scoped admitted-edge digest as their content. Explicitly selected superseded documents retain an explanatory warning. Existing revision CAS, approval, journal, and generic recovery behavior remain in place.

The base is #304; this does not import the whole later #316 stack. Inventory selection, later UI work, provider transport, and native implementation changes are outside this port. No public schema or SQL version changes.

## Provenance

The selected implementation and regression material comes from #316 at `f2b6827fc6270b96fb241b0722f2878de5a17361`:

| Source commit | Material recovered |
|---|---|
| `e9c29800228294894a41c7aa6ffe0e3397856c11` | Saved-scope validation and service preflight; original source `60d8006358dc82a49a42e57eaaac548d4706359f` |
| `3919740d03c9f6432c63d94107f0ce2404c09e90` | Global revision admission, finite cached history, and admitted-edge context key |
| `27ed192b131fdfdc98965c22689806a73f77c6db` | Explicit superseded-source warning |
| `5ab904548e16df799cb924e63ae47b35989d4b0d` | Specifications and initial saved-scope regressions |
| `a200616a67a39735890b04ab86930decd25d2d42` | Negative-status assertion aligned with admitted grammar |
| `a07fc1cf1c8d618d8d4b451888c286815a4e02de` | Empty/captured boundaries and existing card-context fixture coverage |
| `c7f239b4318e3735adab5035ec1502059ffca83c` | Valid cached receipts and admission-sensitive context controls |
| `76843542a10ea0f81ac1ec5a19417ef55ab1d5ae` | Schema-valid authored CSAF withdrawal |

The three production files `index.py`, `context.py`, and `saved_scope.py`, plus the four dedicated support/test files, match the final source blobs on #316. The service patch is the selected `e9c29800` diff applied cleanly to #304. Inventory-only specification text is omitted because foundation has no corresponding feature. The card-context test now supplies its actual index coverage; all provenance assertions remain unchanged. The later pilot test is absent from #304 and is not imported.

## Actual verification at commit preparation

| Check | Observed result |
|---|---|
| Independent native-revision scope probe on unchanged #304 | Both cases fail: 43 positive scoped edges, no conflict warning |
| Same probe on unchanged #316 | Both cases pass |
| Same probe on repaired foundation worktree | Both cases pass: zero positive edges, 43 disputed edges, warning preserved |
| Dedicated saved-scope regression files against old foundation source | 73 failed, 7 passed in 23.33 seconds |
| Same three files after repair | 80 passed in 100.10 seconds |
| Whole `src tests tools` Ruff and whitespace checks | Passed |
| Existing card-context source file after fixture correction | 11 passed in 8.01 seconds |
| First broader affected attempt with xdist | Zero tests, exit 5; command included a pilot test path absent on #304 |
| Repeated broader attempt without xdist | Zero tests, missing-file error; no xdist defect established |
| Corrected broader affected suite, Qt, whole-suite and exact-head hosted gates | Pending at this checkpoint |

The 80 dedicated tests include cached and explicit scopes, source removal/change, global native conflicts, monotonic replacement, context identity, CLI/service refusals, captured repair preflight, and no-side-effect controls. Counts overlap with later broader selections and must not be added together. The red count represents failing assertions across related scenarios, not 73 distinct product defects.

Raw red/green logs, JUnit, independent probe and receipts are retained in [the evidence packet](foundation-saved-scope-20261119/manifest.json). Large red logs are gzip compressed without loss. The early repaired probe reports the base HEAD because it ran before commit; the manifest binds it to exact production-file hashes. It is worktree evidence until the committed-head follow-up completes. The initial failed broader commands remain preserved.

## Acceptance limits

Independent review and exact-current-head hosted qualification are required before merge under the owner's all-test-jobs-green rule. This Linux work does not qualify native Windows, packaging, live services, release, or L1/L2/L3 accuracy. No release or package is requested or produced.

Historical remaining scopes include the primary engine's total-output/memory bounds, profile-switch dirty-state handling, and acquisition index-pair provenance. These are not represented as fixed by this port. The source-scope change intentionally refuses legacy saved searches with no auditable source coverage; users must rerun those searches. Attachment recovery now fails before mutation if any captured scope cannot be validated.
