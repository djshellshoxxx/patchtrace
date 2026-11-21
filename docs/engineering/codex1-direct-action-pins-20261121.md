# CODEX-1: reviewed direct Action pins

## Result and source

The candidate replaces **176 mutable uses** of **11 direct references** across
**21 workflow files** with verified full commit SHAs and readable release
comments. The two existing pinned uses are unchanged. All **178 direct remote
repository uses** now name immutable commits. No application source changed.

| Identity | Commit |
| --- | --- |
| PR #349 baseline | `11f51c105bf63946f59373ae605b937c4fee607a` |
| Contract before implementation | `d4ccc3a0d05442862feb6d2ac64bdf71525e5e03` |
| First pin candidate | `d66f170fdd54a6bac4b858467be7ecbc6aafed0d` |
| Final tested workflow/test source | `ff6c79f1a9c97877d061995cae40be38e42154f9` |
| Final tested complete tree | `82ea9ce307974544abd787e3649e2574e38036b5` |

The [contract and mapping](../specs/ci-action-pinning.md) link each reviewed
upstream commit. Existing major versions are retained. The current upstream
tag, peeled commit and exact manifest research was completed before this
implementation; the author census reproduced all 176 mapped occurrences.

## Preserved behavior and repaired source checks

Text comparison and parsed-YAML comparison verify that each workflow differs
only in the mapped `uses` value and its version comment. Triggers, permissions,
inputs, scripts, job ordering, concurrency, budgets, cache verification,
Linux frozen-smoke work, and release/Pages conditions are unchanged.

Nine affected test files now identify the reviewed commits. Existing allowlists
retain their permitted action identities. The Linux packaging check finds
actual `uses` fields for checkout, interpreter setup and artifact download,
so a version comment alone cannot satisfy presence or ordering assertions.
Only the historical CODEX-1 strict expected-failure mark is removed.

The first affected run exposed an older live-unified source check that rejected
every inline YAML comment. It refused the valid version comment on checkout.
That check now removes the YAML comment before inspecting the plain scalar;
unquoted colon-space and terminal-colon values remain rejected. Four direct
controls cover valid comments and both malformed scalar forms. The original
failed run is retained in the evidence archive.

## Actual qualification

| Source and selection | Outcome |
| --- | --- |
| Unmodified PR #349 workflows, maintained CODEX-1 check with `--runxfail` | **1 failed**, as expected for the 176 mutable uses |
| First pin candidate, 12 affected test files | **267 passed, 1 failed, 1 xfailed** |
| Final tested source, same 12 files plus the four scalar controls | **272 passed, 1 xfailed**, zero failures or ordinary skips |
| Whole-tree Ruff on final tested source | Passed |
| Isolated Python import binding on final tested source | Passed; resolves this worker's checkout |
| Dependency consistency on first pin candidate | Passed; follow-up changed only one test file |
| Final source patch whitespace | Passed |

The remaining expected failure is **CODEX-5**. Selections overlap and must not
be added. These tests are local source, shell-fixture, and owned-fixture checks;
they do not execute upstream Actions or establish native compatibility.

Full logs, JUnit, commands, original failures, source identities, before/after
workflow hashes and complete direct-use censuses are in the
[author archive](evidence/codex1-direct-pins-20261121/author-evidence.zip), covered
by its [manifest](evidence/codex1-direct-pins-20261121/manifest.json).
The [qualification record](evidence/codex1-direct-pins-20261121/qualification.json)
contains the source-specific counts and outstanding boundaries.

## Integration and remaining gates

This is a source-complete CODEX-1 direct-reference candidate. Independent review
and final combined-head hosted checks are required before guarded integration.
No remote ref, PR, main branch, release or deployment was changed by this worker.

Pinning the outer Pages upload composite does not pin its nested mutable upload
Action. The Codex action's npm package selection and requested Node major are
separate, as are runner images, Python/Java patch versions and package hashes.
CODEX-5 and full dependency-closure qualification remain open. Preserve the
existing `[no release]` and `[no deploy]` controls during integration.
