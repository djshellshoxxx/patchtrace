# Independent Tier R Action-contract repair review

**No blocking finding in repair `829600f8d667b74329a79dd0b0d7964c2e092fd0`**, tree `306c4d58fe6c0902c4c1b0fbbc3cddd64aed1c4b`, directly based on `a73cea498d93e353eb49ef08aff785bd0c0a768c`.

## Confirmed missed integration blocker

`tests/test_tier_r_shard.py::test_workflow_structure_and_pins` still required `@v` in non-ilammy Action references after CODEX-1 switched those references to reviewed immutable commits. The retained cancelled Windows run records this actual failure and a partial result of **1 failed, 19,776 passed, 181 skipped, 2 xfailed**. It is not a successful aggregate.

The initial CODEX-1 independent 12-file selection did not include this Tier R test. Its no-blocker assessment missed this coupled-test incompatibility; retain the original assessment and the later failing CI evidence instead of rewriting history.

## Full test-tree search

Read all **984 Python test blobs from immutable a73**, parsed every AST successfully, and inspected Action/version constants in **55 workflow-related files**. Tier R was the only remaining concrete mutable-Action-tag assertion found. The other literal `@v` is an LLVM IR fixture declaration in `test_mutations_ir.py`; other inspected `@` strings are full commit references, URL/date/CSS data or generic immutable-reference predicates. No second concrete mismatch was identified. The scan used Git blobs because the coordinator's local combined checkout was not the same tests tree as a73.

## Repair review

Only `tests/test_tier_r_shard.py` changes. Its seven-entry allowlist exactly matches reviewed Action commits. The check now reads actual line-prefix `uses` fields, rejects unknown references and requires the complete expected Action set. Every workflow byte is unchanged.

AST comparison proves the two original archive-digest assertions, every YAML jobs/triggers/permissions/compiler assertion, and all other module-level code are unchanged. The repair enforces the existing `ci-action-pinning.md` contract; it does not weaken the workflow to satisfy a stale test.

## Independent execution

On clean exact source829600f8, one focused run completed **67 passed: 48 maintained Tier R cases and 19 independent controls**, with zero failures or skips. Isolated Python source binding and whitespace checks passed. The worktree remained clean.

The controls execute the actual candidate check against authored temporary workflow text. They verify all seven exact pin identities, refuse a different full commit for each action, unknown actions and mutable tags, preserve valid comments, reject comment-only action replacement, and retain refusal of changed archive digests, permissions, shard dependency and compiler requirements. The unchanged baseline test body independently reproduces its recorded assertion failure against the actual pinned workflow.

No Git refs, candidate files, workflow execution, native tools or analyzed targets were modified or executed. No full suite was run. The new combined source still requires hosted qualification; this review does not transfer the cancelled ancestor's partial counts to it.
