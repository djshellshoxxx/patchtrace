# Pages deployment veto candidate

## Reviewable commits

Base: `6b6fcd3597a604212032ffc453477aeb6edc69ff`

- Contract and site guidance: `00183247016fef5668beb3c6d07aedaa9f451262`.
- Workflow and maintained tests: `e54e4d0afbcdc3916539c62810877faa65842d5e`.
- Exact complete tree: `ecc943693a310455f1427fff7e3d1abad8f07dd0`.
- Branch: `codex/patchtrace-pages-deploy-veto-20261121-95fe`.
- Worktree: `/workspace/scratch/patchtrace-95fe-c3/pages-guard`.

The worktree was clean before and after the final validation at this exact source commit.

## Behavior

The deploy job now uses this single condition, while retaining `needs: build`:

```yaml
if: github.event_name != 'push' || !contains(github.event.head_commit.message, '[no deploy]')
```

A push whose actual head message contains `[no deploy]` skips deployment. GitHub's case-insensitive substring matching also recognizes mixed letter case. An unmarked push and manual `workflow_dispatch` retain their existing behavior, subject to the successful build dependency.

Site test/build/artifact steps, trigger filters, permissions, environment and all non-Pages workflows are unchanged. The new regression pins the deploy condition and dependency, strengthens retained build/test/artifact assertions, and permits event data only in the declarative condition rather than shell commands.

The existing `[no release]` hold remains separate. This candidate changes the Pages workflow, so a later main merge will match its path filter: put **both `[no release] [no deploy]` in the actual merge commit** when both publication types must remain held. No workflow or deployment was triggered here.

## Local verification

- Red control before adding the workflow condition: **1 failed, 6 passed**; the new case detected the absent deploy condition.
- Final clean-commit selection: **52 passed**, consisting of Pages source contracts and general workflow scalar/top-level checks.
- Full `ruff check --no-cache src tests tools`: **passed**.
- `git diff --check`: passed before commit.
- File-relative source check resolved the test helper, site builder and workflow to this worktree; no `patchtrace` app modules were imported.
- Exact commands, file hashes and clean source/tree observations are recorded in `pages-veto-candidate.json`.

These are static source checks. They do not execute GitHub's expression engine, qualify a hosted deployment, or replace the combined candidate's required hosted CI. The focused pytest invocation disabled conftest and plugin autoload to avoid unrelated application imports; it did not use app fixtures.

The contract was committed before implementation. Root-owned ledgers were not modified. Independent review and combined-candidate hosted qualification remain with the parent task.
