# Independent Pages deployment-guard review

**Source:** `/workspace/scratch/patchtrace-95fe-c3/pages-guard`, HEAD **e54e4d0afbcdc3916539c62810877faa65842d5e**, tree **ecc943693a310455f1427fff7e3d1abad8f07dd0**, against **6b6fcd3597a604212032ffc453477aeb6edc69ff**. Read `AGENTS.md`, the Pages entry in `docs/modules.md`, and `docs/specs/pages-deployment-control.md` before source review. Commit **00183247016fef5668beb3c6d07aedaa9f451262** establishes the specification before the implementation commit.

## Findings

**No blocking specification or source-standards findings.**

- Specification lines 5–13 require the actual push-head message and a hold confined to `deploy`. The only workflow change is `deploy.if` at line 38: `github.event_name != 'push' || !contains(github.event.head_commit.message, '[no deploy]')`. This admits ordinary unmarked pushes and manual dispatch while vetoing marked pushes. It reads the complete message field directly, without interpolating event data into shell commands.
- GitHub documents case-insensitive substring matching for `contains` and expression evaluation of job-level `if`. The condition starts with `github`, so it does not encounter YAML's leading-`!` restriction. No status-check override was introduced; `needs: build` and the default success gate remain effective.
- Specification lines 21–28 preserve tests, build, artifact upload, other QA, and independent release control. Baseline comparison confirms the trigger filters, build job, Pages artifact, job permissions, deployment environment and action are unchanged. No other workflow changes. The deploy-level guard still applies when a path-filter fallback causes the workflow to run.
- The merge operation must place **both `[no release] [no deploy]` in the resulting main merge commit message**. Ancestor markers or PR metadata do not satisfy the new guard. Later unmarked pushes and manual dispatch retain existing deployment behavior.

## Tests and limits

The new regression pins the event/head-message condition and successful-build dependency. Strengthened build assertions require site tests/build/upload and prohibit the marker or a job-level guard before deployment. Existing trigger, privilege, environment and shell-interpolation checks remain. These provide meaningful static contract coverage; they do not evaluate GitHub's engine or establish hosted deployment behavior. The specification states that limit explicitly.

I did not duplicate the author's reported red/green/Ruff runs or execute a deployment/dispatch. Worktree inspection remained clean; no source, refs, settings, or network state was mutated.

Documentation checked read-only: [expression semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#contains), [job conditions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idif), and [path-filter fallback](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#git-diff-comparisons).
