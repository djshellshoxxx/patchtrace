# Pages deployment control

## Push deployment hold (2026-11-21)

A main integration may be authorized while publishing the site is not. The
Pages workflow must honor `[no deploy]` in the actual push head commit's complete
message. Matching uses GitHub Actions' case-insensitive `contains` function.
For a merge, put the marker in the resulting merge commit title or body; a
marker only in an ancestor commit or PR metadata is not the control.

Apply the hold to the `configure-pages` step and the `deploy` job on `push`
events, using the same condition for both:
`github.event_name != 'push' || !contains(github.event.head_commit.message, '[no deploy]')`.
Keep the deploy job's successful `build` dependency, permissions and environment
unchanged. Preserve the existing push branch/path filters and
`workflow_dispatch` trigger.

| Event | Push-head message | Pages configuration and deployment after a successful build |
| --- | --- | --- |
| `push` | No `[no deploy]` marker | Existing deployment behavior |
| `push` | Contains `[no deploy]`, with any letter case | Skipped |
| `workflow_dispatch` | Any or absent head message | Existing manual deployment behavior |

Site tests, the site build and the Pages artifact upload remain enabled whenever
the workflow runs. Do not add a workflow-level CI skip or change other QA,
packaging, release, or artifact jobs. The deployment hold remains effective if
GitHub runs this path-filtered workflow because diff generation timed out.

Without that step condition, the configuration action queries the Pages service
even when deployment is held. If Pages is not enabled, that query fails and
prevents the later artifact upload. Skip that query under the same push hold;
do not enable Pages or suppress
the failure for unmarked pushes or manual dispatches. The artifact upload uses
`site/dist` directly and does not consume configuration outputs. No other build
step or the build job gains a condition.

The marker applies to one push. A later unmarked push or explicit manual
dispatch retains its existing deployment behavior. It does not suppress GitHub
releases: the separate `[no release]` marker controls that publishing job.

## Verification boundary

`tests/test_site_workflow.py` statically checks that configuration and deployment
share the exact condition, the deploy job retains its build dependency, and the
other build steps remain unconditional. It also checks the preserved
build/test/artifact flow and the existing trigger and permission contracts.
These assertions inspect workflow source; they do not execute GitHub's
expression engine or prove a hosted deployment. No deployment or workflow
dispatch is needed for the local regression.

References: [GitHub contains semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#contains),
[GitHub path-filter fallback](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#git-diff-comparisons).
