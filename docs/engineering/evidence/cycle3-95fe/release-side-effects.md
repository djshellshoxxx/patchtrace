# Main integration: publication and deployment audit

Observed 2026-11-21 04:50–04:55 UTC. Captured main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. Qualified PR348 head: `6b6fcd3597a604212032ffc453477aeb6edc69ff`. This audit was read-only.

## Release conclusion

**An ordinary unmarked main merge would enable automatic prerelease publication once required QA succeeds. No source change is needed to suppress that release: the qualified workflow already honors `[no release]` in the actual merge commit message.**

The release job independently requires the absence of that marker. Python cadence-gate errors fail open but cannot override the publishing job's veto. QA, Qt, packages, smoke tests and downloadable Actions artifacts remain enabled. The hold is per push; it does not change future cadence.

The workflow, gate source, gate tests, Pages workflow and release-process guide are byte-identical between captured main and PR348. Blob identities are in the JSON receipt. [Exact qualified workflow](https://github.com/djshellshoxxx/patchtrace/blob/6b6fcd3597a604212032ffc453477aeb6edc69ff/.github/workflows/qa-windows.yml) uses:

```yaml
if: (startsWith(github.ref, 'refs/tags/v') || needs.release-gate.outputs.publish == 'true') && !contains(github.event.head_commit.message, '[no release]')
```

The release job needs qa, qt-gate, linux-smoke and release-gate. It is the only contents:write job in this workflow. [Existing regression tests](https://github.com/djshellshoxxx/patchtrace/blob/6b6fcd3597a604212032ffc453477aeb6edc69ff/tests/test_release_gate.py) pin the exact condition, the unmodified QA/build/artifact flow, and required acceptance dependencies. [Release process](https://github.com/djshellshoxxx/patchtrace/blob/6b6fcd3597a604212032ffc453477aeb6edc69ff/docs/release-process.md) explicitly documents integration without publishing.

## Actual cadence and first-parent anchor

The REST releases collection contains 59 releases. Latest published matching prerelease: [v0.1.0-beta.1035](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.1035), published 2026-11-15T07:13:33Z, targeting `1836eb120571bb3c3a09fd3014447498621e2103`.

Three counted first-parent commits follow, oldest first:

1. `7401078490eb7a447f5ec7274339cb08b051f395`
2. `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`
3. `fdc2696c23bdbfe7668348f25e3b336ce33039f7`

The last includes `[no release]`, which does not skip CI and still counts. Complete messages were checked for actual CI-skip markers.

The actual [main cadence job](https://github.com/djshellshoxxx/patchtrace/actions/runs/44489196124/job/135440201914) logged `publish=true milestones=3`. Pure gate evaluation against the same local Git history reproduced three. A prospective ordinary merge in memory produces **publish=true, milestones=4**, including when its message contains the publication hold: the workflow independently enforces that hold.

Historical [main QA run 44489196124](https://github.com/djshellshoxxx/patchtrace/actions/runs/44489196124) failed in linux-package's apt-install step and skipped release. That skipped job is not isolated proof of the marker because failed required QA independently prevents publication.

## Pages boundary

[Pages](https://github.com/djshellshoxxx/patchtrace/blob/6b6fcd3597a604212032ffc453477aeb6edc69ff/.github/workflows/pages.yml) has **zero changed watched paths** (site/**, tools/site/**, its own workflow) in the exact main-to-PR348 diff. There are 245 commits ahead and 639 changed files overall. Normal path evaluation therefore skips Pages, and an ordinary merge remains below GitHub's 1,000-commit fallback threshold.

However, GitHub's [path-filter documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#git-diff-comparisons) says diff-generation timeouts run filtered workflows. Existing Pages deploy has no independent opt-out. Thus the unchanged source does not provide an absolute no-deployment boundary.

The narrow authorized follow-up is a separate candidate adding a deploy-job veto for `[no deploy]` in push-head messages, preserving ordinary push, manual dispatch, all site build/test/artifact steps and all other QA. Its contract and static workflow regression must be reviewed and qualified separately. This report itself does not claim that candidate is implemented or hosted-qualified.

Backend bundle does not run on main pushes: dispatch, workflow_call and v* tags are its triggers, and publication defaults false. The workflow scan found release creation in qa-windows/backend-bundle and deployment in Pages.

## Method and limits

GitHub GET only; bounded log excerpt; local Git reads; source, specification and test inspection; pure Python gate decisions with an in-memory prospective commit. No workflow, source, ref, settings, release or deployment was mutated during this audit. No binaries or downloaded packages were executed, and no suite was rerun.

GitHub [contains](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#contains) is case-insensitive. Put control markers in the actual resulting merge commit, preserve a head-SHA guard and recheck the resulting state. A permission failure is not a publication-control mechanism.
