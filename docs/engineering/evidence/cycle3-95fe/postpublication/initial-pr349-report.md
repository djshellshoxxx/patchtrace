# PR349 initial hosted qualification snapshot

**Captured 2026-11-21 05:22:34–05:23:00 UTC. Qualification remains pending.** This was one bounded initial REST sweep, followed by exact-source applicability inspection and one completed advisory-job log read. No poll loop, dispatch, retry or remote mutation occurred.

## Exact source

- [PR349](https://github.com/djshellshoxxx/patchtrace/pull/349): open, non-draft; mergeable=true, mergeable_state=unstable.
- Published head: `11f51c105bf63946f59373ae605b937c4fee607a`.
- Captured main/base: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
- Synthetic merge: `301d21b5da515833cc6e000d9ea5f2e944d67a16`.
- Merge parents, in order: captured main, then published head.
- Head and synthetic merge both have tree **`4939056ceb0e02b419c820b9e5748c869c40a857`**, independently read from GitHub REST commit objects.

This binds GitHub's synthetic merge tree to the published source. It is not yet completed full-QA execution evidence. Earlier source qualification does not establish successor success.

## Observed check state

25 current check runs: **15 queued, 4 in progress, 3 success, 3 intentionally skipped**. No completed failing strict check appeared in this snapshot. Snyk's commit status is success, with description “No manifest changes detected in 1 project.”

| Workflow | Run | Actual jobs at capture |
| --- | --- | --- |
| QA and Windows standalone | [44870397228](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397228) | Linux Qt shard 4/4 running; both full-QA jobs and other four Qt jobs queued; release-gate skipped |
| Native Ghidriff | [44870397150](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397150) | raw-cache-hit running; four other variants queued |
| BinDiff | [44870397208](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397208) | Windows running; Linux queued |
| Optional dependencies | [44870397137](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397137) | Both Windows and Linux probes success; whole run success |
| Tier R | [44870397157](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397157) | plan and Windows advisory queued; optional MSVC advisory skipped |
| rizin | [44870397216](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397216) | Both platform jobs queued |
| Intel tools | [44870397141](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397141) | Linux running; Windows job success with advisory test failures below; dispatch-only build-environment job skipped |

Several run-level aggregate statuses were still queued while constituent jobs were already running. Both raw values are preserved; job observations above are the more specific state.

The full Linux [QA job 136743396804](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397228/job/136743396804) and full Windows [QA job 136743396623](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397228/job/136743396623) were still queued. Linux packaging and its two smoke legs had not materialized yet; they depend on successful QA/Qt and packaging, respectively. Tier R shards and merge remain downstream of plan.

## Concrete advisory failures hidden by a green job conclusion

The completed [Windows intel job 136743396511](https://github.com/djshellshoxxx/patchtrace/actions/runs/44870397141/job/136743396511) reports job success because its Windows live-test step deliberately uses continue-on-error. Its actual pytest log reports **2 failed, 1 passed, 1 skipped in 18.96 seconds**:

- capa: version identification failed; no version reported despite exit 0.
- FLOSS: version identification failed; no version reported, exit 1.
- DIE 3.21: reproduced the synthetic-pair goldens.
- FLOSS offline: blocked/skipped because `unshare -rn` is unavailable on Windows.
- Provisioning of pinned tools succeeded.

These are concrete advisory compatibility failures and a platform-specific blocked check. The log does not establish that the new source introduced them. They are not a strict red workflow gate, but a green job must not be reported as all Windows tool acceptance passing. Explicit disposition remains necessary under the no-blocking-findings integration rule.

The receipt retains a bounded failure/status excerpt; the full log was not dumped into chat.

## Applicability

Exact published-source workflow filters were compared with the main-to-head PR diff (708 changed files):

- Seven workflows match, exactly the seven observed runs.
- Unified extraction has **zero matching changed paths**; its absence is consistent with the source filter.
- Pages has no pull_request trigger and is inapplicable to this PR event.
- release-gate is push-only; its skipped result is intentional. The release job cannot publish for this PR event.
- Tier R optional MSVC requires workflow_dispatch plus TIER_R_MSVC=1.
- Intel build-environment acceptance is workflow_dispatch-only.
- Windows BinDiff and Windows intel include advisory behavior; retain actual live-result dispositions separately from job conclusions.

All run/check metadata returned the exact published head. No additional workflow was dispatched to manufacture evidence.

## Next gate

The current queued/running jobs and downstream packaging/smoke/shard jobs must finish before this head can be qualified. Review any strict failure and the advisory findings explicitly; refresh the exact head/base/tree and all applicable job states for the eventual guarded decision. This task intentionally stops after the bounded initial audit; the parent task owns monitoring and merge coordination.

Files: `initial-pr349-rest.json` preserves the 20 raw REST responses; `initial-pr349-summary.json` preserves compact run/job URLs and failure excerpts; `initial-pr349-applicability.json` preserves source-pattern evidence. No release, deployment or merge was performed.
