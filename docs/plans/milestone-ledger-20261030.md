# Milestone ledger: integrated essential alpha (2026-10-30)

Working ledger for the milestone in `docs/plans/next-milestone-dev-prompt-20261030.md` (PR #125). Coordinator branch: `claude/modest-hamilton-kz2gta`. Live GitHub state beats this file; re-check before use.

## Step 0 snapshot (13:08 UTC)

- `origin/main` = `5214720716c7afb7952bacbc9afd4b8255574ae8` (#111). Unchanged since the prompt snapshot.
- `git log -8 --oneline origin/main`: 5214720 (#111), f4063c3 (#107), 94bd6a4 (#106), fbe58d8, 45fa67a, e264bd7, 241a777 (#87), e093ade (#97).
- Latest published prerelease: `v0.1.0-beta.543` (2026-10-29 05:40Z).

### #124 at head `95e09548a82202ae4cfd9380522f36513da87a66`

- Base `5214720` = current main. `mergeable_state: unstable` (non-required check failing, not `blocked`).
- Review threads: 9 of 9 resolved. CodeRabbit review skipped (rate limited). Qodo: 0 open findings.
- Checks at head (43 runs): every QA/native/packaging job success.
  - QA run [41041471026](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471026): `qa (ubuntu-latest)`, `qa (windows-latest)`, `qt-gate` Linux 1–4/4 and Windows 1/1, `linux-package`, `linux-smoke` 22.04/24.04 success; `release`/`release-gate` skipped (PR event).
  - Native Ghidriff five jobs success in runs [41041462592](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041462592) and [41041471132](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471132).
  - Live rz-diff [41041471212](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471212) success on ubuntu-latest and windows-latest.
  - Live BinDiff [41041471099](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471099) job success (licence state still to read from its log; job success is not live-BinDiff evidence).
  - **SonarCloud**: quality gate failed (C security, C reliability on new code). Not a required check. Findings triaged in `docs/audits/20261030-consolidation-review.md` §"Connected SonarCloud check triage". Recorded as open, not green.

### Ownership map (remote branches, last 24 h)

| Branch | Last commit (UTC) | Owner / PR | Disposition |
|---|---|---|---|
| `claude/compassionate-goldberg-5uuqks` | 10-30 12:55 | #125 (prompt author) | docs only, leave to owner |
| `codex/deep-review-consolidation-20261030` | 10-30 10:32 | #124 | land in Phase 1 |
| `claude/awesome-ramanujan-o3pxx3-{ci,hostile,win1}` | 10-30 04:55–05:11 | owner-only | do not touch |
| `codex/pr110-ci-repairs-20261029` | 10-30 05:02 | #115 | superseded candidate |
| `claude/jolly-fermi-eghaxy` | 10-30 04:40 | #123 | superseded candidate |
| `codex/pr110-kb-arch-scope-20261029` | 10-30 04:08 | #122 | superseded candidate |
| `codex/pr110-persistence-feedback-20261029` | 10-30 04:07 | #119 | superseded candidate |
| `codex/pr111-bounded-nav-into-integration-20261029` | 10-30 04:05 | #117 | superseded candidate |
| `fix/pr110-ci-regressions-20261029` | 10-30 03:58 | #113 | superseded candidate |
| `codex/fix-pr110-ci-gates-20261029` | 10-30 03:57 | #114 | superseded candidate |
| `codex/pr110-qa-wbjson-diaphora-help-20261029` | 10-30 03:54 | #112 | superseded candidate |

No branch other than #125's was pushed in the hour before this check, so no conflicting coordinator.

## Decisions

1. **Merge #124 with SonarCloud red.** Reason: M-A defines the gate as the QA workflow legs, all green at the exact head; Sonar is not a required check; its findings are triaged with evidence and the hostile-input fixtures cannot turn green without disabling rules, which the rules forbid. Sonar stays recorded as an open gate.

## Log

| Time (UTC) | Action | SHA / link | Result |
|---|---|---|---|
| 13:10 | ledger created, draft PR | [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) | — |
| 13:09 | **merged #124** (merge commit, expected head `95e0954`) | main `a04f5a299a8d4afef023261e52e08d14678cf1e7` (parents `5214720`, `95e0954`) | push QA run [41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610) started |
| 13:25 | closed #110 #112 #113 #114 #115 #117 #119 #122 #123 as superseded by #124 | comment on each with evidence | see M-B table |

## M-B evidence (superseded PRs)

| PR | Head | Method | Result |
|---|---|---|---|
| #110 | `5ed624e` | `git merge-base --is-ancestor` vs `a04f5a2` | ancestor |
| #113 | `979ddfa` | ancestor check | ancestor (chosen repair alternative) |
| #123 | `99f8328` | ancestor check | ancestor (#124 baseline) |
| #117 | `025300f` | added lines of `c1e21ef..head` present in main tree | 35/35 present |
| #119 | `3e9cedb` | same | 73/73 present |
| #122 | `40e02da` | same | 16/16 present |
| #112 | `aba4c20` | PR test files run against main | 1 fail: asserts standalone `winbindex.strict_json` rejects lone surrogate; on main only `parse`/`parse_rows` call it and both validate per entry → contract without caller, no behaviour lost |
| #114 | `c0d1c38` | same | 1 fail: same contract via PR-only `allow_entry_surrogates` kwarg; symbol-consent tests pass |
| #115 | `bb42828` | same | all pass |

Script: line-presence check over `git diff -U0 base..head` added lines (len ≥ 6) against `git show origin/main:<file>`. Alternative-PR tests run in a detached worktree of `a04f5a2` (42 passed, 2 failed as above).

## Next executable step

Wait for push QA run 41060959610 on `a04f5a2`; record per-leg results and Windows artifacts (M-A/M-C); check release job for B1 403 (M-D).
