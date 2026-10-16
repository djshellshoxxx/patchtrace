# PatchTrace handoff index (read this first)

Purpose: let another engineer or Claude session finish the project with no chat history. Written 2026-10-15 from branch `claude/instance-d-gui` at `da7d2db` (PR #64 head). Facts here come from the repository, `git`, GitHub PR/check/release reads and a few focused local test runs; anything not checked is marked UNVERIFIED.

## Files in this folder

The four files marked "this area" were written together. The other area files were written by sibling workers in the same run; their names below are the planned names. Run `ls docs/handoff` to see what actually exists (UNVERIFIED that each name below exists when you read this).

| File | Purpose |
|---|---|
| `README.md` (this area) | Index, resume order, every open PR and branch with the next action |
| `lbl32-card-controls-chatgpt-20261016.md` | Active LBL-32 stacked PR #79: current code, tests, deduplication, exact unverified/live gates and merge instructions |
| `lbl31-output-persistence-chatgpt-20261015.md` | Current LBL-31 PR #78 implementation, verification, pending native Windows and train=true acceptance |
| `00-how-we-work.md` (this area) | Working method: instances, worktrees, merge flow, CI workflows, push rules, invariants, cost rules, tool limits |
| `qa-and-release.md` (this area) | QA plan, CI gates, beta build steps, what is not verified anywhere, release rules; ordered remaining checklist |
| `owner-actions.md` (this area) | Everything only the owner can do, with plain steps |
| `01-label-training.md` (planned name, UNVERIFIED) | Finishing label training (LBL, Tier R, Tier W, preregistration) |
| `02-unified-engine.md` (planned name, UNVERIFIED) | Unified engine: gates G-U1..G-U7, live runs, flag stays OFF until they pass |
| `03-backend-bundle.md` (planned name, UNVERIFIED) | Zero-download offline bundle |
| `04-gui-panels.md` (planned name, UNVERIFIED) | Qt panels and GUI follow-ups |
| other area files (UNVERIFIED) | Features (KB, search, graph, strings, CAP, DIE, KEV, YARA-X), intelligence, specs |

Existing authoritative sources the handoff points to (all verified to exist): `AGENTS.md`, `CLAUDE.md`, `docs/plans/worker-brief.md`, `docs/plans/master-plan-d.md`, `docs/plans/master-todo-d.md`, `docs/plans/ledger-{A,B,C,D}.md`, `docs/plans/owner-decisions-20261015.md`, `docs/plans/multi-instance-coordination.md`, `docs/plans/lbl-remaining-plan.md`, `docs/specs/program-e/OUTSTANDING-specs-ledger.md`, `docs/release-process.md`, `docs/qa.md`, `docs/windows.md`, `docs/runbooks/*.md`.

## Recommended order to resume

1. Read `AGENTS.md`, `CLAUDE.md`, then `00-how-we-work.md`.
2. Run the state commands in `qa-and-release.md` section 1 (they prove where `main`, PR #64 and CI stand). Never trust a number in a doc over a fresh read.
3. Land PR #64 (`qa-and-release.md` item 1), then PR #66.
4. Do the owner actions that block other work: `owner-actions.md` items O1-O4 (Windows desktop pass, Tier W runs, prereg lock sign-off, Pages setting).
5. Work the area files in the order listed in their own checklists. Label training and the unified engine are the two pillars; the bundle gates a "usable Windows standalone alpha".
6. After every merge to `main`, check the prerelease it produced (`qa-and-release.md` section 6).

## Open pull requests (read from GitHub 2026-10-15; re-read before acting)

| PR | Branch to base | State | Next action |
|---|---|---|---|
| #64 | `claude/instance-d-gui` to `main` | draft, head `da7d2db`. 21 check runs seen, mostly queued at the last read | Wait for all required checks on `da7d2db`. Mark ready, squash-merge with `expectedHeadSha`, no skip marker in the message. The PR adds `unified-live-gates.yml` so the release job cannot publish for that merge (workflow-file hazard): see `qa-and-release.md` item 1. Then reset `claude/instance-d-gui` to `main` |
| #66 | `claude/instance-c-research` to `main` | draft, head `393d09b`, LBL-15 (train, shift, TIER_R_CLAIM). Branch is 5 commits ahead of `main`, 0 behind | After #64: re-run CI, merge. Does not run the real training matrix |
| #61 | `codex/agent-skills-spec56-20261014` to `main` | ready (not draft), docs and skills only (SPEC-56), base is the old `0fb25d8` | Owner decides; if accepted, merge `main` into it first, run CI. It edits `AGENTS.md` and `CLAUDE.md` (policy files): read the diff before merging |
| #67 | `chatgpt/deferred-audit-fixes-1` to `claude/instance-d-gui` | draft, ChatGPT: SEC-1 Ghidriff half, SEC-3, ACQ-12, ACQ-13, CORE-5, CORE-6, CORE-8, CORE-10. Tests never run | Do not merge as is. A Sonnet worker applies each fix in its own worktree with a red test first, runs the focused tests and `ruff`, and takes only what passes. Touches `backend.py` and `cli.py` (frozen shared files: integrator only) |
| #68 | `chatgpt/corpus-1` to `claude/instance-d-gui` | draft, 24 candidate recipes under `tools/calibration/catalogue/*-candidate.json`, all BLOCKED_UNVERIFIED | Label-training input. Follow `01-label-training.md`: verify every SHA and licence, then promote one at a time |
| #69 | `chatgpt/kb-fixtures-1` to `claude/instance-d-gui` | draft, synthetic KB fixtures and tests, never run | A worker runs the tests, fixes what fails, adds `.gitattributes` LF lines (integrator), cherry-picks |
| #70 | `chatgpt/help-docs-1` to `claude/instance-d-gui` | draft, 25 help topics under `docs/help/` | Docs only. Review claims against the manifest, check `docs/help/` has no filename clash with existing files, then merge with `[skip ci]` |
| #71 | `chatgpt/unified-fixtures-1` to `claude/instance-d-gui` | draft, unified synthetic fixtures and gate tests; known defective originals plus `-2` variants | Replace the originals with the `-2` variants (delete the defective ones), run, fix. See `tests/unified_support/fixture-gaps.md` on that branch |
| #72 | `chatgpt/panels-1` to `claude/instance-d-gui` | draft, 9 panel specs and `docs/plans/panels-build-plan.md` | Docs only. Review against the real manifest; basis for the remaining Qt panels |

Merged and no longer open: #58 (21a005e), #59 (2804fbf), #65 (00db4c9, current `main`). #40, #41, #43 are not in the open list (owner decision 11: closed; I did not re-verify their final state).

## Branches (remote, 2026-10-15)

| Branch | Status | Next action |
|---|---|---|
| `origin/main` | `00db4c9` (PR #65). Latest prerelease `v0.1.0-beta.281` (commit 21a005e). Latest published release is a prerelease; `releases/latest` returns 404 because no final release exists | Merge target for everything |
| `origin/claude/instance-d-gui` | Integration branch, PR #64, 240 commits ahead of `main`, 0 behind. Owner: instance D | Merge PR #64, then `git fetch origin main && git checkout -B claude/instance-d-gui origin/main` and push with `--force-with-lease` only after the remote holds merged history only |
| `origin/claude/instance-c-research` | Label training, instance C. PR #66. Was force-pushed by accident earlier; restored (the tip is a merge named "Merge restored research branch") | Merge #66 after #64 |
| `origin/claude/instance-b-features` | Instance B. Merged as #59, then reset to `main` (commit `ffce49c`), now 3 post-reset commits (6e1e153 WB2 G6 layout helpers, 06b26d8 Search S7 saved-search model, 5191c3c CAP-4 cache wiring). `git diff --shortstat origin/main origin/claude/instance-b-features`: 8 files, +1369 -3 | Open a PR when the next wave is ready. Panels for these helpers are D's |
| `origin/claude/clever-clarke-s4nhi6` | Instance A's old branch. Its tree is far behind `main` (467 files differ, 68,965 deletions against `main`); 1 commit not on `main` (`5024026` CI timeout 60 min) | Do not merge. Check whether `5024026`'s content is on `main` (`grep -n timeout-minutes .github/workflows/qa-windows.yml` shows 60 on this tree, so it probably is) then leave it |
| `origin/chatgpt/*` (6 branches) | The ChatGPT drafts above. All based on `claude/instance-d-gui` | See PR table |
| Older branches (`feat/*`, `fix/*`, `audit/*`, `codex/*`, `docs/*`, `feature/*`, `security/*`, `access-test-*`, `claude/audit-beta`, `claude/bundle-license-gate`, `claude/symbol-policy-isolated-settings`, `claude/patchtrace-cli-dotpath-spec-er6hha`) | `git branch -r --no-merged origin/main` lists them because the project squash-merges, so ancestry cannot show whether they are merged. Their status is UNVERIFIED | Owner housekeeping, low priority: for each, `git diff --shortstat origin/main origin/<branch>`; if the content is on `main` the branch can be deleted. Never delete without that check |
| `worktree-agent-*` (local, in the main checkout) | Local worker branches. Two hold unpushed, unmerged work: `worktree-agent-ae1ddf7ace07cf49d` (KB panels K4b/K7, commit 72605cd) and `worktree-agent-ac64fcf9a50ccae01` (WB1-WB3 panels, a338d6a..6620230). Source: `docs/plans/ledger-D.md`. Whether these still exist in the main checkout is UNVERIFIED from this worktree | Rebase onto `main` (B's code is on `main` since #59), run `QT_QPA_PLATFORM=offscreen python tools/qt_gate.py --repeat 5` on their test files, open a PR. If the container is gone, rebuild from `docs/specs/panels/*.md` (PR #72) |
