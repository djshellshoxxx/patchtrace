# PR 156 identity preparation follow-up, 2026-11-01

Both external review findings were reproduced and repaired in isolated `wt-identity-cancel`, starting at local main-port `b92c8de`, whose tree matches published PR head `15deb8f28e207a9679379265571d2691de52e7e2`. The exact external findings from the GitHub connector are retained in `external-findings.json`.

Apply these commits in order:

1. `0e7298fe5b5abe1f5098bd573feb6096fef4d9e5` — preserve the active budget during refacts identity and secondary-flag preparation.
2. `827edfce3e9e24ce552857750ca260d062d7a6dd` — resolve captured unified identities outside the Qt owner thread.

Final tree: `87157d865d29c7033c3350ba809912ceac11361c`. The worktree was clean after both commits. No remote mutation was performed.

## Refacts reproduction and repair

Four deterministic tests over a real staged result failed before the repair (`refacts-red.log`): cancellation and deadline expiration during the third manual snapshot serialization were ignored by identity preparation; cancellation and deadline expiration during the third secondary record ordering continued through all eight records and installed an ordering cache. The new tests require stopping at the third record, leaving no incomplete cache, and preserving every staged byte. Refacts now checks the caller budget at entry and passes it through both identity and flag preparation.

The focused refacts/identity/wire/facts selection passed **69 tests in 5.91 seconds** (`refacts-green.log`). Independent review passed 18 tests in 1.03 seconds and approved exact commit `0e7298f`.

## Owner-thread reproduction and repair

Real offscreen Qt controls recorded complete manual-content hashing on the main thread during both reload and Run (`owner-red.log`, 2 failures). The first implementation moved capture hashing off-thread but the run control caught another owner hash during publication; that genuine intermediate failure is retained in `owner-initial-green.log` (1 failed, 101 passed).

The final implementation captures validated snapshots on the owner thread, resolves their complete identities under a budget in task work, and returns to the owner for exact-key pointer selection or publication. Unresolved captures expose no placeholder result key. Synchronous `make_plan` and `prepare` remain fully resolved APIs for existing callers. The CLI run wrapper also forwards its active cancellation token during resolution; its original late-cancellation failure is retained in `owner-cli-cancel-red.log`.

Manual-digest reuse is private to a completed immutable snapshot, with per-record exact comparisons off-thread before reuse. A previous selection omitting manual evidence cannot seed the empty digest. Changed names, code or addresses re-key; explicit replacement inputs and replaced plans drop the cache; worker-observed raw status still re-keys independently of the unchanged manual digest. Cancellation, expired request deadlines, stale project/revision/generation callbacks, and project close are covered. Publication uses the resolved request. The tests exercise exact stale detection after a manual edit and cancellation during real identity work preserving the previous published result.

Validation (selections overlap; counts must not be added):

- Owner/UI/pipeline/read-model/identity selection: **168 passed in 25.47 seconds** (`owner-focused.log`).
- New owner/cache controls after additional boundary checks: **13 passed in 3.99 seconds** (`owner-controls.log`).
- CLI/wire/import-DAG/worker/identity integration selection: **222 passed in 19.90 seconds** (`owner-integration.log`).
- Final owner/cache/pipeline/CLI selection after the active CLI cancellation repair: **112 passed in 12.18 seconds** (`owner-final.log`).
- Whole-tree `ruff check src tests tools` and `git diff --check`: passed (`ruff.log`, `diff-check.log`).
- Independent reviewer `/root/ci_review` approved exact commit `827edfc` and final tree: 72 tests in 7.08 seconds plus the added CLI cancellation control (1 passed in 0.63 seconds), scoped Ruff/diff clean. No blocker remained.

All commands used `/workspace/scratch/142cb233d750/full-venv/bin/python`, `PYTHONPATH=src`, and `QT_QPA_PLATFORM=offscreen` from the isolated worktree. That existing environment was not reinstalled. This patch changes internal capture/resolution APIs and tests, not a persisted wire schema, scoring policy or threshold. No schema regeneration was required. It leaves the central/main compute-policy differences untouched.

This is bounded source and synthetic regression evidence. No full suite, performance acceptance, native comparator or target execution was run. Existing owner-side capture I/O remains on the owner thread; this does not claim that all owner work is now asynchronous. Root owns integration and the next exact-source full run.

Read-only port check: the owner-only patch applies cleanly to central `f1dcc5a`, which already contains refacts cherry-pick `1dc34fb`. The initial combined check refused the already-applied refacts files; no source mutation occurred.

Coordinator main-port verification: 79 focused plan/capture/refacts/wire/Qt checks passed17.25s at local2bac65b. The combined source selection separately passed159 in20.26s; these overlap and are not summed. Whole source Ruff and schema drift checks are rerun before publication. Exact-head CI and packaging remain required.

Resume integration retains main’s complete archive at the original filename and the preceding combined archive as `identity-followup-integrated-original-20261101.tar.gz`; neither historical evidence set was discarded.
