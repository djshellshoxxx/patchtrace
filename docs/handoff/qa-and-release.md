# QA plan and release (operations handoff)

Sources: `docs/release-process.md`, `docs/qa.md`, `docs/specs/windows-acceptance-and-milestone-builds.md`, `docs/specs/program-e/E6-test-performance-beta-plan.md`, `docs/specs/windows-release-signing-policy.md`, `docs/runbooks/backend-bundle.md`, `.github/workflows/*.yml`, `tests/stress/`. Written 2026-10-15. UNVERIFIED marks anything not confirmed by reading or running.

## 1. Purpose and current state

Goal: a downloadable Windows (and Linux) prerelease with honest evidence, then beta builds, never a final release without the owner.

State commands (run them; numbers below were true on 2026-10-15):

```
git fetch origin
git log -1 --format='%h %s' origin/main                       # 00db4c9 Bundle: validate full payloads ... (#65)
git rev-list --left-right --count origin/main...origin/claude/instance-d-gui   # 0 240
gh pr view 64 --json headRefOid,isDraft,statusCheckRollup     # head da7d2db...; or the GitHub MCP get_check_runs
gh release list --limit 3                                     # newest v0.1.0-beta.281 (prerelease), then beta.243
QT_QPA_PLATFORM=offscreen python -m pytest tests/stress tests/test_release_gate.py -q -p no:cacheprovider
                                                              # 511 passed, 1 skipped, 2 xfailed in 75 s (run on da7d2db)
python tools/qt_gate.py --print-command                       # shows the repeat command CI runs
```
Latest prerelease evidence (beta.281, commit 21a005e): Linux pytest 13214 passed, 62 skipped, 0 failed; Windows pytest 13189 passed, 87 skipped, 0 failed; Ruff pass; Linux package smoke on 22.04 and 24.04 pass; Windows frozen self-test pass. Not run for that SHA: native Ghidriff matrix, live rz-diff. Manual Windows checklist: 0 pass, 18 not-run.

## 2. What is DONE

| Item | Where | Evidence |
|---|---|---|
| Prerelease pipeline (build, smoke, gate, publish) | `.github/workflows/qa-windows.yml`, `tools/release_gate.py`, `tools/milestone_notes.py` | beta.243 and beta.281 published with zip, tar.gz and sha256; `tests/test_release_gate.py` passes |
| Release cadence gate (every third counted merge, `[release]` override, fail-open) | `tools/release_gate.py`, `docs/release-process.md` | beta.281 notes: "6 counted merges since beta.243, threshold 3" |
| Windows qa job timeout raised to 60 min | `qa-windows.yml` line 17 (`timeout-minutes: 60`) | commit 5024026 |
| Qt repeat gate in CI (T7 in master to-do) | `qa-windows.yml` job `qt-gate` runs `tools/qt_gate.py --repeat ${{ matrix.repeat }}`; check names show 20 on ubuntu, 5 on windows | PR #64 check list |
| Stress and fuzz suites | `tests/stress/` (GUI, fuzz, CLI/persistence, stress2) | 511 passed, 2 strict xfails (below) |
| Ten audits and fix passes | `docs/audits/20261015-*.md`, `-fixes-*.md` | PR #64 body: 1 High / 49 Medium / about 110 Low; deferred items listed in fixes files |
| Bundle pins recorded | `tools/backend_pin.json` (commit 8fb3521); no component left as `placeholder` (grep shows the word only inside a prose note) | `tools/check_backend_pin.py --release` is the check (not run here, UNVERIFIED) |
| BinDiff pin file exists, unverified | `tools/bindiff_pin.json` has `"verified": false` | runbook `docs/runbooks/bindiff-pin.md` steps still to do |
| Signing policy written | `docs/specs/windows-release-signing-policy.md` (SPEC-52) | alpha stays unsigned; owner decision 9 |
| Pages tooling | `site/`, `tools/site/`, `pages.yml` | first CI run waits for the owner (qa.md line about Pages) |

## 3. What REMAINS (ordered checklist)

Size S/M/L; tier is the cheapest model that is enough.

### 1. Land PR #64 (the integration PR)
- Goal: put 240 commits of GUI, audits, QA, unified gates, bundle pins on `main`.
- Files: none to change; this is a merge. The PR adds `.github/workflows/unified-live-gates.yml`.
- How: (a) read the PR head SHA and the check runs of that exact SHA (`00-how-we-work.md` section 6); (b) if red, fix on `claude/instance-d-gui` with a red test, push, wait for the new head; (c) mark ready, squash-merge with `expectedHeadSha`, commit message free of skip markers; (d) because the head changes files under `.github/workflows/`, `GITHUB_TOKEN` publication gets HTTP 403: the build succeeds but no prerelease is published. Merge the next non-workflow commit (PR #66 or any small one; put `[release]` in the message if fewer than 3 merges counted); (e) `git fetch origin main && git checkout -B claude/instance-d-gui origin/main`.
- Tests first: none new.
- Commands: `gh pr checks 64`; `gh pr merge 64 --squash --match-head-commit <sha>` (UNVERIFIED flag spelling; check `gh pr merge --help`, or use the GitHub MCP `merge_pull_request` with `sha`).
- CI proof: `qa-windows.yml` jobs `qa` (both OS), `qt-gate` (both OS), `linux-smoke`; advisory live jobs are reported, not required.
- Acceptance gate: all required jobs green on the merged head; a prerelease exists for a later merge with Linux and Windows assets and sha256.
- Size S. Tier: sonnet (haiku can poll). Depends on: CI finishing.

### 2. Merge PR #66 (LBL-15 training pipeline)
- Goal: `tools/calibration/train.py`, `shift.py`, `TIER_R_CLAIM` report on `main` (no real training run).
- How: after item 1, `git fetch origin main`; check `git rev-list --left-right --count origin/main...origin/claude/instance-c-research`; merge `main` into it if behind; wait for CI on the new head; squash-merge. Label-training work continues in `01-label-training.md`.
- Tests: `tests/test_train_pipeline.py`, `test_train_report.py`, `test_train_shift.py` (62 passed per the PR body, run locally by C).
- Commands: `PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m pytest tests/test_train_pipeline.py tests/test_train_report.py tests/test_train_shift.py -q -p no:cacheprovider`; `python -m ruff check src tests tools`.
- CI: `qa-windows.yml` `qa`. Gate: green; no change to calibration display level (stays `ordinal`). Size S. Tier sonnet. Depends on item 1.

### 3. Verify the next prerelease end to end
- Goal: a human-verified Windows zip and Linux tar.gz.
- How: follow `docs/release-process.md` "Verify assets before announcing": download zip, tar.gz and `.sha256`; `sha256sum -c` (Linux) or `Get-FileHash -Algorithm SHA256` (Windows); confirm it is marked Pre-release and the tag commit is the intended `main` commit; read the Open gates list in the notes; do not repeat a claim the notes do not make.
- Commands: `gh release view <tag> --json isPrerelease,targetCommitish,assets`.
- Gate: checksums equal; notes list job results. Size S. Tier haiku. Depends on item 1 and a published beta.

### 4. Run the live and native workflows that the notes list as "not run"
- Goal: replace "not run" in the notes with real results (never mocked).
- How: dispatch (Actions UI or `gh workflow run <file>`): `live-backend.yml` (no inputs; native Windows Ghidriff, 5 variants), `live-rizin.yml` (UNVERIFIED inputs, read the file), `live-bindiff.yml`, `live-capa.yml`, `live-intel-tools.yml`, `live-unified.yml`. Read each result; add a row to `docs/qa.md` under a heading `### [OPS:live-runs]` with run URL, SHA, counts. A failure is recorded as a failure with the defect filed in `tasks/todo.md`, not retried until green.
- Gate: each workflow has a recorded run on a `main` SHA. Size M. Tier sonnet. Depends on item 1.

### 5. Unified engine live gates (cross-reference)
- Dispatch `unified-live-gates.yml` with `pairs=all`, `per_class=20` once PR #64 is on `main` (the file is not on `main` before). G-U3 stays `blocked` until the BinDiff pin is verified (`docs/runbooks/bindiff-pin.md`, then `python -m tools.unified.bindiff_pin verify --require-verified` exits 0). About 240 Ghidriff runs for G-U2. Details in `02-unified-engine.md` (UNVERIFIED that the file exists). Size L, owner reviews the compute. Tier sonnet.

### 6. Offline bundle full build and acceptance
- Goal: attach `PatchTrace-<ver>-windows-x64-full.zip` / `-linux-x86_64-full.tar.gz` (names from `docs/runbooks/backend-bundle.md` section 1) to a prerelease.
- How: dispatch `backend-bundle.yml` with `platforms=both`, `version` empty (0.1.0), `publish_prerelease=false`; read the `vrfy` (acceptance) job result; fix what the first live run exposes (JPype/pyghidra headless on both OS is the expected first failure, `master-todo-d.md` B2); only then re-dispatch with `publish_prerelease=true` (needs contents write on the token). A tag push builds and runs acceptance but never publishes.
- Gate: offline acceptance green (no network, read-only tree), asset size below `ASSET_LIMIT` 1.9 GiB, warn above 1.2 GB. Size L. Tier sonnet; opus only after two failed sonnet attempts on one named problem. Full steps in `03-backend-bundle.md` (UNVERIFIED).

### 7. Two strict xfails and the exit-code table (QA)
- `QA-CLI-3` (`tests/stress/test_cli_stress_paths.py::test_cache_verify_on_a_file_reports_failure`): `cache verify` on a `--cache-dir` that is a regular file exits 3, expected 2, while `cache status` is pinned at 3 by `tests/test_cli.py`. Owner decision 7 adopted: one table, usage/config errors 2, partial 3, empty/not-found 4, cancelled 5, add `status` to the envelope. Steps: update `docs/specs/cli-umbrella.md` section 8 first, change both commands and the pinned test together, remove the xfail marker (a strict xfail turns an XPASS into a failure, so the marker must go in the same commit), document in `docs/cli-reference.md`. Frozen file `cli.py`: integrator only. Size M, sonnet.
- `QA-S2-2` (`tests/stress/test_stress2_enrichment_store.py::test_lock_serialised_writers_keep_every_row`): project connection is bound to its creating thread (`persistence.py` `sqlite3.connect` without `check_same_thread`). Either open a connection per thread or serialise through one writer; test first (already exists as the xfail); remove marker. Size M, sonnet.
- `QA-GUI-1` (codediff alignment bug, `tests/stress/test_gui_stress_codediff.py` docstring): not among the xfails reported by the last run (`23 passed, 1 skipped, 2 xfailed` on three stress files); whether it was fixed or skipped is UNVERIFIED, check `-rxs`.
- Other strict xfails on `main`: `tests/test_codex_pkg_packaging.py` (CODEX-10/11/12/14), `tests/test_codex_pkg_workflows.py` (CODEX-1..8), `tests/test_corpus_cards_audit.py` (three LBL-05 licence items). Fixing a defect without removing its marker fails the suite; remove the marker in the same commit.

### 8. Windows automated acceptance additions A6-A12
- Goal: implement what the beta.281 notes list as "Not implemented or not run": A6 native 3-build series with real Ghidra, A7 Job Object kill-on-close, A8 Job Object cancel/timeout, A9 scheduler fan-out cancel, A11 transient files off sync folders, A12 antivirus/file-lock helper, and the trailing-dot/reserved-name halves of A10.
- Spec: `docs/specs/windows-acceptance-and-milestone-builds.md` section 2 (A7 must drive the real `jobs.run_process` path and write the grandchild PID to a temp file; A6-A8 run in the native matrix `live-backend.yml`; Windows-only tests are `skipif(os.name != 'nt')`).
- How: one test file per item under `tests/`, hermetic, red first on Windows CI (cannot be proven on Linux). Add the job step to `live-backend.yml` (workflow edit: triggers the publication hazard for that merge).
- Size L total. Tier sonnet. Depends on item 1.

### 9. E-6 phase: final feature audit, scripted beta, performance, frozen smoke
- Plan: `docs/specs/program-e/E6-test-performance-beta-plan.md` (entry criteria section 1, audit checklist section 2, bug check section 3, scripted beta scenarios section 4, performance budgets section 5, frozen smoke section 6, blocked external acceptance section 7, order section 8).
- How: do not start before the entry criteria hold. Run it in the order of section 8 of that plan. The master to-do items A1-A5 (audit per feature, wiring audit, stress list, RA-1..RA-10 closure, security audit) feed it.
- Size XL. Tier sonnet; haiku for read-only audits.

### 10. Documentation sweep
- Collapse duplicate lines in `tasks/todo.md` (T12), refresh stale statuses in `docs/specs/REGISTRY.md` (T13), update `docs/version-history.md` for the next beta, record every run in `docs/qa.md`. One tracker-only commit with `[skip ci]`. Size S. Tier haiku.

### 11. Pages first deploy
- After the owner enables Pages (owner-actions O9): dispatch `pages.yml`, read the build job (site tests, build), confirm deploy. Size S. Tier haiku. The `actions/*` majors were pinned without API access (`qa.md`): if the run fails on an action version, fix the version.

### 12. Beta builds and notes
- Each code merge to `main` yields a candidate prerelease (every third counted merge publishes). For a beta milestone, put `[release]` in the merge commit message, then item 3. Notes come from `tools/milestone_notes.py`; the template is spec section 4 ("never write production ready"). Final release: never without the owner (section 6).

## 4. Decisions only the owner can make (recommendation)

| Decision | Recommendation |
|---|---|
| Publish workflow-touching merges (PR #64) as-is, or split the workflow file out so the merge publishes | Keep as-is; the next non-workflow merge publishes. Avoid splitting a merged PR |
| Required checks for branch protection (which jobs block a merge) | Require `qa` and `qt-gate` on both OS plus `linux-smoke`; keep live jobs advisory |
| When a beta becomes "the" alpha for outside testers | After items 1, 3, 6 and the Windows desktop pass M01-M18 have recorded results |
| Exit-code table (decision 7 adopted; the owner may object) | Proceed as adopted |
| Signing | Unsigned alpha; apply to SignPath Foundation in parallel (decision 9) |

## 5. Pitfalls and lessons

- Skip marker anywhere in a squash message suppresses the whole run, hence no build and no count; `[release]` plus a skip marker cannot publish.
- Workflow-file hazard (403 on publish) applies to any head commit touching `.github/workflows/`.
- Fixtures need LF: `.gitattributes` line `tests/fixtures/wbq/** text eol=lf` was added after a Windows-only failure; new fixture directories need their own line (integrator).
- One native job (`raw-cache-hit`) flaked because `_java_version` returned unknown after a 15 s probe; hardening is T10 (`backend.py`).
- Windows monotonic clock is 15.6 ms: use `>=` in timing tests. `PYTEST_CURRENT_TEST` limit 32767 characters: use short parametrize ids.
- Windows qa job needed a 60 minute limit (about 21 minutes of pytest alone).
- `python -m tools.calibration...` fails with `ModuleNotFoundError: patchtrace` unless `PYTHONPATH=src`.
- Strict xfail: a fixed bug with its marker still present fails the suite.
- Mocked backend or provider tests are never live compatibility evidence.
- Microsoft-derived data (binaries, PDBs, Winbindex labels) never goes into git, CI artifacts or uploads; `corpus-tier-r.yml` handles our own synthetic builds only.
- Pages and signing facts from blocked hosts are snippet-only (`[S]`) in `docs/research/windows-signing-options.md`: re-check at decision time.

## 6. Final release rules and what is NOT verified

Rules (`docs/release-process.md`, `AGENTS.md`, `CLAUDE.md`): never create a final (non-prerelease) release, draft or auto-update without the owner; never bypass or silently skip a failing test; never describe a release as published if the token lacked permission; no "air-gapped" or "signed" claim without linked evidence; do not call the project complete while acceptance gates are open.

Not verified anywhere (as of beta.281 and this handoff): clean Windows 11 GUI acceptance M01-M28 (0 of 18 recorded in the notes; M19-M28 are accessibility items added later); DPI 100/150/200 percent, NVDA, Narrator, high contrast, Accessibility Insights; live AI provider acceptance (no credentials); relocatable offline backend bundle and disconnected-VM acceptance; real Ghidriff on a OneDrive-backed Windows folder; rz-diff and BinDiff live runs on the newest SHA; unified engine gates G-U1..G-U7 live (G-U3 blocked by the unverified BinDiff pin); matching accuracy and performance (unmeasured, no claim made); Tier W results (owner machine only); Pages first deploy; code signing; SmartScreen behaviour; ChatGPT draft PRs #67-#72 (nothing in them was executed).

## 7. Verification checklist before calling QA and release finished

- [ ] PR #64 and #66 merged with all required checks green on the merged head (exact run URLs in `docs/qa.md`).
- [ ] A prerelease exists whose tag commit is the intended `main` commit; checksums verified; notes read.
- [ ] `live-backend.yml` and the other live workflows have a recorded run on a recent `main` SHA, or are listed as open gates.
- [ ] Bundle full build and offline acceptance green, or listed as open.
- [ ] Both stress xfails resolved or recorded with owner decision.
- [ ] A7-A12 implemented or listed open in the notes.
- [ ] Windows manual checklist M01-M28 has recorded results from the owner.
- [ ] `ruff check src tests tools` clean; `pytest -q` green on Linux and Windows.
- [ ] No final release created.
